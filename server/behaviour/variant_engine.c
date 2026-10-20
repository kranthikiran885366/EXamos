/*
 * ExamOS Phase 5 — Variant Engine Implementation
 * server/behaviour/variant_engine.c
 *
 * Real server-side individualized question variants:
 * - Seed = HMAC-SHA256(EXAMOS_VARIANT_SECRET, "candidate_id:exam_id:template_id:version")
 * - Parameters generated deterministically from seed via DRBG-style counter expansion
 * - Answer key stays server-side, never in candidate JSON
 * - All generated variants persisted to EXAMOS_VARIANT_STORE for audit/reproducibility
 */

#define _GNU_SOURCE
#include "../include/variant_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef EXAMOS_BUILD_ID
#define EXAMOS_BUILD_ID "dev-unset"
#endif

#define VARIANT_STORE_DEFAULT   "/var/lib/examos/variants"
#define VARIANT_KEY_FILE        "variants.log"
#define WATERMARK_FILE          "watermarks.log"
#define MAX_PATH                512

static char g_variant_dir[MAX_PATH]   = VARIANT_STORE_DEFAULT;
static char g_variant_path[MAX_PATH]  = {0};
static char g_watermark_path[MAX_PATH]= {0};
static pthread_mutex_t g_vlock        = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized              = 0;

/* Built-in question templates (extend by loading from EXAMOS_TEMPLATE_DIR) */
#define MAX_BUILTIN_TEMPLATES  8
static question_template_t g_templates[MAX_BUILTIN_TEMPLATES];
static int g_template_count = 0;

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void copy_text(char *dest, size_t dest_size, const char *source) {
    if (!dest || dest_size == 0) return;
    if (!source) source = "";
    size_t length = strlen(source);
    if (length >= dest_size) length = dest_size - 1;
    memcpy(dest, source, length);
    dest[length] = '\0';
}

static int join_store_path(char *dest, size_t dest_size, const char *filename) {
    size_t dir_len = strlen(g_variant_dir);
    size_t file_len = strlen(filename);
    if (dir_len + 1 + file_len >= dest_size) return -1;
    memcpy(dest, g_variant_dir, dir_len);
    dest[dir_len] = '/';
    memcpy(dest + dir_len + 1, filename, file_len + 1);
    return 0;
}

static int mkdir_p(const char *path) {
    char tmp[MAX_PATH];
    strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1]='\0';
    size_t len = strlen(tmp);
    if (tmp[len-1]=='/') tmp[--len]='\0';
    for (char *p=tmp+1; *p; p++) {
        if (*p=='/') { *p='\0'; mkdir(tmp, 0750); *p='/'; }
    }
    return mkdir(tmp,0750)==0||errno==EEXIST ? 0 : -1;
}

static int safe_append(const char *path, const char *line) {
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    int rc = 0;
    if (fprintf(f,"%s\n",line)<0) rc=-1;
    if (fflush(f)) rc=-1;
    if (fsync(fileno(f))) rc=-1;
    if (fclose(f)) rc=-1;
    return rc;
}

/* ── HMAC-SHA256 seed derivation ─────────────────────────────────────────── */

static int derive_seed(const char *candidate_id, const char *exam_id,
                       const char *template_id, const char *gen_version,
                       unsigned char out_seed[32]) {
    /* EXAMOS_VARIANT_SECRET must be provisioned (>=32 chars) */
    const char *secret = getenv("EXAMOS_VARIANT_SECRET");
    if (!secret || strlen(secret) < 32) {
        fprintf(stderr, "[VariantEngine] FATAL: EXAMOS_VARIANT_SECRET not provisioned\n");
        return -1;
    }

    /* canonical string: candidate_id + ":" + exam_id + ":" + template_id + ":" + gen_version */
    char canonical[512];
    snprintf(canonical, sizeof(canonical), "%s:%s:%s:%s",
             candidate_id, exam_id, template_id, gen_version);

    unsigned int out_len = 0;
    unsigned char *result = HMAC(EVP_sha256(),
        secret, (int)strlen(secret),
        (const unsigned char*)canonical, strlen(canonical),
        out_seed, &out_len);
    return (result && out_len == 32) ? 0 : -1;
}

/* Expand seed to produce a double in [0.0, 1.0) for parameter index i */
static double seed_to_uniform(const unsigned char seed[32], int param_index, int counter) {
    unsigned char buf[SHA256_DIGEST_LENGTH];
    char input[64];
    snprintf(input, sizeof(input), "%d:%d", param_index, counter);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, seed, 32);
    SHA256_Update(&ctx, input, strlen(input));
    SHA256_Final(buf, &ctx);
    /* Take first 8 bytes as uint64 */
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) val = (val << 8) | buf[i];
    return (double)val / (double)UINT64_MAX;
}

/* ── Fingerprint ─────────────────────────────────────────────────────────── */

static void compute_fingerprint(const question_variant_t *v, char out[VARIANT_FINGERPRINT_LEN]) {
    char payload[4096] = {0};
    size_t off = (size_t)snprintf(payload, sizeof(payload),
        "%s:%s:%s:%s:%s", v->candidate_id, v->exam_id,
        v->template_id, v->template_version, v->generator_version);
    for (int i = 0; i < v->param_count; i++) {
        off += (size_t)snprintf(payload+off, sizeof(payload)-off,
            ":%s=%.8f", v->params[i].name, v->params[i].value);
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)payload, strlen(payload), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out+(i*2), "%02x", hash[i]);
    out[64] = '\0';
}

/* ── Unique ID generation ─────────────────────────────────────────────────── */

static void gen_unique_id(char *out, size_t max, const char *prefix) {
    unsigned char rb[8];
    RAND_bytes(rb, sizeof(rb));
    char hex[17];
    for (int i=0;i<8;i++) sprintf(hex+(i*2),"%02x",rb[i]);
    hex[16]='\0';
    snprintf(out, max, "%s-%ld-%s", prefix, (long)time(NULL), hex);
}

/* ── Built-in template initialization ───────────────────────────────────── */

static void init_builtin_templates(void) {
    /* Template 1: Cryptographic hashing throughput question */
    question_template_t *t = &g_templates[g_template_count++];
    memset(t, 0, sizeof(*t));
    strncpy(t->template_id,      "TMPL-CRYPTO-THROUGHPUT-001", sizeof(t->template_id)-1);
    strncpy(t->template_version, "p5-v1",                      sizeof(t->template_version)-1);
    strncpy(t->question_type,    "NUMERICAL",                  sizeof(t->question_type)-1);
    strncpy(t->wording_template,
        "A secure cryptographic hashing pipeline processes {BLOCK_SIZE}-byte blocks with a "
        "SHA-256 throughput of {HASH_MBPS} MB/s. If the network interface streams data at "
        "{NET_GBPS} Gbps, what is the bottleneck utilization percentage of the hashing pipeline? "
        "Round to 2 decimal places.",
        sizeof(t->wording_template)-1);
    strncpy(t->watermark_footer,
        "Candidate: {CANDIDATE_REF} | Exam: {EXAM_ID} | Variant: {VARIANT_ID}",
        sizeof(t->watermark_footer)-1);

    /* BLOCK_SIZE: 512 to 8192, step 512 */
    strncpy(t->params[0].name, "BLOCK_SIZE", sizeof(t->params[0].name)-1);
    t->params[0].min_val=512; t->params[0].max_val=8192; t->params[0].step=512; t->params[0].is_integer=1;
    /* HASH_MBPS: 64 to 512, step 64 */
    strncpy(t->params[1].name, "HASH_MBPS", sizeof(t->params[1].name)-1);
    t->params[1].min_val=64; t->params[1].max_val=512; t->params[1].step=64; t->params[1].is_integer=1;
    /* NET_GBPS: 1 to 10, step 1 */
    strncpy(t->params[2].name, "NET_GBPS", sizeof(t->params[2].name)-1);
    t->params[2].min_val=1; t->params[2].max_val=10; t->params[2].step=1; t->params[2].is_integer=1;
    t->param_count = 3;
    strncpy(t->solution_formula_id, "CRYPTO_THROUGHPUT_UTIL", sizeof(t->solution_formula_id)-1);
    strncpy(t->rubric_version,      "p5-v1",                   sizeof(t->rubric_version)-1);
    t->correct_option_index = -1;   /* numerical */
    t->difficulty_min = 0.5; t->difficulty_max = 0.8;

    /* Template 2: Network packet loss analysis */
    t = &g_templates[g_template_count++];
    memset(t, 0, sizeof(*t));
    strncpy(t->template_id,      "TMPL-NET-PACKET-002", sizeof(t->template_id)-1);
    strncpy(t->template_version, "p5-v1",               sizeof(t->template_version)-1);
    strncpy(t->question_type,    "NUMERICAL",            sizeof(t->question_type)-1);
    strncpy(t->wording_template,
        "A network link transmits {PKT_RATE} packets per second with a packet loss rate of "
        "{LOSS_PERCENT}%%. TCP retransmission overhead is {RETX_PERCENT}%% of retransmitted bytes. "
        "If each packet is {PKT_SIZE} bytes, compute the effective data throughput in KB/s "
        "after accounting for loss and retransmissions.",
        sizeof(t->wording_template)-1);
    strncpy(t->watermark_footer,
        "Candidate: {CANDIDATE_REF} | Exam: {EXAM_ID} | Variant: {VARIANT_ID}",
        sizeof(t->watermark_footer)-1);
    strncpy(t->params[0].name,"PKT_RATE",sizeof(t->params[0].name)-1);
    t->params[0].min_val=1000; t->params[0].max_val=100000; t->params[0].step=1000; t->params[0].is_integer=1;
    strncpy(t->params[1].name,"LOSS_PERCENT",sizeof(t->params[1].name)-1);
    t->params[1].min_val=1; t->params[1].max_val=15; t->params[1].step=1; t->params[1].is_integer=1;
    strncpy(t->params[2].name,"RETX_PERCENT",sizeof(t->params[2].name)-1);
    t->params[2].min_val=5; t->params[2].max_val=30; t->params[2].step=5; t->params[2].is_integer=1;
    strncpy(t->params[3].name,"PKT_SIZE",sizeof(t->params[3].name)-1);
    t->params[3].min_val=64; t->params[3].max_val=1500; t->params[3].step=64; t->params[3].is_integer=1;
    t->param_count = 4;
    strncpy(t->solution_formula_id,"NET_EFFECTIVE_THROUGHPUT",sizeof(t->solution_formula_id)-1);
    strncpy(t->rubric_version,"p5-v1",sizeof(t->rubric_version)-1);
    t->correct_option_index = -1;
    t->difficulty_min=0.6; t->difficulty_max=0.85;
}

/* ── Server-side answer computation ─────────────────────────────────────── */

static double compute_answer(const question_variant_t *v) {
    /* CRYPTO_THROUGHPUT_UTIL:
     * utilization = (HASH_MBPS * 8) / (NET_GBPS * 1000) * 100
     * If util > 100, bottleneck is hash pipeline → 100% util
     */
    if (strcmp(v->params[0].name,"BLOCK_SIZE")==0 &&
        strcmp(v->params[1].name,"HASH_MBPS")==0 &&
        strcmp(v->params[2].name,"NET_GBPS")==0) {
        double hash_mbps = v->params[1].value;
        double net_gbps  = v->params[2].value;
        double net_mbps  = net_gbps * 1000.0;
        double util      = (hash_mbps / net_mbps) * 100.0;
        if (util > 100.0) util = 100.0;
        return round(util * 100.0) / 100.0;
    }

    /* NET_EFFECTIVE_THROUGHPUT:
     * effective = pkt_rate * pkt_size * (1 - loss_pct/100) * (1 - retx_pct/100) / 1024
     */
    if (strcmp(v->params[0].name,"PKT_RATE")==0 &&
        strcmp(v->params[1].name,"LOSS_PERCENT")==0 &&
        strcmp(v->params[2].name,"RETX_PERCENT")==0 &&
        strcmp(v->params[3].name,"PKT_SIZE")==0) {
        double pkt_rate  = v->params[0].value;
        double loss_pct  = v->params[1].value / 100.0;
        double retx_pct  = v->params[2].value / 100.0;
        double pkt_size  = v->params[3].value;
        double eff = pkt_rate * pkt_size * (1.0-loss_pct) * (1.0-retx_pct) / 1024.0;
        return round(eff * 100.0) / 100.0;
    }

    return 0.0; /* unknown formula — flag as failed */
}

/* ── Template rendering ───────────────────────────────────────────────────── */

static void render_template(const question_template_t *tmpl,
                             const question_variant_t *v,
                             char *out, size_t max) {
    strncpy(out, tmpl->wording_template, max-1);
    out[max-1]='\0';
    for (int i = 0; i < v->param_count; i++) {
        char placeholder[64], replacement[64];
        snprintf(placeholder, sizeof(placeholder), "{%s}", v->params[i].name);
        strncpy(replacement, v->params[i].value_str, sizeof(replacement)-1);
        /* Simple single-pass replacement */
        char *pos;
        while ((pos = strstr(out, placeholder)) != NULL) {
            size_t pre = (size_t)(pos - out);
            size_t pl_len = strlen(placeholder);
            size_t repl_len = strlen(replacement);
            size_t tail_len = strlen(pos + pl_len);
            if (pre + repl_len + tail_len + 1 >= max) break;
            memmove(pos + repl_len, pos + pl_len, tail_len + 1);
            memcpy(pos, replacement, repl_len);
        }
    }
}

static void render_watermark(const question_template_t *tmpl,
                              const question_variant_t *v,
                              const char *candidate_display_ref,
                              char *out, size_t max) {
    strncpy(out, tmpl->watermark_footer, max-1);
    out[max-1]='\0';

    /* Replace {CANDIDATE_REF} */
    char *pos;
    const char *ref = candidate_display_ref && *candidate_display_ref
                      ? candidate_display_ref : v->candidate_id;
    while ((pos = strstr(out, "{CANDIDATE_REF}")) != NULL) {
        size_t pre = (size_t)(pos-out);
        size_t tl = strlen(pos+15);
        size_t rl = strlen(ref);
        if (pre+rl+tl+1>=max) break;
        memmove(pos+rl, pos+15, tl+1);
        memcpy(pos, ref, rl);
    }
    /* {EXAM_ID} */
    while ((pos = strstr(out, "{EXAM_ID}")) != NULL) {
        size_t pre=(size_t)(pos-out), tl=strlen(pos+9), rl=strlen(v->exam_id);
        if(pre+rl+tl+1>=max) break;
        memmove(pos+rl,pos+9,tl+1); memcpy(pos,v->exam_id,rl);
    }
    /* {VARIANT_ID} */
    while ((pos = strstr(out, "{VARIANT_ID}")) != NULL) {
        size_t pre=(size_t)(pos-out), tl=strlen(pos+12), rl=strlen(v->variant_id);
        if(pre+rl+tl+1>=max) break;
        memmove(pos+rl,pos+12,tl+1); memcpy(pos,v->variant_id,rl);
    }
}

/* ── Constraint validation ───────────────────────────────────────────────── */

static int validate_constraints(const question_template_t *tmpl,
                                 const question_variant_t *v) {
    for (int i = 0; i < v->param_count && i < tmpl->param_count; i++) {
        double val = v->params[i].value;
        if (val < tmpl->params[i].min_val || val > tmpl->params[i].max_val) return 0;
        /* Check modulo step */
        if (tmpl->params[i].step > 0) {
            double rem = fmod(val - tmpl->params[i].min_val, tmpl->params[i].step);
            if (fabs(rem) > 1e-6) return 0;
        }
    }
    /* Check answer makes sense */
    double ans = compute_answer(v);
    if (ans <= 0.0 && v->param_count > 0) return 0;
    return 1;
}

/* ── Init ─────────────────────────────────────────────────────────────────── */

int variant_engine_init(void) {
    pthread_mutex_lock(&g_vlock);
    if (g_initialized) { pthread_mutex_unlock(&g_vlock); return 0; }

    const char *env_dir = getenv("EXAMOS_VARIANT_STORE");
    if (env_dir && *env_dir) {
        strncpy(g_variant_dir, env_dir, sizeof(g_variant_dir)-1);
        g_variant_dir[sizeof(g_variant_dir)-1]='\0';
    }
    if (mkdir_p(g_variant_dir)!=0 && errno!=EEXIST) {
        fprintf(stderr, "[VariantEngine] FATAL: cannot create store %s\n", g_variant_dir);
        pthread_mutex_unlock(&g_vlock);
        return -1;
    }
    if (join_store_path(g_variant_path, sizeof(g_variant_path), VARIANT_KEY_FILE) != 0 ||
        join_store_path(g_watermark_path, sizeof(g_watermark_path), WATERMARK_FILE) != 0) {
        fprintf(stderr, "[VariantEngine] FATAL: store path is too long\n");
        pthread_mutex_unlock(&g_vlock);
        return -1;
    }

    /* Check EXAMOS_VARIANT_SECRET is provisioned */
    const char *secret = getenv("EXAMOS_VARIANT_SECRET");
    if (!secret || strlen(secret) < 32) {
        fprintf(stderr, "[VariantEngine] FATAL: EXAMOS_VARIANT_SECRET not set (>=32 chars)\n");
        pthread_mutex_unlock(&g_vlock);
        return -1;
    }

    init_builtin_templates();
    g_initialized = 1;
    printf("[VariantEngine] Phase 5 variant engine ready. Store: %s Templates: %d\n",
           g_variant_dir, g_template_count);
    pthread_mutex_unlock(&g_vlock);
    return 0;
}

/* ── Generate variant ────────────────────────────────────────────────────── */

int variant_generate(const char *candidate_id, const char *exam_id,
                     const question_template_t *tmpl,
                     question_variant_t *out) {
    if (!candidate_id||!exam_id||!tmpl||!out) return -1;
    if (!g_initialized && variant_engine_init()!=0) return -1;

    memset(out, 0, sizeof(*out));
    gen_unique_id(out->variant_id, sizeof(out->variant_id), "var");
    strncpy(out->candidate_id,     candidate_id,             sizeof(out->candidate_id)-1);
    strncpy(out->exam_id,          exam_id,                  sizeof(out->exam_id)-1);
    copy_text(out->template_id, sizeof(out->template_id), tmpl->template_id);
    copy_text(out->template_version, sizeof(out->template_version), tmpl->template_version);
    strncpy(out->generator_version, VARIANT_GENERATOR_VERSION, sizeof(out->generator_version)-1);
    out->created_ts = time(NULL);
    out->param_count = tmpl->param_count;

    /* Derive seed */
    unsigned char seed[32];
    if (derive_seed(candidate_id, exam_id,
                    tmpl->template_id, VARIANT_GENERATOR_VERSION, seed) != 0) {
        strncpy(out->generation_status, "VARIANT_GENERATION_FAILED", sizeof(out->generation_status)-1);
        return -1;
    }

    /* Generate parameters deterministically */
    for (int i = 0; i < tmpl->param_count; i++) {
        strncpy(out->params[i].name, tmpl->params[i].name, VARIANT_PARAM_NAME_LEN-1);
        double u = seed_to_uniform(seed, i, 0);
        double range = tmpl->params[i].max_val - tmpl->params[i].min_val;
        double raw   = tmpl->params[i].min_val + u * range;
        double val;
        if (tmpl->params[i].step > 0) {
            /* Snap to nearest valid step */
            double steps = floor((raw - tmpl->params[i].min_val) / tmpl->params[i].step);
            val = tmpl->params[i].min_val + steps * tmpl->params[i].step;
            /* Clamp */
            if (val < tmpl->params[i].min_val) val = tmpl->params[i].min_val;
            if (val > tmpl->params[i].max_val) val = tmpl->params[i].max_val;
        } else {
            val = raw;
            if (val < tmpl->params[i].min_val) val = tmpl->params[i].min_val;
            if (val > tmpl->params[i].max_val) val = tmpl->params[i].max_val;
        }
        if (tmpl->params[i].is_integer) val = round(val);
        out->params[i].value = val;
        if (tmpl->params[i].is_integer)
            snprintf(out->params[i].value_str, VARIANT_PARAM_VALUE_LEN-1, "%d", (int)val);
        else
            snprintf(out->params[i].value_str, VARIANT_PARAM_VALUE_LEN-1, "%.4f", val);
    }

    /* Validate constraints */
    if (!validate_constraints(tmpl, out)) {
        strncpy(out->generation_status, "VARIANT_CONSTRAINT_FAILURE", sizeof(out->generation_status)-1);
        out->constraint_validated = 0;
        fprintf(stderr, "[VariantEngine] VARIANT_CONSTRAINT_FAILURE for %s/%s template=%s\n",
                candidate_id, exam_id, tmpl->template_id);
        return -1;
    }
    out->constraint_validated = 1;

    /* Render question wording */
    render_template(tmpl, out, out->rendered_question, sizeof(out->rendered_question));

    /* Render watermark */
    /* Use first 8 chars of SHA-256(candidate_id) as display reference */
    unsigned char chash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)candidate_id, strlen(candidate_id), chash);
    char cref[16];
    snprintf(cref, sizeof(cref), "REF-%02x%02x%02x%02x", chash[0], chash[1], chash[2], chash[3]);
    render_watermark(tmpl, out, cref, out->watermark_text, sizeof(out->watermark_text));

    /* Compute server-side answer */
    out->answer_numeric = compute_answer(out);
    out->answer_option_index = tmpl->correct_option_index;
    snprintf(out->answer_explanation, sizeof(out->answer_explanation),
             "Computed by formula %s on parameters %s", tmpl->solution_formula_id, out->variant_id);
    copy_text(out->rubric_version, sizeof(out->rubric_version), tmpl->rubric_version);

    /* Fingerprint */
    compute_fingerprint(out, out->fingerprint);

    strncpy(out->generation_status, "GENERATED", sizeof(out->generation_status)-1);

    /* Persist: answer key stored server-side, variant_id + fingerprint for audit */
    char line[4096];
    snprintf(line, sizeof(line),
        "VARIANT|%s|%s|%s|%s|%s|%s"
        "|%.6f|%d|%.4f|%s|%ld",
        out->variant_id, out->candidate_id, out->exam_id,
        out->template_id, out->template_version, out->generator_version,
        out->answer_numeric, out->answer_option_index,
        out->answer_numeric, /* duplicate for grep-ability */
        out->fingerprint,
        (long)out->created_ts);
    /* Append param values */
    char params_part[1024]={0};
    for (int i=0;i<out->param_count;i++) {
        char pp[64];
        snprintf(pp, sizeof(pp), "|%s=%.4f", out->params[i].name, out->params[i].value);
        strncat(params_part, pp, sizeof(params_part)-strlen(params_part)-1);
    }
    strncat(line, params_part, sizeof(line)-strlen(line)-1);

    pthread_mutex_lock(&g_vlock);
    safe_append(g_variant_path, line);
    pthread_mutex_unlock(&g_vlock);

    /* Persist watermark record */
    watermark_record_t wm;
    memset(&wm, 0, sizeof(wm));
    strncpy(wm.candidate_ref,    cref,                        sizeof(wm.candidate_ref)-1);
    strncpy(wm.exam_id,          exam_id,                     sizeof(wm.exam_id)-1);
    copy_text(wm.variant_id, sizeof(wm.variant_id), out->variant_id);
    copy_text(wm.watermark_text, sizeof(wm.watermark_text), out->watermark_text);
    strncpy(wm.generator_version, VARIANT_GENERATOR_VERSION,  sizeof(wm.generator_version)-1);
    wm.generated_ts = out->created_ts;
    variant_persist_watermark(&wm);

    printf("[VariantEngine] Generated variant=%s for candidate=%s exam=%s template=%s ans=%.4f\n",
           out->variant_id, candidate_id, exam_id, tmpl->template_id, out->answer_numeric);
    return 0;
}

/* ── Retrieve variant ────────────────────────────────────────────────────── */

int variant_retrieve(const char *variant_id, question_variant_t *out) {
    if (!variant_id || !out || !g_initialized) return -1;

    pthread_mutex_lock(&g_vlock);
    FILE *f = fopen(g_variant_path, "r");
    if (!f) { pthread_mutex_unlock(&g_vlock); return -1; }

    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), f) && !found) {
        char ftype[16]={0}, fvid[64]={0};
        if (sscanf(line, "%15[^|]|%63[^|]", ftype, fvid)<2) continue;
        if (strcmp(ftype,"VARIANT")!=0 || strcmp(fvid,variant_id)!=0) continue;
        found = 1;
        memset(out, 0, sizeof(*out));
        char fcid[64]={0},fexam[64]={0},ftmpl[64]={0},ftver[16]={0},fgver[32]={0};
        double fans=0; int fopt=0; double fans2=0; long fts=0;
        char ffp[65]={0};
        sscanf(line,
            "%15[^|]|%63[^|]|%63[^|]|%63[^|]|%63[^|]|%15[^|]|%31[^|]"
            "|%lf|%d|%lf|%64[^|]|%ld",
            ftype, fvid, fcid, fexam, ftmpl, ftver, fgver,
            &fans, &fopt, &fans2, ffp, &fts);
        copy_text(out->variant_id, sizeof(out->variant_id), fvid);
        copy_text(out->candidate_id, sizeof(out->candidate_id), fcid);
        copy_text(out->exam_id, sizeof(out->exam_id), fexam);
        copy_text(out->template_id, sizeof(out->template_id), ftmpl);
        copy_text(out->template_version, sizeof(out->template_version), ftver);
        copy_text(out->generator_version, sizeof(out->generator_version), fgver);
        copy_text(out->fingerprint, sizeof(out->fingerprint), ffp);
        out->answer_numeric      = fans;
        out->answer_option_index = fopt;
        out->created_ts          = (time_t)fts;
        out->constraint_validated = 1;
        strncpy(out->generation_status, "GENERATED", sizeof(out->generation_status)-1);

        for (int t = 0; t < g_template_count; t++) {
            if (strcmp(g_templates[t].template_id, out->template_id) == 0) {
                render_template(&g_templates[t], out, out->rendered_question, sizeof(out->rendered_question));
                unsigned char chash[SHA256_DIGEST_LENGTH];
                SHA256((const unsigned char*)out->candidate_id, strlen(out->candidate_id), chash);
                char cref[16];
                snprintf(cref, sizeof(cref), "REF-%02x%02x%02x%02x", chash[0], chash[1], chash[2], chash[3]);
                render_watermark(&g_templates[t], out, cref, out->watermark_text, sizeof(out->watermark_text));
                break;
            }
        }
    }
    fclose(f);
    pthread_mutex_unlock(&g_vlock);
    return found ? 0 : -1;
}

/* ── Grading ─────────────────────────────────────────────────────────────── */

double variant_grade_answer(const char *variant_id,
                             int submitted_option,
                             double submitted_numeric,
                             const char *rubric_version,
                             char *out_grade_detail, size_t detail_max) {
    question_variant_t v;
    if (variant_retrieve(variant_id, &v) != 0) {
        if (out_grade_detail)
            snprintf(out_grade_detail, detail_max, "VARIANT_NOT_FOUND");
        return 0.0;
    }
    /* Check rubric version matches */
    if (rubric_version && strcmp(v.rubric_version, rubric_version) != 0) {
        if (out_grade_detail)
            snprintf(out_grade_detail, detail_max,
                     "RUBRIC_MISMATCH:stored=%s requested=%s",
                     v.rubric_version, rubric_version);
        return 0.0;
    }

    double score = 0.0;
    if (v.answer_option_index >= 0) {
        /* MCQ */
        score = (submitted_option == v.answer_option_index) ? 1.0 : 0.0;
        if (out_grade_detail)
            snprintf(out_grade_detail, detail_max,
                     "MCQ:submitted=%d correct=%d score=%.1f",
                     submitted_option, v.answer_option_index, score);
    } else {
        /* Numerical: 2% tolerance */
        double tolerance = fabs(v.answer_numeric) * 0.02;
        if (tolerance < 0.01) tolerance = 0.01;
        if (fabs(submitted_numeric - v.answer_numeric) <= tolerance) score = 1.0;
        else score = 0.0;
        if (out_grade_detail)
            snprintf(out_grade_detail, detail_max,
                     "NUMERICAL:submitted=%.4f correct=%.4f tol=%.4f score=%.1f",
                     submitted_numeric, v.answer_numeric, tolerance, score);
    }
    return score;
}

/* ── JSON exports ─────────────────────────────────────────────────────────── */

int variant_export_candidate_json(const char *variant_id,
                                   char *out_buf, size_t max_len) {
    question_variant_t v;
    if (variant_retrieve(variant_id, &v) != 0) {
        snprintf(out_buf, max_len, "{\"error\":\"VARIANT_NOT_FOUND\"}");
        return -1;
    }
    snprintf(out_buf, max_len,
        "{\"variant_id\":\"%s\","
        "\"exam_id\":\"%s\","
        "\"template_id\":\"%s\","
        "\"template_version\":\"%s\","
        "\"generator_version\":\"%s\","
        "\"question_text\":\"%s\","
        "\"watermark_footer\":\"%s\","
        "\"constraint_validated\":%s}",
        v.variant_id, v.exam_id, v.template_id,
        v.template_version, v.generator_version,
        v.rendered_question, v.watermark_text,
        v.constraint_validated ? "true" : "false");
    /* Note: answer_numeric and answer_option_index NOT included */
    return 0;
}

int variant_export_reviewer_json(const char *variant_id,
                                  char *out_buf, size_t max_len) {
    question_variant_t v;
    if (variant_retrieve(variant_id, &v) != 0) {
        snprintf(out_buf, max_len, "{\"error\":\"VARIANT_NOT_FOUND\"}");
        return -1;
    }
    snprintf(out_buf, max_len,
        "{\"variant_id\":\"%s\","
        "\"candidate_id\":\"%s\","
        "\"exam_id\":\"%s\","
        "\"template_id\":\"%s\","
        "\"template_version\":\"%s\","
        "\"generator_version\":\"%s\","
        "\"fingerprint\":\"%s\","
        "\"question_text\":\"%s\","
        "\"watermark_footer\":\"%s\","
        "\"answer_numeric\":%.6f,"
        "\"answer_option_index\":%d,"
        "\"rubric_version\":\"%s\","
        "\"constraint_validated\":%s,"
        "\"created_ts\":%ld}",
        v.variant_id, v.candidate_id, v.exam_id,
        v.template_id, v.template_version, v.generator_version,
        v.fingerprint, v.rendered_question, v.watermark_text,
        v.answer_numeric, v.answer_option_index, v.rubric_version,
        v.constraint_validated ? "true" : "false",
        (long)v.created_ts);
    return 0;
}

/* ── Watermark persistence and trace ────────────────────────────────────── */

int variant_persist_watermark(const watermark_record_t *rec) {
    if (!rec || !g_initialized) return -1;
    char line[1024];
    snprintf(line, sizeof(line),
        "WATERMARK|%s|%s|%s|%s|%s|%ld",
        rec->candidate_ref, rec->exam_id, rec->variant_id,
        rec->watermark_text, rec->generator_version,
        (long)rec->generated_ts);
    pthread_mutex_lock(&g_vlock);
    int rc = safe_append(g_watermark_path, line);
    pthread_mutex_unlock(&g_vlock);
    return rc;
}

int variant_trace_watermark(const char *watermark_text_fragment,
                             char *out_candidate_ref, size_t max_len,
                             char *out_variant_id,    size_t vid_max) {
    if (!watermark_text_fragment || !out_candidate_ref || !out_variant_id) return -1;
    if (!g_initialized) return -1;

    pthread_mutex_lock(&g_vlock);
    FILE *f = fopen(g_watermark_path, "r");
    if (!f) { pthread_mutex_unlock(&g_vlock); return -1; }

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f) && !found) {
        if (!strstr(line, watermark_text_fragment)) continue;
        char ftype[16]={0}, fcref[64]={0}, fexam[64]={0};
        char fvid[64]={0}, fwm[256]={0};
        if (sscanf(line, "%15[^|]|%63[^|]|%63[^|]|%63[^|]|%255[^|]",
                   ftype, fcref, fexam, fvid, fwm) < 4) continue;
        if (strcmp(ftype,"WATERMARK")!=0) continue;
        strncpy(out_candidate_ref, fcref, max_len-1);
        out_candidate_ref[max_len-1]='\0';
        strncpy(out_variant_id, fvid, vid_max-1);
        out_variant_id[vid_max-1]='\0';
        found = 1;
    }
    fclose(f);
    pthread_mutex_unlock(&g_vlock);
    return found ? 0 : -1;
}

/* ── Diversity measurement ───────────────────────────────────────────────── */

double variant_diversity_fraction(const question_variant_t *a,
                                   const question_variant_t *b) {
    if (!a || !b) return 0.0;
    int total = 0, different = 0;
    int n = a->param_count < b->param_count ? a->param_count : b->param_count;
    for (int i = 0; i < n; i++) {
        total++;
        if (fabs(a->params[i].value - b->params[i].value) > 1e-6) different++;
    }
    return total > 0 ? (double)different / (double)total : 0.0;
}
