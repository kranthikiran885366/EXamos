/* Isolated crypto/memory regression. Real libpq PGresults and real RSA OAEP;
 * database/TPM boundaries supply fixtures, never production bypasses. */
#include "../../server/include/key_release.h"
#include "../../server/db/db.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static char *public_key;
static int insert_seen, rng_failure, insert_failure;
static const char fingerprint[] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
int __real_RAND_bytes(unsigned char *, int);
int __wrap_RAND_bytes(unsigned char *out, int n) {
    return rng_failure ? 0 : __real_RAND_bytes(out,n);
}
PGconn *db_acquire(void) { return (PGconn *)1; }
void db_release(PGconn *conn, int broken) { (void)conn; (void)broken; }
int attestation_get_exam_key(const char *session, const char *device, char *out, size_t size) {
    (void)session; (void)device;
    snprintf(out,size,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); return 0;
}
PGresult *db_simple(PGconn *conn, const char *sql, int count, const char **params, const int *lens) {
    (void)conn; (void)count; (void)lens;
    if (strstr(sql,"INSERT INTO examos_exam_key_transports")) {
        assert(strcmp(params[1],"att_correct_id") == 0);
        assert(strcmp(params[5],fingerprint) == 0);
        insert_seen++;
        return PQmakeEmptyPGresult(NULL, insert_failure ? PGRES_FATAL_ERROR : PGRES_COMMAND_OK);
    }
    PGresult *r=PQmakeEmptyPGresult(NULL,PGRES_TUPLES_OK);
    PGresAttDesc attrs[7] = {{0}};
    for(int i=0;i<7;i++) { attrs[i].name="column"; attrs[i].typid=25; attrs[i].typlen=-1; }
    assert(PQsetResultAttrs(r,7,attrs));
    const char *values[7]={public_key,fingerprint,"verified","TRUSTED","exam_launch","1795710000","att_correct_id"};
    for(int i=0;i<7;i++) assert(PQsetvalue(r,0,i,(char *)values[i],(int)strlen(values[i])));
    return r;
}
int main(void) {
    EVP_PKEY *key=EVP_PKEY_Q_keygen(NULL,NULL,"RSA",2048);
    assert(key); BIO *b=BIO_new(BIO_s_mem()); assert(b);
    assert(PEM_write_bio_PUBKEY(b,key)==1);
    char *p=NULL; long n=BIO_get_mem_data(b,&p);
    public_key=malloc((size_t)n+1); assert(public_key);
    memcpy(public_key,p,(size_t)n); public_key[n]=0;
    BIO_free(b); EVP_PKEY_free(key);
    char envelope[4096],error[64];
    assert(key_release_wrap_session_key("candidate","session","device",envelope,sizeof(envelope),error)==0);
    assert(insert_seen==1 && strstr(envelope,fingerprint));
    rng_failure=1;
    assert(key_release_wrap_session_key("candidate","session","device",envelope,sizeof(envelope),error)==-1);
    assert(!envelope[0] && insert_seen==1);
    rng_failure=0; insert_failure=1;
    assert(key_release_wrap_session_key("candidate","session","device",envelope,sizeof(envelope),error)==-1);
    assert(!envelope[0]);
    assert(key_release_wrap_session_key("candidate","session\"","device",envelope,sizeof(envelope),error)==-1);
    assert(!envelope[0] && !strcmp(error,"P3_INVALID_REQUEST"));
    free(public_key);
    puts("PASS: PGresult lifetime, attestation ID, RNG and persistence fail-closed regressions");
}
