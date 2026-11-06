/*
 * support_controller.c — SPPIO / ExamOS Support platform backend.
 * Server-side support lifecycle, comments, assignment, validated status
 * transitions, escalation into incidents, recovery (with centralized
 * approval), real diagnostics and service status — against dedicated
 * PostgreSQL tables (migration 032). All authorization, validation, SLA,
 * ticket numbering, tenant isolation and audit are enforced server-side.
 */
#include "support_controller.h"
#include "../db/db.h"
#include "../audit/audit.h"
#include "../security/security.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void support_send(int fd, int status, const char *body,
                         const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, status, body, extra);
}
static void support_error(int fd, int status, const char *message,
                          const char *origin, char *extra, size_t extra_len) {
    char escaped[768], body[900];
    ctrl_json_escape(message, escaped, sizeof(escaped));
    snprintf(body, sizeof(body), "{\"error\":\"%s\"}", escaped);
    support_send(fd, status, body, origin, extra, extra_len);
}

static int support_gen_id(char *out, size_t out_len, const char *prefix) {
    unsigned char random[16];
    static const char hex[] = "0123456789abcdef";
    size_t prefix_len = strlen(prefix);
    if (out_len < prefix_len + sizeof(random) * 2 + 1 || RAND_bytes(random, sizeof(random)) != 1) return -1;
    memcpy(out, prefix, prefix_len);
    for (size_t i = 0; i < sizeof(random); i++) { out[prefix_len+i*2]=hex[random[i]>>4]; out[prefix_len+i*2+1]=hex[random[i]&15]; }
    out[prefix_len + sizeof(random)*2] = '\0';
    return 0;
}
static int support_safe_id(const char *id) {
    if (!id || !id[0] || strlen(id) > 64) return 0;
    for (const unsigned char *p=(const unsigned char *)id; *p; p++)
        if (!( (*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'||*p=='.' )) return 0;
    return 1;
}
static int support_safe_id_len(const char *id, size_t len) {
    if (!id || len==0 || len>64) return 0;
    for (size_t i=0;i<len;i++) { unsigned char c=(unsigned char)id[i];
        if (!( (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.' )) return 0; }
    return 1;
}

/* Growable string buffer for safe JSON assembly. */
typedef struct { char *data; size_t len, cap; } sbuf;
static int sb_init(sbuf *s, size_t cap) { s->cap = cap?cap:1024; s->len=0; s->data=malloc(s->cap); if(!s->data) return -1; s->data[0]='\0'; return 0; }
static int sb_reserve(sbuf *s, size_t extra) { if (s->len+extra+1<=s->cap) return 0; size_t ncap=s->cap; while(ncap<s->len+extra+1) ncap*=2; char *nd=realloc(s->data,ncap); if(!nd) return -1; s->data=nd; s->cap=ncap; return 0; }
static int sb_put(sbuf *s, const char *p, size_t n) { if (sb_reserve(s,n)!=0) return -1; memcpy(s->data+s->len,p,n); s->len+=n; s->data[s->len]='\0'; return 0; }
static int sb_puts(sbuf *s, const char *str) { return str? sb_put(s,str,strlen(str)) : sb_put(s,"",0); }
static int sb_putc(sbuf *s, char c) { return sb_put(s,&c,1); }
static int sb_json_string(sbuf *s, const char *str) {
    if (sb_putc(s,'"')!=0) return -1;
    if (str) for (const unsigned char *p=(const unsigned char *)str; *p; p++) {
        switch(*p){case '"':if(sb_puts(s,"\\\""))return -1;break;case '\\':if(sb_puts(s,"\\\\"))return -1;break;
        case '\b':if(sb_puts(s,"\\b"))return -1;break;case '\f':if(sb_puts(s,"\\f"))return -1;break;
        case '\n':if(sb_puts(s,"\\n"))return -1;break;case '\r':if(sb_puts(s,"\\r"))return -1;break;
        case '\t':if(sb_puts(s,"\\t"))return -1;break;
        default: if(*p<0x20){char t[8];snprintf(t,sizeof(t),"\\u%04x",*p);if(sb_puts(s,t))return -1;} else if(sb_putc(s,(char)*p))return -1; }
    }
    return sb_putc(s,'"');
}
static int sb_fstr(sbuf *s, const char *k, const char *v) { if(sb_json_string(s,k))return -1; if(sb_putc(s,':'))return -1; return sb_json_string(s,v); }
static int sb_fnum(sbuf *s, const char *k, const char *n) { if(sb_json_string(s,k))return -1; if(sb_putc(s,':'))return -1; return sb_puts(s, n?n:"null"); }
static void sb_free(sbuf *s) { if (s&&s->data){ free(s->data); s->data=NULL; } }

/* "Manage" actions (assign/status/escalate/internal notes). Aligned to the
 * frontend's support.manage grants: platform owner, institution admin, exam
 * controller, invigilator, tech/ops admin and support engineer. Read-only
 * auditor is excluded, as are security admin and incident investigator
 * (which the frontend grants only support.view, or no support role at all),
 * so the server is never wider than the intended model. */
static int support_can_manage(user_role_t role) {
    switch (role) {
        case ROLE_PLATFORM_OWNER:
        case ROLE_INSTITUTION_ADMIN:
        case ROLE_EXAM_MANAGER:
        case ROLE_INVIGILATOR:
        case ROLE_TECH_OPERATOR:
        case ROLE_SUPPORT_ENGINEER:
            return 1;
        default:
            return 0;
    }
}
static int support_can_request_recovery(user_role_t role) { return role==ROLE_PLATFORM_OWNER || role==ROLE_INSTITUTION_ADMIN; }
static int support_sla_hours(const char *p) { if(!strcmp(p,"critical"))return 1; if(!strcmp(p,"high"))return 4; if(!strcmp(p,"normal"))return 24; return 72; }
static long now_ms(void) { struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts); return (long)ts.tv_sec*1000L+ts.tv_nsec/1000000L; }

static int status_transition_allowed(const char *from, const char *to) {
    if (!from||!to||!strcmp(from,to)) return 0;
    static const char *P[][2]={{"new","assigned"},{"new","in-progress"},{"new","waiting"},{"new","resolved"},{"new","cancelled"},
        {"assigned","in-progress"},{"assigned","waiting"},{"assigned","resolved"},{"assigned","cancelled"},{"assigned","new"},
        {"waiting","in-progress"},{"waiting","assigned"},{"waiting","resolved"},{"waiting","cancelled"},
        {"in-progress","waiting"},{"in-progress","resolved"},{"in-progress","assigned"},{"in-progress","cancelled"},
        {"resolved","closed"},{"resolved","reopened"},{"closed","reopened"},
        {"reopened","assigned"},{"reopened","in-progress"},{"reopened","waiting"},{"reopened","resolved"},{"reopened","cancelled"},
        {NULL,NULL}};
    for (int i=0;P[i][0];i++) if(!strcmp(P[i][0],from)&&!strcmp(P[i][1],to)) return 1;
    return 0;
}

/* Resolve trusted tenant scope. Platform owner names a valid institution;
 * everyone else is pinned to their session institution. */
static int resolve_scope(const auth_session_t *sess, const char *body, char *out, size_t out_len) {
    if (sess->role==ROLE_PLATFORM_OWNER) {
        char tenant[65]={0};
        if (!ctrl_json_string(body,"tenantId",tenant,sizeof(tenant)) && !ctrl_json_string(body,"tenant_id",tenant,sizeof(tenant))) tenant[0]='\0';
        if (!support_safe_id(tenant)||!tenant[0]) return -2;
        const char *p[1]={tenant};
        PGresult *r=db_query("SELECT 1 FROM examos_institutions WHERE institution_id=$1",1,p);
        int ok=r&&PQresultStatus(r)==PGRES_TUPLES_OK&&PQntuples(r)==1; if(r)PQclear(r);
        if(!ok) return -3;
        snprintf(out,out_len,"%s",tenant); return 0;
    }
    if (!sess->institution_id[0]) return -4;
    snprintf(out,out_len,"%s",sess->institution_id); return 0;
}

#define REQUEST_LIST_SQL \
  "SELECT r.id, r.ticket_no, r.institution_id, r.subject, r.description, r.category, " \
  "r.priority, r.status, r.requester_id, r.requester_name, r.assignee_id, " \
  "u.full_name AS assignee_name, r.incident_id, r.linked_device_id, r.linked_exam_id, " \
  "r.sla_due_at, r.first_response_at, r.resolved_at, r.closed_at, r.resolution, " \
  "r.escalation_reason, r.satisfaction_score, r.created_at, r.updated_at " \
  "FROM support_requests r LEFT JOIN examos_admin_users u ON u.user_id = r.assignee_id "

static int append_null_or_str(sbuf *s, const char *key, PGresult *res, int row, int col) {
    if (col>=0 && !PQgetisnull(res,row,col)) return sb_fstr(s,key,PQgetvalue(res,row,col));
    return sb_fstr(s,key,NULL);
}
static int append_null_or_num(sbuf *s, const char *key, PGresult *res, int row, int col) {
    if (col>=0 && !PQgetisnull(res,row,col)) return sb_fnum(s,key,PQgetvalue(res,row,col));
    return sb_fnum(s,key,NULL);
}
static int append_request(sbuf *s, PGresult *res, int row) {
    if (sb_putc(s,'{')!=0) return -1;
    sb_fstr(s,"id",PQgetvalue(res,row,PQfnumber(res,"id"))); sb_putc(s,',');
    sb_fstr(s,"no",PQgetvalue(res,row,PQfnumber(res,"ticket_no"))); sb_putc(s,',');
    sb_fstr(s,"tenantId",PQgetvalue(res,row,PQfnumber(res,"institution_id"))); sb_putc(s,',');
    sb_fstr(s,"subject",PQgetvalue(res,row,PQfnumber(res,"subject"))); sb_putc(s,',');
    sb_fstr(s,"description",PQgetvalue(res,row,PQfnumber(res,"description"))); sb_putc(s,',');
    sb_fstr(s,"category",PQgetvalue(res,row,PQfnumber(res,"category"))); sb_putc(s,',');
    sb_fstr(s,"priority",PQgetvalue(res,row,PQfnumber(res,"priority"))); sb_putc(s,',');
    sb_fstr(s,"status",PQgetvalue(res,row,PQfnumber(res,"status"))); sb_putc(s,',');
    sb_fstr(s,"requesterId",PQgetvalue(res,row,PQfnumber(res,"requester_id"))); sb_putc(s,',');
    sb_fstr(s,"requesterName",PQgetvalue(res,row,PQfnumber(res,"requester_name"))); sb_putc(s,',');
    append_null_or_str(s,"assignee",res,row,PQfnumber(res,"assignee_id")); sb_putc(s,',');
    append_null_or_str(s,"assigneeName",res,row,PQfnumber(res,"assignee_name")); sb_putc(s,',');
    append_null_or_str(s,"incidentId",res,row,PQfnumber(res,"incident_id")); sb_putc(s,',');
    append_null_or_str(s,"linkedDeviceId",res,row,PQfnumber(res,"linked_device_id")); sb_putc(s,',');
    append_null_or_str(s,"linkedExamId",res,row,PQfnumber(res,"linked_exam_id")); sb_putc(s,',');
    sb_fnum(s,"slaDue",PQgetvalue(res,row,PQfnumber(res,"sla_due_at"))); sb_putc(s,',');
    append_null_or_num(s,"firstResponseAt",res,row,PQfnumber(res,"first_response_at")); sb_putc(s,',');
    append_null_or_num(s,"resolvedAt",res,row,PQfnumber(res,"resolved_at")); sb_putc(s,',');
    append_null_or_num(s,"closedAt",res,row,PQfnumber(res,"closed_at")); sb_putc(s,',');
    sb_fstr(s,"resolution",PQgetvalue(res,row,PQfnumber(res,"resolution"))); sb_putc(s,',');
    sb_fstr(s,"escalationReason",PQgetvalue(res,row,PQfnumber(res,"escalation_reason"))); sb_putc(s,',');
    append_null_or_num(s,"satisfactionScore",res,row,PQfnumber(res,"satisfaction_score")); sb_putc(s,',');
    sb_fnum(s,"createdAt",PQgetvalue(res,row,PQfnumber(res,"created_at"))); sb_putc(s,',');
    sb_fnum(s,"updatedAt",PQgetvalue(res,row,PQfnumber(res,"updated_at")));
    return sb_putc(s,'}');
}

static int record_event(PGconn *conn, const char *request_id, const auth_session_t *actor,
                        const char *event_type, const char *detail) {
    char eid[64]; if (support_gen_id(eid,sizeof(eid),"sev_")!=0) return -1;
    const char *p[5]={eid,request_id,actor->user_id,event_type,detail?detail:""};
    int l[5]; for(int i=0;i<5;i++) l[i]=(int)strlen(p[i]);
    PGresult *res=db_simple(conn,"INSERT INTO support_events (id,request_id,actor_id,event_type,detail,created_at) "
        "VALUES ($1,$2,$3,$4,$5,(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000)",5,p,l);
    int ok=res&&PQresultStatus(res)==PGRES_COMMAND_OK; if(res)PQclear(res); return ok?0:-1;
}
static PGresult *fetch_request_scoped(const char *id, const auth_session_t *sess) {
    const char *p[2]={id,sess->institution_id};
    if (sess->role==ROLE_PLATFORM_OWNER) return db_query(REQUEST_LIST_SQL "WHERE r.id=$1",1,p);
    return db_query(REQUEST_LIST_SQL "WHERE r.id=$1 AND r.institution_id=$2",2,p);
}
static int parse_request_action(const char *path, char *req_id, size_t req_len, char *action, size_t act_len) {
    static const char prefix[]="/api/v1/support/requests/";
    if (strncmp(path,prefix,sizeof(prefix)-1)!=0) return 0;
    const char *rest=path+sizeof(prefix)-1;
    const char *slash=strchr(rest,'/');
    size_t id_len=slash?(size_t)(slash-rest):strlen(rest);
    if (!id_len||id_len>=req_len||!support_safe_id_len(rest,id_len)) return 0;
    memcpy(req_id,rest,id_len); req_id[id_len]='\0';
    if (slash) snprintf(action,act_len,"%s",slash+1); else action[0]='\0';
    return 1;
}

/* GET /requests */
static void support_list(int fd, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    PGresult *res;
    if (sess->role==ROLE_PLATFORM_OWNER) res=db_query(REQUEST_LIST_SQL "ORDER BY r.created_at DESC LIMIT 500",0,NULL);
    else { const char *p[1]={sess->institution_id}; res=db_query(REQUEST_LIST_SQL "WHERE r.institution_id=$1 ORDER BY r.created_at DESC LIMIT 500",1,p); }
    if (!res||PQresultStatus(res)!=PGRES_TUPLES_OK) { if(res)PQclear(res); support_error(fd,500,"Database read failed",origin,extra,extra_len); return; }
    sbuf s; if (sb_init(&s,8192)!=0) { PQclear(res); support_error(fd,500,"Out of memory",origin,extra,extra_len); return; }
    sb_putc(&s,'[');
    for (int i=0;i<PQntuples(res);i++) { if(i)sb_putc(&s,','); append_request(&s,res,i); }
    sb_putc(&s,']'); PQclear(res);
    support_send(fd,200,s.data,origin,extra,extra_len); sb_free(&s);
}

/* POST /requests */
static void support_create(int fd, const char *body, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    if (!body||body[0]!='{') { support_error(fd,400,"A JSON body is required",origin,extra,extra_len); return; }
    char subject[161]={0}, description[4001]={0}, category[25]={0}, priority[13]={0};
    char linked_device[65]={0}, linked_exam[65]={0}, requester_name[128]={0};
    ctrl_json_string(body,"subject",subject,sizeof(subject));
    ctrl_json_string(body,"description",description,sizeof(description));
    ctrl_json_string(body,"category",category,sizeof(category));
    ctrl_json_string(body,"priority",priority,sizeof(priority));
    ctrl_json_string(body,"linkedDeviceId",linked_device,sizeof(linked_device));
    ctrl_json_string(body,"linkedExamId",linked_exam,sizeof(linked_exam));
    ctrl_json_string(body,"requesterName",requester_name,sizeof(requester_name));
    if (strlen(subject)<5) { support_error(fd,400,"Subject must be at least 5 characters",origin,extra,extra_len); return; }
    if (strlen(description)<10) { support_error(fd,400,"Description must be at least 10 characters",origin,extra,extra_len); return; }
    const char *vc[]={"device","exam","access","policy","billing","data","other"}, *vp[]={"critical","high","normal","low"};
    int cat_ok=0,pri_ok=0;
    for (size_t i=0;i<sizeof(vc)/sizeof(vc[0]);i++) if(!strcmp(category,vc[i])) cat_ok=1;
    for (size_t i=0;i<sizeof(vp)/sizeof(vp[0]);i++) if(!strcmp(priority,vp[i])) pri_ok=1;
    if (!cat_ok) { support_error(fd,400,"Invalid category",origin,extra,extra_len); return; }
    if (!pri_ok) { support_error(fd,400,"Invalid priority",origin,extra,extra_len); return; }
    char institution[65]={0}; int sc=resolve_scope(sess,body,institution,sizeof(institution));
    if (sc==-2) { support_error(fd,400,"A valid tenantId is required",origin,extra,extra_len); return; }
    if (sc==-3) { support_error(fd,400,"Unknown institution",origin,extra,extra_len); return; }
    if (sc==-4) { support_error(fd,403,"No institution context for this account",origin,extra,extra_len); return; }
    if (sc!=0) { support_error(fd,403,"Scope not allowed",origin,extra,extra_len); return; }
    if (linked_device[0]&&!support_safe_id(linked_device)) { support_error(fd,400,"Invalid device id",origin,extra,extra_len); return; }
    if (linked_exam[0]&&!support_safe_id(linked_exam)) { support_error(fd,400,"Invalid exam id",origin,extra,extra_len); return; }
    char id[64], incident_id[64]={0};
    if (support_gen_id(id,sizeof(id),"sup_")!=0) { support_error(fd,500,"Id generation failed",origin,extra,extra_len); return; }
    long created=now_ms(); long sla_due=created+(long)support_sla_hours(priority)*3600L*1000L;
    char sla_text[24], created_text[24]; snprintf(sla_text,sizeof(sla_text),"%ld",sla_due); snprintf(created_text,sizeof(created_text),"%ld",created);
    PGconn *conn=db_acquire(); if (!conn) { support_error(fd,503,"Database unavailable",origin,extra,extra_len); return; }
    if (!PQexec(conn,"BEGIN")) { db_release(conn,1); support_error(fd,500,"Transaction error",origin,extra,extra_len); return; }
    PGresult *seq=PQexec(conn,"SELECT 'SUP-' || nextval('support_ticket_seq')");
    if (!seq||PQresultStatus(seq)!=PGRES_TUPLES_OK||PQntuples(seq)!=1) { if(seq)PQclear(seq); PQexec(conn,"ROLLBACK"); db_release(conn,1); support_error(fd,500,"Ticket sequence unavailable",origin,extra,extra_len); return; }
    char ticket_no[32]; snprintf(ticket_no,sizeof(ticket_no),"%s",PQgetvalue(seq,0,0)); PQclear(seq);
    const char *params[13]={id,ticket_no,institution,subject,description,category,priority,sess->user_id,
        requester_name[0]?requester_name:sess->username,sla_text,created_text,linked_device,linked_exam};
    int lens[13]; for(int i=0;i<13;i++) lens[i]=(int)strlen(params[i]);
    PGresult *ins=db_simple(conn,"INSERT INTO support_requests (id,ticket_no,institution_id,subject,description,category,priority,"
        "status,requester_id,requester_name,sla_due_at,created_at,updated_at,linked_device_id,linked_exam_id) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,'new',$8,$9,$10,$11,$11,NULLIF($12,''),NULLIF($13,''))",13,params,lens);
    int ok=ins&&PQresultStatus(ins)==PGRES_COMMAND_OK; if(ins)PQclear(ins);
    if (!ok) { PQexec(conn,"ROLLBACK"); db_release(conn,1); support_error(fd,500,"Could not create request",origin,extra,extra_len); return; }
    char msg_id[64]; if (support_gen_id(msg_id,sizeof(msg_id),"msg_")==0) {
        const char *mp[6]={msg_id,id,sess->user_id,sess->username,description};
        int ml[6]; for(int i=0;i<5;i++) ml[i]=(int)strlen(mp[i]); ml[5]=4;
        PGresult *mi=db_simple(conn,"INSERT INTO support_comments (id,request_id,author_id,author_name,body,internal,created_at) "
            "VALUES ($1,$2,$3,$4,$5,FALSE,(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000)",5,mp,ml);
        if(mi)PQclear(mi);
    }
    record_event(conn,id,sess,"SUPPORT_REQUEST_CREATED",ticket_no);
    if (!strcmp(priority,"critical") && support_gen_id(incident_id,sizeof(incident_id),"sinc_")==0) {
        char title[192]; snprintf(title,sizeof(title),"%s: %s",ticket_no,subject);
        const char *ip[5]={incident_id,institution,title,"HIGH",linked_device};
        int il[5]; for(int i=0;i<5;i++) il[i]=(int)strlen(ip[i]);
        PGresult *ii=db_simple(conn,"INSERT INTO examos_security_incidents (incident_id,institution_id,title,severity,status,device_id,summary) "
            "VALUES ($1,$2,$3,$4,'OPEN',NULLIF($5,''),$3)",5,ip,il);
        if (ii&&PQresultStatus(ii)==PGRES_COMMAND_OK) { PQclear(ii);
            const char *lp[2]={incident_id,id}; int ll[2]={(int)strlen(lp[0]),(int)strlen(lp[1])};
            PGresult *lu=db_simple(conn,"UPDATE support_requests SET incident_id=$1,updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$2",2,lp,ll);
            if(lu)PQclear(lu); record_event(conn,id,sess,"SUPPORT_AUTO_INCIDENT",incident_id);
        } else if(ii)PQclear(ii);
    }
    if (!PQexec(conn,"COMMIT")) { db_release(conn,1); support_error(fd,500,"Commit failed",origin,extra,extra_len); return; }
    db_release(conn,0); audit_append(sess->user_id,"SUPPORT_REQUEST_CREATED",ticket_no);
    /* Return the created request with its first message. */
    const char *gp[1]={id}; PGresult *gr=db_query(REQUEST_LIST_SQL "WHERE r.id=$1",1,gp);
    if (gr&&PQresultStatus(gr)==PGRES_TUPLES_OK&&PQntuples(gr)==1) {
        sbuf s; if (sb_init(&s,4096)==0) {
            append_request(&s,gr,0); PQclear(gr);
            const char *cp[1]={id}; PGresult *cr=db_query("SELECT id,author_id,author_name,body,internal,created_at FROM support_comments WHERE request_id=$1 ORDER BY created_at",1,cp);
            if (s.len>0&&s.data[s.len-1]=='}') { s.len--; s.data[s.len]='\0'; }
            sb_puts(&s,",\"messages\":[");
            if (cr&&PQresultStatus(cr)==PGRES_TUPLES_OK) for (int i=0;i<PQntuples(cr);i++) {
                if(i)sb_putc(&s,','); sb_putc(&s,'{');
                sb_fstr(&s,"id",PQgetvalue(cr,i,0)); sb_putc(&s,','); sb_fstr(&s,"by",PQgetvalue(cr,i,1)); sb_putc(&s,',');
                sb_fstr(&s,"authorName",PQgetvalue(cr,i,2)); sb_putc(&s,','); sb_fstr(&s,"text",PQgetvalue(cr,i,3)); sb_putc(&s,',');
                sb_fstr(&s,"internal",strcmp(PQgetvalue(cr,i,4),"t")==0?"true":"false"); sb_putc(&s,','); sb_fnum(&s,"at",PQgetvalue(cr,i,5));
                sb_putc(&s,'}');
            }
            if(cr)PQclear(cr); sb_puts(&s,"]}");
            support_send(fd,201,s.data,origin,extra,extra_len); sb_free(&s); return;
        } else sb_free(&s);
    }
    if(gr)PQclear(gr);
    support_send(fd,201,"{\"status\":\"created\"}",origin,extra,extra_len);
}

/* GET /requests/{id} */
static void support_detail(int fd, const char *req_id, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    PGresult *res=fetch_request_scoped(req_id,sess);
    if (!res||PQresultStatus(res)!=PGRES_TUPLES_OK||PQntuples(res)!=1) { if(res)PQclear(res); support_error(fd,404,"Request not found",origin,extra,extra_len); return; }
    sbuf s; if (sb_init(&s,8192)!=0) { PQclear(res); support_error(fd,500,"Out of memory",origin,extra,extra_len); return; }
    append_request(&s,res,0); PQclear(res);
    int show_internal=support_can_manage(sess->role);
    const char *cp[1]={req_id};
    PGresult *cr=db_query("SELECT id,author_id,author_name,body,internal,created_at FROM support_comments WHERE request_id=$1 ORDER BY created_at",1,cp);
    if (s.len>0&&s.data[s.len-1]=='}') { s.len--; s.data[s.len]='\0'; }
    sb_puts(&s,",\"messages\":[");
    if (cr&&PQresultStatus(cr)==PGRES_TUPLES_OK) for (int i=0,first=1;i<PQntuples(cr);i++) {
        int internal=strcmp(PQgetvalue(cr,i,4),"t")==0; if (internal&&!show_internal) continue;
        if(!first)sb_putc(&s,','); first=0; sb_putc(&s,'{');
        sb_fstr(&s,"id",PQgetvalue(cr,i,0)); sb_putc(&s,','); sb_fstr(&s,"by",PQgetvalue(cr,i,1)); sb_putc(&s,',');
        sb_fstr(&s,"authorName",PQgetvalue(cr,i,2)); sb_putc(&s,','); sb_fstr(&s,"text",PQgetvalue(cr,i,3)); sb_putc(&s,',');
        sb_fstr(&s,"internal",internal?"true":"false"); sb_putc(&s,','); sb_fnum(&s,"at",PQgetvalue(cr,i,5)); sb_putc(&s,'}');
    }
    if(cr)PQclear(cr);
    sb_puts(&s,"],\"events\":[");
    PGresult *er=db_query("SELECT actor_id,event_type,detail,created_at FROM support_events WHERE request_id=$1 ORDER BY created_at",1,cp);
    if (er&&PQresultStatus(er)==PGRES_TUPLES_OK) for (int i=0;i<PQntuples(er);i++) {
        if(i)sb_putc(&s,','); sb_putc(&s,'{'); sb_fstr(&s,"by",PQgetvalue(er,i,0)); sb_putc(&s,',');
        sb_fstr(&s,"event",PQgetvalue(er,i,1)); sb_putc(&s,','); sb_fstr(&s,"detail",PQgetvalue(er,i,2)); sb_putc(&s,',');
        sb_fnum(&s,"at",PQgetvalue(er,i,3)); sb_putc(&s,'}');
    }
    if(er)PQclear(er);
    PGresult *rr=db_query("SELECT id,kind,target,state,approval_request_id FROM support_recoveries WHERE request_id=$1 LIMIT 1",1,cp);
    if (rr&&PQresultStatus(rr)==PGRES_TUPLES_OK&&PQntuples(rr)==1) {
        sb_puts(&s,"],\"recovery\":{"); sb_fstr(&s,"id",PQgetvalue(rr,0,0)); sb_putc(&s,',');
        sb_fstr(&s,"kind",PQgetvalue(rr,0,1)); sb_putc(&s,','); sb_fstr(&s,"target",PQgetvalue(rr,0,2)); sb_putc(&s,',');
        sb_fstr(&s,"state",PQgetvalue(rr,0,3)); sb_putc(&s,','); append_null_or_str(&s,"approvalId",rr,0,4); sb_puts(&s,"}}");
    } else sb_puts(&s,"]}");
    if(rr)PQclear(rr);
    support_send(fd,200,s.data,origin,extra,extra_len); sb_free(&s);
}

/* POST /requests/{id}/comments */
static void support_comment(int fd, const char *req_id, const char *body, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    if (!body||body[0]!='{') { support_error(fd,400,"A JSON body is required",origin,extra,extra_len); return; }
    char text[4001]={0}; int internal=0;
    ctrl_json_string(body,"text",text,sizeof(text)); ctrl_json_bool(body,"internal",&internal);
    if (strlen(text)<2) { support_error(fd,400,"Message too short",origin,extra,extra_len); return; }
    if (internal&&!support_can_manage(sess->role)) { support_error(fd,403,"Only support staff may add internal notes",origin,extra,extra_len); return; }
    PGresult *ex=fetch_request_scoped(req_id,sess);
    if (!ex||PQresultStatus(ex)!=PGRES_TUPLES_OK||PQntuples(ex)!=1) { if(ex)PQclear(ex); support_error(fd,404,"Request not found",origin,extra,extra_len); return; }
    char requester_id[64]={0}; int rc=PQfnumber(ex,"requester_id"); if(rc>=0)snprintf(requester_id,sizeof(requester_id),"%s",PQgetvalue(ex,0,rc));
    PQclear(ex);
    PGconn *conn=db_acquire(); if(!conn){support_error(fd,503,"Database unavailable",origin,extra,extra_len);return;}
    if(!PQexec(conn,"BEGIN")){db_release(conn,1);support_error(fd,500,"Transaction error",origin,extra,extra_len);return;}
    char msg_id[64]; if(support_gen_id(msg_id,sizeof(msg_id),"msg_")!=0){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,500,"Id failed",origin,extra,extra_len);return;}
    const char *p[6]={msg_id,req_id,sess->user_id,sess->username,text,internal?"true":"false"};
    int l[6]; for(int i=0;i<6;i++)l[i]=(int)strlen(p[i]);
    PGresult *ins=db_simple(conn,"INSERT INTO support_comments (id,request_id,author_id,author_name,body,internal,created_at) "
        "VALUES ($1,$2,$3,$4,$5,$6::boolean,(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000)",6,p,l);
    int ok=ins&&PQresultStatus(ins)==PGRES_COMMAND_OK; if(ins)PQclear(ins);
    if(!ok){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,500,"Could not add message",origin,extra,extra_len);return;}
    if (strcmp(requester_id,sess->user_id)!=0) {
        const char *fp[1]={req_id}; int fl[1]={(int)strlen(fp[0])};
        PGresult *u=db_simple(conn,"UPDATE support_requests SET first_response_at=COALESCE(first_response_at,(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000), "
            "status=CASE WHEN status='new' THEN 'in-progress' ELSE status END, updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$1",1,fp,fl);
        if(u)PQclear(u);
    } else {
        const char *fp[1]={req_id}; int fl[1]={(int)strlen(fp[0])};
        PGresult *u=db_simple(conn,"UPDATE support_requests SET updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$1",1,fp,fl);
        if(u)PQclear(u);
    }
    record_event(conn,req_id,sess,internal?"SUPPORT_INTERNAL_NOTE":"SUPPORT_REPLY",text);
    if(!PQexec(conn,"COMMIT")){db_release(conn,1);support_error(fd,500,"Commit failed",origin,extra,extra_len);return;}
    db_release(conn,0); audit_append(sess->user_id,internal?"SUPPORT_INTERNAL_NOTE":"SUPPORT_REPLY",req_id);
    support_send(fd,200,"{\"status\":\"added\"}",origin,extra,extra_len);
}

/* POST /requests/{id}/assign */
static void support_assign(int fd, const char *req_id, const char *body, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    if (!support_can_manage(sess->role)) { support_error(fd,403,"Permission denied",origin,extra,extra_len); return; }
    char assignee[65]={0}, reason[256]={0};
    ctrl_json_string(body,"assignee",assignee,sizeof(assignee)); ctrl_json_string(body,"reason",reason,sizeof(reason));
    if (!support_safe_id(assignee)) { support_error(fd,400,"A valid assignee id is required",origin,extra,extra_len); return; }
    PGresult *ex=fetch_request_scoped(req_id,sess);
    if (!ex||PQresultStatus(ex)!=PGRES_TUPLES_OK||PQntuples(ex)!=1) { if(ex)PQclear(ex); support_error(fd,404,"Request not found",origin,extra,extra_len); return; }
    char inst[65]={0}, cur_status[16]={0};
    int ic=PQfnumber(ex,"institution_id"), sc=PQfnumber(ex,"status");
    if(ic>=0)snprintf(inst,sizeof(inst),"%s",PQgetvalue(ex,0,ic));
    if(sc>=0)snprintf(cur_status,sizeof(cur_status),"%s",PQgetvalue(ex,0,sc));
    PQclear(ex);
    const char *ap[2]={assignee,inst};
    PGresult *au=db_query("SELECT 1 FROM examos_admin_users WHERE user_id=$1 AND institution_id=$2 AND active=TRUE",2,ap);
    if (!au||PQresultStatus(au)!=PGRES_TUPLES_OK||PQntuples(au)!=1) { if(au)PQclear(au); support_error(fd,400,"Assignee is not an active admin in this institution",origin,extra,extra_len); return; }
    PQclear(au);
    PGconn *conn=db_acquire(); if(!conn){support_error(fd,503,"Database unavailable",origin,extra,extra_len);return;}
    if(!PQexec(conn,"BEGIN")){db_release(conn,1);support_error(fd,500,"Transaction error",origin,extra,extra_len);return;}
    const char *p[3]={assignee,req_id,(strcmp(cur_status,"new")==0)?"assigned":cur_status};
    int l[3]; for(int i=0;i<3;i++)l[i]=(int)strlen(p[i]);
    PGresult *u=db_simple(conn,"UPDATE support_requests SET assignee_id=$1, status=$3, updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$2",3,p,l);
    int ok=u&&PQresultStatus(u)==PGRES_COMMAND_OK; if(u)PQclear(u);
    if(!ok){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,500,"Assign failed",origin,extra,extra_len);return;}
    char detail[300]; snprintf(detail,sizeof(detail),"%s -> %s%s%s",req_id,assignee,reason[0]?": ":"",reason[0]?reason:"");
    record_event(conn,req_id,sess,"SUPPORT_ASSIGNED",detail);
    if(!PQexec(conn,"COMMIT")){db_release(conn,1);support_error(fd,500,"Commit failed",origin,extra,extra_len);return;}
    db_release(conn,0); audit_append(sess->user_id,"SUPPORT_ASSIGNED",detail);
    support_send(fd,200,"{\"status\":\"assigned\"}",origin,extra,extra_len);
}

/* POST /requests/{id}/status */
static void support_status(int fd, const char *req_id, const char *body, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    if (!support_can_manage(sess->role)) { support_error(fd,403,"Permission denied",origin,extra,extra_len); return; }
    char status[17]={0}, note[4001]={0};
    ctrl_json_string(body,"status",status,sizeof(status)); ctrl_json_string(body,"note",note,sizeof(note));
    if (!status[0]) { support_error(fd,400,"A status is required",origin,extra,extra_len); return; }
    PGresult *ex=fetch_request_scoped(req_id,sess);
    if (!ex||PQresultStatus(ex)!=PGRES_TUPLES_OK||PQntuples(ex)!=1) { if(ex)PQclear(ex); support_error(fd,404,"Request not found",origin,extra,extra_len); return; }
    char from[17]={0}; int sc=PQfnumber(ex,"status"); if(sc>=0)snprintf(from,sizeof(from),"%s",PQgetvalue(ex,0,sc));
    int resolved_null=1; int rc=PQfnumber(ex,"resolved_at"); if(rc>=0)resolved_null=PQgetisnull(ex,0,rc);
    PQclear(ex);
    if (!status_transition_allowed(from,status)) { support_error(fd,409,"Invalid status transition",origin,extra,extra_len); return; }
    if (!strcmp(status,"resolved")&&strlen(note)<10) { support_error(fd,400,"A resolution note of 10+ characters is required",origin,extra,extra_len); return; }
    if (!strcmp(status,"closed")&&resolved_null) { support_error(fd,409,"Resolve the request before closing it",origin,extra,extra_len); return; }
    PGconn *conn=db_acquire(); if(!conn){support_error(fd,503,"Database unavailable",origin,extra,extra_len);return;}
    if(!PQexec(conn,"BEGIN")){db_release(conn,1);support_error(fd,500,"Transaction error",origin,extra,extra_len);return;}
    const char *params[3]={status,req_id,note}; int lens[3]={strlen(status),strlen(req_id),strlen(note)};
    const char *sql;
    if (!strcmp(status,"resolved")) sql="UPDATE support_requests SET status=$1, resolution=$3, resolved_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000, updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$2";
    else if (!strcmp(status,"closed")) sql="UPDATE support_requests SET status=$1, closed_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000, updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$2";
    else sql="UPDATE support_requests SET status=$1, updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$2";
    PGresult *u=db_simple(conn,sql,3,params,lens);
    int ok=u&&PQresultStatus(u)==PGRES_COMMAND_OK; if(u)PQclear(u);
    if(!ok){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,500,"Status update failed",origin,extra,extra_len);return;}
    if (!strcmp(status,"resolved")) {
        char msg_id[64], text[4050];
        if (support_gen_id(msg_id,sizeof(msg_id),"msg_")==0) { snprintf(text,sizeof(text),"Resolved: %s",note);
            const char *mp[5]={msg_id,req_id,sess->user_id,sess->username,text}; int ml[5]; for(int i=0;i<5;i++)ml[i]=(int)strlen(mp[i]);
            PGresult *mi=db_simple(conn,"INSERT INTO support_comments (id,request_id,author_id,author_name,body,internal,created_at) VALUES ($1,$2,$3,$4,$5,FALSE,(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000)",5,mp,ml);
            if(mi)PQclear(mi);
        }
    }
    char ev[48]; snprintf(ev,sizeof(ev),"SUPPORT_%s",status); for(char *p=ev;*p;p++) if(*p=='-')*p='_';
    record_event(conn,req_id,sess,ev,note);
    if(!PQexec(conn,"COMMIT")){db_release(conn,1);support_error(fd,500,"Commit failed",origin,extra,extra_len);return;}
    db_release(conn,0); audit_append(sess->user_id,ev,req_id);
    support_send(fd,200,"{\"status\":\"updated\"}",origin,extra,extra_len);
}

/* POST /requests/{id}/escalate */
static void support_escalate(int fd, const char *req_id, const char *body, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    if (!support_can_manage(sess->role)) { support_error(fd,403,"Permission denied",origin,extra,extra_len); return; }
    char reason[301]={0}; ctrl_json_string(body,"reason",reason,sizeof(reason));
    if (strlen(reason)<8) { support_error(fd,400,"A reason of 8+ characters is required",origin,extra,extra_len); return; }
    PGresult *ex=fetch_request_scoped(req_id,sess);
    if (!ex||PQresultStatus(ex)!=PGRES_TUPLES_OK||PQntuples(ex)!=1) { if(ex)PQclear(ex); support_error(fd,404,"Request not found",origin,extra,extra_len); return; }
    char inst[65]={0}, subj[141]={0}, prio[13]={0}, dev[65]={0};
    int ic=PQfnumber(ex,"institution_id"), sc=PQfnumber(ex,"subject"), pc=PQfnumber(ex,"priority"), dc=PQfnumber(ex,"linked_device_id");
    if(ic>=0)snprintf(inst,sizeof(inst),"%s",PQgetvalue(ex,0,ic));
    if(sc>=0)snprintf(subj,sizeof(subj),"%s",PQgetvalue(ex,0,sc));
    if(pc>=0)snprintf(prio,sizeof(prio),"%s",PQgetvalue(ex,0,pc));
    if(dc>=0&&!PQgetisnull(ex,0,dc))snprintf(dev,sizeof(dev),"%s",PQgetvalue(ex,0,dc));
    PQclear(ex);
    char incident_id[64]; if(support_gen_id(incident_id,sizeof(incident_id),"sinc_")!=0){support_error(fd,500,"Id failed",origin,extra,extra_len);return;}
    char title[200]; snprintf(title,sizeof(title),"%s: %s",req_id,subj);
    const char *sev=!strcmp(prio,"critical")?"CRITICAL":"HIGH";
    PGconn *conn=db_acquire(); if(!conn){support_error(fd,503,"Database unavailable",origin,extra,extra_len);return;}
    if(!PQexec(conn,"BEGIN")){db_release(conn,1);support_error(fd,500,"Transaction error",origin,extra,extra_len);return;}
    const char *ip[5]={incident_id,inst,title,sev,dev}; int il[5]; for(int i=0;i<5;i++)il[i]=(int)strlen(ip[i]);
    PGresult *ii=db_simple(conn,"INSERT INTO examos_security_incidents (incident_id,institution_id,title,severity,status,device_id,summary) VALUES ($1,$2,$3,$4,'OPEN',NULLIF($5,''),$3)",5,ip,il);
    int ok=ii&&PQresultStatus(ii)==PGRES_COMMAND_OK; if(ii)PQclear(ii);
    if(!ok){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,500,"Incident creation failed",origin,extra,extra_len);return;}
    const char *up[3]={incident_id,req_id,reason}; int ul[3]; for(int i=0;i<3;i++)ul[i]=(int)strlen(up[i]);
    PGresult *u=db_simple(conn,"UPDATE support_requests SET incident_id=$1, status='in-progress', priority='high', escalation_reason=$3, updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$2",3,up,ul);
    ok=u&&PQresultStatus(u)==PGRES_COMMAND_OK; if(u)PQclear(u);
    if(!ok){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,500,"Link failed",origin,extra,extra_len);return;}
    char detail[330]; snprintf(detail,sizeof(detail),"%s -> %s: %s",req_id,incident_id,reason);
    record_event(conn,req_id,sess,"SUPPORT_ESCALATED",detail);
    if(!PQexec(conn,"COMMIT")){db_release(conn,1);support_error(fd,500,"Commit failed",origin,extra,extra_len);return;}
    db_release(conn,0); audit_append(sess->user_id,"SUPPORT_ESCALATED",detail);
    sbuf s; if(sb_init(&s,128)==0){ sb_puts(&s,"{\"status\":\"escalated\",\"incidentId\":"); sb_json_string(&s,incident_id); sb_putc(&s,'}'); support_send(fd,200,s.data,origin,extra,extra_len); sb_free(&s); }
    else support_send(fd,200,"{\"status\":\"escalated\"}",origin,extra,extra_len);
}

/* POST /requests/{id}/rate */
static void support_rate(int fd, const char *req_id, const char *body, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    int score=0; char comment[501]={0};
    ctrl_json_int(body,"score",&score); ctrl_json_string(body,"comment",comment,sizeof(comment));
    if (score<1||score>5) { support_error(fd,400,"Score must be between 1 and 5",origin,extra,extra_len); return; }
    PGresult *ex=fetch_request_scoped(req_id,sess);
    if (!ex||PQresultStatus(ex)!=PGRES_TUPLES_OK||PQntuples(ex)!=1) { if(ex)PQclear(ex); support_error(fd,404,"Request not found",origin,extra,extra_len); return; }
    PQclear(ex);
    char score_text[8]; snprintf(score_text,sizeof(score_text),"%d",score);
    const char *p[2]={score_text,req_id};
    PGresult *u=db_query("UPDATE support_requests SET satisfaction_score=$1::smallint, updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$2",2,p);
    int ok=u&&PQresultStatus(u)==PGRES_COMMAND_OK; if(u)PQclear(u);
    if(!ok){support_error(fd,500,"Rating failed",origin,extra,extra_len);return;}
    audit_append(sess->user_id,"SUPPORT_RATED",req_id);
    support_send(fd,200,"{\"status\":\"rated\"}",origin,extra,extra_len);
}

/* GET /stats */
static void support_stats(int fd, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    PGresult *r;
    if (sess->role==ROLE_PLATFORM_OWNER)
        r=db_query("SELECT COUNT(*), COUNT(*) FILTER (WHERE status IN ('new','assigned','waiting','in-progress','reopened')), "
            "COUNT(*) FILTER (WHERE status IN ('new','assigned','waiting','in-progress','reopened') AND priority='critical'), "
            "COUNT(*) FILTER (WHERE status IN ('new','assigned','waiting','in-progress','reopened') AND first_response_at IS NULL AND sla_due_at<(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000), "
            "COUNT(*) FILTER (WHERE status IN ('resolved','closed')), "
            "COALESCE(ROUND(AVG(satisfaction_score) FILTER (WHERE satisfaction_score IS NOT NULL)),0), "
            "COALESCE(ROUND(AVG(first_response_at-created_at) FILTER (WHERE first_response_at IS NOT NULL))/60000,0) FROM support_requests",0,NULL);
    else {
        const char *p[1]={sess->institution_id};
        r=db_query("SELECT COUNT(*), COUNT(*) FILTER (WHERE institution_id=$1 AND status IN ('new','assigned','waiting','in-progress','reopened')), "
            "COUNT(*) FILTER (WHERE institution_id=$1 AND status IN ('new','assigned','waiting','in-progress','reopened') AND priority='critical'), "
            "COUNT(*) FILTER (WHERE institution_id=$1 AND status IN ('new','assigned','waiting','in-progress','reopened') AND first_response_at IS NULL AND sla_due_at<(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000), "
            "COUNT(*) FILTER (WHERE institution_id=$1 AND status IN ('resolved','closed')), "
            "COALESCE(ROUND(AVG(satisfaction_score) FILTER (WHERE satisfaction_score IS NOT NULL)),0), "
            "COALESCE(ROUND(AVG(first_response_at-created_at) FILTER (WHERE first_response_at IS NOT NULL))/60000,0) FROM support_requests WHERE institution_id=$1",1,p);
    }
    if (!r||PQresultStatus(r)!=PGRES_TUPLES_OK||PQntuples(r)!=1) { if(r)PQclear(r); support_error(fd,500,"Stats unavailable",origin,extra,extra_len); return; }
    sbuf s; if(sb_init(&s,512)!=0){PQclear(r);support_error(fd,500,"Out of memory",origin,extra,extra_len);return;}
    sb_puts(&s,"{\"total\":"); sb_puts(&s,PQgetvalue(r,0,0)); sb_putc(&s,',');
    sb_puts(&s,"\"open\":"); sb_puts(&s,PQgetvalue(r,0,1)); sb_putc(&s,',');
    sb_puts(&s,"\"critical\":"); sb_puts(&s,PQgetvalue(r,0,2)); sb_putc(&s,',');
    sb_puts(&s,"\"breached\":"); sb_puts(&s,PQgetvalue(r,0,3)); sb_putc(&s,',');
    sb_puts(&s,"\"resolved\":"); sb_puts(&s,PQgetvalue(r,0,4)); sb_putc(&s,',');
    sb_puts(&s,"\"avgSatisfaction\":"); sb_puts(&s,PQgetvalue(r,0,5)); sb_putc(&s,',');
    sb_puts(&s,"\"firstResponseMins\":"); sb_puts(&s,PQgetvalue(r,0,6)); sb_putc(&s,'}');
    PQclear(r); support_send(fd,200,s.data,origin,extra,extra_len); sb_free(&s);
}

/* GET /diagnostics — real, read-only checks executed live. */
static void support_diagnostics(int fd, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    const char *inst=(sess->role==ROLE_PLATFORM_OWNER)?NULL:sess->institution_id;
    sbuf s; if(sb_init(&s,8192)!=0){support_error(fd,500,"Out of memory",origin,extra,extra_len);return;}
    sb_puts(&s,"{\"checks\":[");
    int db_ok=(db_health()==0);
    sb_puts(&s,"{\"key\":\"database\",\"label\":\"PostgreSQL database\",\"status\":\""); sb_puts(&s,db_ok?"PASS":"FAIL");
    sb_puts(&s,"\",\"detail\":\""); sb_puts(&s,db_ok?"Server-side health check succeeded":"Database health check failed"); sb_puts(&s,"\"},");
    /* open incidents */
    { PGresult *r=inst?db_query("SELECT COUNT(*) FROM examos_security_incidents WHERE institution_id=$1 AND status IN ('OPEN','INVESTIGATING','CONTAINED')",1,&inst)
        : db_query("SELECT COUNT(*) FROM examos_security_incidents WHERE status IN ('OPEN','INVESTIGATING','CONTAINED')",0,NULL);
      long c=0; if(r&&PQresultStatus(r)==PGRES_TUPLES_OK&&PQntuples(r)==1)c=atol(PQgetvalue(r,0,0)); if(r)PQclear(r);
      char d[80]; snprintf(d,sizeof(d),"%ld open incident(s)",c);
      sb_puts(&s,"{\"key\":\"incidents\",\"label\":\"Open incidents\",\"status\":\""); sb_puts(&s,c?"WARN":"PASS");
      sb_puts(&s,"\",\"detail\":\""); sb_puts(&s,d); sb_puts(&s,"\"},");
    }
    /* support queue */
    { const char *pi=inst?inst:""; PGresult *r=inst?db_query("SELECT COUNT(*) FROM support_requests WHERE institution_id=$1 AND status IN ('new','assigned','waiting','in-progress','reopened')",1,&pi)
        : db_query("SELECT COUNT(*) FROM support_requests WHERE status IN ('new','assigned','waiting','in-progress','reopened')",0,NULL);
      long c=0; if(r&&PQresultStatus(r)==PGRES_TUPLES_OK&&PQntuples(r)==1)c=atol(PQgetvalue(r,0,0)); if(r)PQclear(r);
      char d[80]; snprintf(d,sizeof(d),"%ld open request(s)",c);
      sb_puts(&s,"{\"key\":\"support\",\"label\":\"Support queue\",\"status\":\"PASS\",\"detail\":\""); sb_puts(&s,d); sb_puts(&s,"\"},");
    }
    /* recovery pending */
    { const char *pi=inst?inst:""; PGresult *r=inst?db_query("SELECT COUNT(*) FROM support_recoveries WHERE institution_id=$1 AND state='pending-approval'",1,&pi)
        : db_query("SELECT COUNT(*) FROM support_recoveries WHERE state='pending-approval'",0,NULL);
      long c=0; if(r&&PQresultStatus(r)==PGRES_TUPLES_OK&&PQntuples(r)==1)c=atol(PQgetvalue(r,0,0)); if(r)PQclear(r);
      char d[80]; snprintf(d,sizeof(d),"%ld awaiting approval",c);
      sb_puts(&s,"{\"key\":\"recovery\",\"label\":\"Recovery pending\",\"status\":\""); sb_puts(&s,c?"WARN":"PASS");
      sb_puts(&s,"\",\"detail\":\""); sb_puts(&s,d); sb_puts(&s,"\"},");
    }
    /* revoked releases */
    { PGresult *r=db_query("SELECT COUNT(*) FROM examos_software_releases WHERE status IN ('ROLLED_BACK','REVOKED')",0,NULL);
      long c=0; if(r&&PQresultStatus(r)==PGRES_TUPLES_OK&&PQntuples(r)==1)c=atol(PQgetvalue(r,0,0)); if(r)PQclear(r);
      char d[80]; snprintf(d,sizeof(d),"%ld revoked/rolled-back",c);
      sb_puts(&s,"{\"key\":\"releases\",\"label\":\"Revoked releases\",\"status\":\""); sb_puts(&s,c?"WARN":"PASS");
      sb_puts(&s,"\",\"detail\":\""); sb_puts(&s,d); sb_puts(&s,"\"},");
    }
    /* devices */
    { const char *pi=inst?inst:""; PGresult *r=inst?db_query("SELECT COUNT(*) FROM console_records WHERE collection='devices' AND ($1='' OR institution_id=$1)",1,&pi)
        : db_query("SELECT COUNT(*) FROM console_records WHERE collection='devices'",0,NULL);
      long c=0; if(r&&PQresultStatus(r)==PGRES_TUPLES_OK&&PQntuples(r)==1)c=atol(PQgetvalue(r,0,0)); if(r)PQclear(r);
      char d[80]; snprintf(d,sizeof(d),"%ld registered device record(s)",c);
      sb_puts(&s,"{\"key\":\"devices\",\"label\":\"Device telemetry\",\"status\":\""); sb_puts(&s,c?"PASS":"WARN");
      sb_puts(&s,"\",\"detail\":\""); sb_puts(&s,d); sb_puts(&s,"\"},");
    }
    /* attestation failures */
    { const char *pi=inst?inst:""; PGresult *r=inst?db_query("SELECT COUNT(*) FROM console_records WHERE collection='attestations' AND ($1='' OR institution_id=$1) AND data->>'result'='failed'",1,&pi)
        : db_query("SELECT COUNT(*) FROM console_records WHERE collection='attestations' AND data->>'result'='failed'",0,NULL);
      long c=0; if(r&&PQresultStatus(r)==PGRES_TUPLES_OK&&PQntuples(r)==1)c=atol(PQgetvalue(r,0,0)); if(r)PQclear(r);
      char d[80]; snprintf(d,sizeof(d),"%ld recent failure(s)",c);
      sb_puts(&s,"{\"key\":\"attestation\",\"label\":\"Attestation failures\",\"status\":\""); sb_puts(&s,c?"WARN":"PASS");
      sb_puts(&s,"\",\"detail\":\""); sb_puts(&s,d); sb_puts(&s,"\"}");
    }
    sb_puts(&s,"],\"database\":"); sb_puts(&s,db_ok?"true":"false");
    sb_puts(&s,",\"generated\":"); char ts[24]; snprintf(ts,sizeof(ts),"%ld",now_ms()); sb_puts(&s,ts);
    sb_puts(&s,",\"read_only\":true");
    sb_puts(&s,",\"note\":\"Checks execute live against PostgreSQL on request; no historical uptime is implied.\"}");
    support_send(fd,200,s.data,origin,extra,extra_len); sb_free(&s);
}

/* GET /status — service status counts from real records; uptime honestly unavailable. */
static void support_status_page(int fd, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    const char *inst=(sess->role==ROLE_PLATFORM_OWNER)?NULL:sess->institution_id;
    const char *pi=inst?inst:"";
    PGresult *r=inst?db_query("SELECT COUNT(*), COUNT(*) FILTER (WHERE data->>'status'='down'), COUNT(*) FILTER (WHERE data->>'status'='degraded') FROM console_records WHERE collection='services' AND ($1='' OR institution_id=$1)",1,&pi)
        : db_query("SELECT COUNT(*), COUNT(*) FILTER (WHERE data->>'status'='down'), COUNT(*) FILTER (WHERE data->>'status'='degraded') FROM console_records WHERE collection='services'",0,NULL);
    if (!r||PQresultStatus(r)!=PGRES_TUPLES_OK||PQntuples(r)!=1) { if(r)PQclear(r); support_error(fd,500,"Status unavailable",origin,extra,extra_len); return; }
    int total=atoi(PQgetvalue(r,0,0)), down=atoi(PQgetvalue(r,0,1)), degraded=atoi(PQgetvalue(r,0,2));
    PQclear(r);
    int db_ok=(db_health()==0);
    const char *overall=down>0?"outage":((degraded>0||!db_ok)?"degraded":"operational");
    sbuf s; if(sb_init(&s,512)!=0){ support_error(fd,500,"Out of memory",origin,extra,extra_len); return; }
    sb_puts(&s,"{\"overall\":"); sb_json_string(&s,overall); sb_putc(&s,',');
    { char n[16]; snprintf(n,sizeof(n),"%d",total); sb_puts(&s,"\"services\":"); sb_puts(&s,n); sb_putc(&s,','); }
    { char n[16]; snprintf(n,sizeof(n),"%d",down); sb_puts(&s,"\"down\":"); sb_puts(&s,n); sb_putc(&s,','); }
    { char n[16]; snprintf(n,sizeof(n),"%d",degraded); sb_puts(&s,"\"degraded\":"); sb_puts(&s,n); sb_putc(&s,','); }
    sb_puts(&s,"\"database\":"); sb_puts(&s,db_ok?"\"operational\"":"\"unavailable\""); sb_putc(&s,',');
    sb_puts(&s,"\"uptime\":\"insufficient-data\",\"alerts\":0,\"lastBackup\":null,\"regions\":[],");
    sb_puts(&s,"\"note\":\"Uptime requires monitoring history which is not configured; status reflects current service records and a live database health check only.\"}");
    support_send(fd,200,s.data,origin,extra,extra_len); sb_free(&s);
}

/* POST /recovery — create recovery case + centralized approval request. */
static void support_create_recovery(int fd, const char *body, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    if (!support_can_request_recovery(sess->role)) { support_error(fd,403,"Recovery may only be requested by institution administrators",origin,extra,extra_len); return; }
    if (!body||body[0]!='{') { support_error(fd,400,"A JSON body is required",origin,extra,extra_len); return; }
    char kind[25]={0}, target[81]={0}, reason[301]={0};
    ctrl_json_string(body,"kind",kind,sizeof(kind)); ctrl_json_string(body,"target",target,sizeof(target)); ctrl_json_string(body,"reason",reason,sizeof(reason));
    const char *vk[]={"account-access","device-trust","usb-custody","exam-session","data-restore"};
    int kind_ok=0; for(size_t i=0;i<sizeof(vk)/sizeof(vk[0]);i++) if(!strcmp(kind,vk[i])) kind_ok=1;
    if (!kind_ok) { support_error(fd,400,"Invalid recovery kind",origin,extra,extra_len); return; }
    if (strlen(target)<1) { support_error(fd,400,"A target is required",origin,extra,extra_len); return; }
    if (strlen(reason)<10) { support_error(fd,400,"A reason of 10+ characters is required",origin,extra,extra_len); return; }
    char institution[65]={0}; int sc=resolve_scope(sess,body,institution,sizeof(institution));
    if (sc!=0) { support_error(fd,403,"Recovery scope not allowed for this account",origin,extra,extra_len); return; }
    PGresult *pr=db_query("SELECT version, required_approvals, risk_level FROM approval_policies WHERE policy_key='support-recovery' AND active=TRUE LIMIT 1",0,NULL);
    if (!pr||PQresultStatus(pr)!=PGRES_TUPLES_OK||PQntuples(pr)!=1) { if(pr)PQclear(pr); support_error(fd,500,"Recovery approval policy is not configured",origin,extra,extra_len); return; }
    int policy_version=atoi(PQgetvalue(pr,0,0)), required_approvals=atoi(PQgetvalue(pr,0,1));
    PQclear(pr);
    char req_id[64], rec_id[64], apv_id[64];
    if (support_gen_id(req_id,sizeof(req_id),"sup_")!=0||support_gen_id(rec_id,sizeof(rec_id),"src_")!=0||support_gen_id(apv_id,sizeof(apv_id),"apr_")!=0)
        { support_error(fd,500,"Id generation failed",origin,extra,extra_len); return; }
    const char *category=!strcmp(kind,"account-access")?"access":(!strcmp(kind,"data-restore")?"data":"device");
    const char *priority=!strcmp(kind,"exam-session")?"critical":"high";
    char subject[200]; snprintf(subject,sizeof(subject),"Recovery · %s · %s",kind,target);
    char desc[500]; snprintf(desc,sizeof(desc),"Recovery requested for %s. Reason: %s",target,reason);
    PGconn *conn=db_acquire(); if(!conn){support_error(fd,503,"Database unavailable",origin,extra,extra_len);return;}
    if(!PQexec(conn,"BEGIN")){db_release(conn,1);support_error(fd,500,"Transaction error",origin,extra,extra_len);return;}
    PGresult *seq=PQexec(conn,"SELECT 'SUP-' || nextval('support_ticket_seq')");
    if (!seq||PQresultStatus(seq)!=PGRES_TUPLES_OK||PQntuples(seq)!=1) { if(seq)PQclear(seq); PQexec(conn,"ROLLBACK"); db_release(conn,1); support_error(fd,500,"Sequence failed",origin,extra,extra_len); return; }
    char ticket_no[32]; snprintf(ticket_no,sizeof(ticket_no),"%s",PQgetvalue(seq,0,0)); PQclear(seq);
    long created=now_ms(); long sla_due=created+(long)support_sla_hours(priority)*3600L*1000L;
    char sla_text[24], created_text[24]; snprintf(sla_text,sizeof(sla_text),"%ld",sla_due); snprintf(created_text,sizeof(created_text),"%ld",created);
    const char *rp[11]={req_id,ticket_no,institution,subject,desc,category,priority,sess->user_id,sess->username,sla_text,created_text};
    int rl[11]; for(int i=0;i<11;i++)rl[i]=(int)strlen(rp[i]);
    PGresult *ri=db_simple(conn,"INSERT INTO support_requests (id,ticket_no,institution_id,subject,description,category,priority,status,requester_id,requester_name,sla_due_at,created_at,updated_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,'new',$8,$9,$10,$11,$11)",11,rp,rl);
    int ok=ri&&PQresultStatus(ri)==PGRES_COMMAND_OK; if(ri)PQclear(ri);
    if(!ok){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,500,"Could not create recovery request",origin,extra,extra_len);return;}
    record_event(conn,req_id,sess,"SUPPORT_REQUEST_CREATED",ticket_no);
    record_event(conn,req_id,sess,"RECOVERY_REQUESTED",kind);
    const char *cvp[7]={rec_id,req_id,institution,kind,target,sess->user_id,reason};
    int cvl[7]; for(int i=0;i<7;i++)cvl[i]=(int)strlen(cvp[i]);
    PGresult *cvi=db_simple(conn,"INSERT INTO support_recoveries (id,request_id,institution_id,kind,target,requested_by,reason,state,created_at,updated_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,'pending-approval',(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000,(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000)",7,cvp,cvl);
    ok=cvi&&PQresultStatus(cvi)==PGRES_COMMAND_OK; if(cvi)PQclear(cvi);
    if(!ok){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,500,"Could not create recovery record",origin,extra,extra_len);return;}
    char label[200]; snprintf(label,sizeof(label),"Recovery · %s · %s",kind,target);
    char pv_text[8], ra_text[8]; snprintf(pv_text,sizeof(pv_text),"%d",policy_version); snprintf(ra_text,sizeof(ra_text),"%d",required_approvals);
    const char *ap[11]={apv_id,"support-recovery",pv_text,"support-recovery",rec_id,institution,label,reason,sess->user_id,sess->username,security_role_to_string(sess->role)};
    int al[11]; for(int i=0;i<11;i++)al[i]=(int)strlen(ap[i]);
    PGresult *ai=db_simple(conn,"INSERT INTO approval_requests (id,policy_key,policy_version,resource_type,resource_id,institution_id,label,reason,proposed_data,requester_id,requester_name,requester_role,risk_level,status,conflict_status,required_approvals,execution_status,created_at,updated_at,expires_at) "
        "VALUES ($1,$2,$3::integer,$4,$5,NULLIF($6,''),$7,$8,'{}'::jsonb,$9,$10,$11,$12,'pending_review','CLEAR',$13::smallint,'not_started',"
        "(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000,(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000,((EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)+2592000)*1000)",11,ap,al);
    int apv_ok=ai&&PQresultStatus(ai)==PGRES_COMMAND_OK; if(ai)PQclear(ai);
    if(!apv_ok){PQexec(conn,"ROLLBACK");db_release(conn,1);support_error(fd,409,"A recovery approval for this target is already open or could not be created",origin,extra,extra_len);return;}
    const char *lp[2]={apv_id,rec_id}; int ll[2]={(int)strlen(lp[0]),(int)strlen(lp[1])};
    PGresult *lu=db_simple(conn,"UPDATE support_recoveries SET approval_request_id=$1, updated_at=(EXTRACT(EPOCH FROM clock_timestamp())::BIGINT)*1000 WHERE id=$2",2,lp,ll);
    if(lu)PQclear(lu);
    if(!PQexec(conn,"COMMIT")){db_release(conn,1);support_error(fd,500,"Commit failed",origin,extra,extra_len);return;}
    db_release(conn,0); audit_append(sess->user_id,"RECOVERY_REQUESTED",label);
    sbuf s; if(sb_init(&s,256)==0){ sb_puts(&s,"{\"status\":\"opened\",\"requestId\":"); sb_json_string(&s,req_id); sb_puts(&s,",\"ticketNo\":"); sb_json_string(&s,ticket_no);
        sb_puts(&s,",\"approvalId\":"); sb_json_string(&s,apv_id); sb_puts(&s,",\"state\":\"pending-approval\"}");
        support_send(fd,201,s.data,origin,extra,extra_len); sb_free(&s);
    } else support_send(fd,201,"{\"status\":\"opened\"}",origin,extra,extra_len);
}

/* GET /recovery — list recovery cases with live approval state. */
static void support_list_recovery(int fd, const char *origin, char *extra, size_t extra_len, const auth_session_t *sess) {
    char sql[600];
    PGresult *res;
    if (sess->role==ROLE_PLATFORM_OWNER) {
        snprintf(sql,sizeof(sql),"SELECT r.id, r.ticket_no, r.institution_id, r.subject, r.status, r.created_at, "
            "v.kind, v.target, v.state, v.approval_request_id, a.status AS approval_status "
            "FROM support_recoveries v JOIN support_requests r ON r.id=v.request_id "
            "LEFT JOIN approval_requests a ON a.id=v.approval_request_id "
            "ORDER BY r.created_at DESC LIMIT 500");
        res=db_query(sql,0,NULL);
    } else {
        const char *p[1]={sess->institution_id};
        snprintf(sql,sizeof(sql),"SELECT r.id, r.ticket_no, r.institution_id, r.subject, r.status, r.created_at, "
            "v.kind, v.target, v.state, v.approval_request_id, a.status AS approval_status "
            "FROM support_recoveries v JOIN support_requests r ON r.id=v.request_id "
            "LEFT JOIN approval_requests a ON a.id=v.approval_request_id "
            "WHERE r.institution_id=$1 ORDER BY r.created_at DESC LIMIT 500");
        res=db_query(sql,1,p);
    }
    if (!res||PQresultStatus(res)!=PGRES_TUPLES_OK) { if(res)PQclear(res); support_error(fd,500,"Database read failed",origin,extra,extra_len); return; }
    sbuf s; if(sb_init(&s,8192)!=0){PQclear(res);support_error(fd,500,"Out of memory",origin,extra,extra_len);return;}
    sb_putc(&s,'[');
    for (int i=0;i<PQntuples(res);i++) {
        if(i)sb_putc(&s,','); sb_putc(&s,'{');
        sb_fstr(&s,"id",PQgetvalue(res,i,0)); sb_putc(&s,','); sb_fstr(&s,"no",PQgetvalue(res,i,1)); sb_putc(&s,',');
        sb_fstr(&s,"tenantId",PQgetvalue(res,i,2)); sb_putc(&s,','); sb_fstr(&s,"subject",PQgetvalue(res,i,3)); sb_putc(&s,',');
        sb_fstr(&s,"status",PQgetvalue(res,i,4)); sb_putc(&s,','); sb_fnum(&s,"createdAt",PQgetvalue(res,i,5)); sb_putc(&s,',');
        sb_puts(&s,"\"recovery\":{"); sb_fstr(&s,"kind",PQgetvalue(res,i,6)); sb_putc(&s,','); sb_fstr(&s,"target",PQgetvalue(res,i,7)); sb_putc(&s,',');
        { const char *st=PQgetvalue(res,i,10); const char *live=PQgetisnull(res,i,10)?PQgetvalue(res,i,8):
            (!strcmp(st,"approved")||!strcmp(st,"execution_pending")||!strcmp(st,"executing")?"approved":
             !strcmp(st,"rejected")||!strcmp(st,"blocked")?"rejected":
             !strcmp(st,"completed")?"completed":!strcmp(st,"withdrawn")?"withdrawn":"pending-approval");
          sb_fstr(&s,"state",live); } sb_putc(&s,',');
        append_null_or_str(&s,"approvalId",res,i,9); sb_puts(&s,"}}");
    }
    sb_putc(&s,']'); PQclear(res);
    support_send(fd,200,s.data,origin,extra,extra_len); sb_free(&s);
}

/* ------------------------------------------------------------------ dispatch */
void support_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) { support_error(client_fd,401,"Admin credentials required",origin,extra_headers,extra_len); return; }
    if (strcmp(method,"GET")==0 && strcmp(path,"/api/v1/support/stats")==0) { support_stats(client_fd,origin,extra_headers,extra_len,&sess); return; }
    if (strcmp(method,"GET")==0 && strcmp(path,"/api/v1/support/diagnostics")==0) { support_diagnostics(client_fd,origin,extra_headers,extra_len,&sess); return; }
    if (strcmp(method,"GET")==0 && strcmp(path,"/api/v1/support/status")==0) { support_status_page(client_fd,origin,extra_headers,extra_len,&sess); return; }
    if (strcmp(path,"/api/v1/support/recovery")==0) {
        if (strcmp(method,"GET")==0) { support_list_recovery(client_fd,origin,extra_headers,extra_len,&sess); return; }
        if (strcmp(method,"POST")==0) { support_create_recovery(client_fd,body,origin,extra_headers,extra_len,&sess); return; }
        support_error(client_fd,405,"Method not allowed",origin,extra_headers,extra_len); return;
    }
    if (strcmp(path,"/api/v1/support/requests")==0) {
        if (strcmp(method,"GET")==0) { support_list(client_fd,origin,extra_headers,extra_len,&sess); return; }
        if (strcmp(method,"POST")==0) { support_create(client_fd,body,origin,extra_headers,extra_len,&sess); return; }
        support_error(client_fd,405,"Method not allowed",origin,extra_headers,extra_len); return;
    }
    char req_id[65]={0}, action[33]={0};
    if (parse_request_action(path,req_id,sizeof(req_id),action,sizeof(action))) {
        if (action[0]=='\0') {
            if (strcmp(method,"GET")==0) { support_detail(client_fd,req_id,origin,extra_headers,extra_len,&sess); return; }
            support_error(client_fd,405,"Method not allowed",origin,extra_headers,extra_len); return;
        }
        if (strcmp(method,"POST")!=0) { support_error(client_fd,405,"Method not allowed",origin,extra_headers,extra_len); return; }
        if (strcmp(action,"comments")==0) { support_comment(client_fd,req_id,body,origin,extra_headers,extra_len,&sess); return; }
        if (strcmp(action,"assign")==0) { support_assign(client_fd,req_id,body,origin,extra_headers,extra_len,&sess); return; }
        if (strcmp(action,"status")==0) { support_status(client_fd,req_id,body,origin,extra_headers,extra_len,&sess); return; }
        if (strcmp(action,"escalate")==0) { support_escalate(client_fd,req_id,body,origin,extra_headers,extra_len,&sess); return; }
        if (strcmp(action,"rate")==0) { support_rate(client_fd,req_id,body,origin,extra_headers,extra_len,&sess); return; }
    }
    support_error(client_fd,404,"Not found",origin,extra_headers,extra_len);
}
