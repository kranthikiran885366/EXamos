#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int notify_ready(void) {
    const char *path = getenv("NOTIFY_SOCKET");
    if (!path || !path[0]) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t n = strlen(path);
    if (n >= sizeof(address.sun_path)) return -1;
    memcpy(address.sun_path, path, n+1);
    if (address.sun_path[0] == '@') address.sun_path[0] = '\0';
    socklen_t size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n +
        (path[0] == '@' ? 0 : 1));
    int fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0);
    if (fd<0) return -1;
    const char message[]="READY=1\nSTATUS=ExamOS ptrace and W+X policies attached";
    ssize_t sent=sendto(fd,message,sizeof(message)-1,MSG_NOSIGNAL,
                       (struct sockaddr *)&address,size);
    close(fd);
    return sent==(ssize_t)(sizeof(message)-1)?0:-1;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr,"usage: examos-bpf-lsm POLICY_OBJECT\n"); return 2; }
    struct stat metadata;
    if (lstat(argv[1],&metadata)!=0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid!=0 || (metadata.st_mode&0022)) {
        fprintf(stderr,"BPF policy must be a root-owned, non-writable regular file\n"); return 1;
    }
    sigset_t signals;
    sigemptyset(&signals); sigaddset(&signals,SIGTERM); sigaddset(&signals,SIGINT);
    if (sigprocmask(SIG_BLOCK,&signals,NULL)!=0) return 1;
    struct bpf_object *object=bpf_object__open_file(argv[1],NULL);
    if (!object || libbpf_get_error(object)) {
        fprintf(stderr,"Cannot open BPF-LSM object\n"); return 1;
    }
    struct bpf_link *links[2]={NULL,NULL};
    int status=1;
    if (bpf_object__load(object)!=0) goto done;
    /* Require the exact expected programs. A partial attach is never READY. */
    const char *names[2]={"examos_deny_ptrace","examos_deny_wx"};
    for (size_t i=0;i<2;i++) {
        struct bpf_program *program=bpf_object__find_program_by_name(object,names[i]);
        if (!program) goto done;
        links[i]=bpf_program__attach_lsm(program);
        if (!links[i] || libbpf_get_error(links[i])) { links[i]=NULL; goto done; }
    }
    if (notify_ready()!=0) { fprintf(stderr,"Cannot notify systemd of attached LSM policy\n"); goto done; }
    int received;
    status=sigwait(&signals,&received)==0?0:1;
done:
    /* The systemd BindsTo relationship stops the kiosk when this holder exits.
     * No pinned orphan policies or success markers survive a failed start. */
    for (size_t i=0;i<2;i++) if (links[i]) bpf_link__destroy(links[i]);
    bpf_object__close(object);
    return status;
}
