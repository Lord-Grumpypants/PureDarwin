#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <lzma.h>

#define CACHE "/Library/UpdateCache"
#define MANIFEST CACHE "/manifest"
#define SIGNATURE CACHE "/manifest.sig"
#define ARCHIVE CACHE "/update.tar.xz"
#define STAGING CACHE "/staging"
#define BACKUP CACHE "/rollback"
#define JOURNAL CACHE "/transaction"
#define TRUSTED_KEY "/System/Library/PrivateFrameworks/PDUpdate.framework/Resources/update-ed25519.pub"
#define MAX_MANIFEST 4096
#define MAX_ARCHIVE (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define MAX_OPS 16

static const char *roots[] = { "System", "usr", "bin", "sbin", "etc", "Applications" };

static void message(const char *s) { (void)write(2, s, strlen(s)); }
static int run(const char *path, char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (!pid) { execv(path, argv); _exit(127); }
    int status;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
static int exists(const char *p) { struct stat st; return lstat(p, &st) == 0; }
static int remove_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
        return unlink(path);
    DIR *dir = opendir(path);
    if (!dir) return -1;
    struct dirent *entry;
    int result = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        char child[PATH_MAX];
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int)sizeof(child) ||
            remove_tree(child) != 0) {
            result = -1;
            break;
        }
    }
    if (closedir(dir) != 0) result = -1;
    if (result == 0 && rmdir(path) != 0) result = -1;
    return result;
}
static int sync_dir(const char *p)
{
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    int r = fsync(fd); close(fd); return r;
}
static int read_file(const char *path, unsigned char **out, size_t *length, size_t maximum)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > maximum) { close(fd); errno = EINVAL; return -1; }
    size_t n = (size_t)st.st_size;
    unsigned char *p = malloc(n + 1);
    if (!p) { close(fd); return -1; }
    size_t done = 0;
    while (done < n) {
        ssize_t r = read(fd, p + done, n - done);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { free(p); close(fd); errno = EIO; return -1; }
        done += (size_t)r;
    }
    close(fd); p[n] = 0; *out = p; *length = n; return 0;
}
static int parse_manifest(const unsigned char *p, size_t n, unsigned char digest[32], uint64_t *size)
{
    if (!n || n >= MAX_MANIFEST || memchr(p, 0, n)) return -1;
    char *copy = strndup((const char *)p, n), *save = NULL;
    if (!copy) return -1;
    char *line = strtok_r(copy, "\n", &save);
    if (!line || strcmp(line, "PDUPDATE1")) { free(copy); return -1; }
    int hash = 0, bytes = 0, version = 0;
    while ((line = strtok_r(NULL, "\n", &save))) {
        if (!strncmp(line, "version=", 8) && !version && line[8]) version = 1;
        else if (!strncmp(line, "sha256=", 7) && !hash && strlen(line + 7) == 64) {
            for (int i=0;i<32;i++) { unsigned v; if (sscanf(line+7+i*2,"%2x",&v)!=1) { free(copy); return -1; } digest[i]=(unsigned char)v; }
            hash=1;
        } else if (!strncmp(line, "size=", 5) && !bytes) {
            char *end=NULL; unsigned long long v=strtoull(line+5,&end,10);
            if (!end || *end || !v || v>MAX_ARCHIVE) { free(copy); return -1; }
            *size=(uint64_t)v; bytes=1;
        } else { free(copy); return -1; }
    }
    free(copy); return hash && bytes && version ? 0 : -1;
}
static int verify_signature(const unsigned char *m,size_t ml,const unsigned char *s,size_t sl)
{
    if (sl!=64) return 0;
    FILE *fp=fopen(TRUSTED_KEY,"rb"); if(!fp) return 0;
    EVP_PKEY *key=PEM_read_PUBKEY(fp,NULL,NULL,NULL); fclose(fp);
    if(!key || EVP_PKEY_id(key)!=EVP_PKEY_ED25519) { EVP_PKEY_free(key); return 0; }
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    int ok=ctx && EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1 && EVP_DigestVerify(ctx,s,sl,m,ml)==1;
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); return ok;
}
static int verify_archive(const unsigned char expected[32],uint64_t size)
{
    int fd=open(ARCHIVE,O_RDONLY|O_NOFOLLOW); if(fd<0) return 0;
    struct stat st; if(fstat(fd,&st)||!S_ISREG(st.st_mode)||(uint64_t)st.st_size!=size){close(fd);return 0;}
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); if(!ctx||EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)!=1){EVP_MD_CTX_free(ctx);close(fd);return 0;}
    unsigned char b[65536],actual[EVP_MAX_MD_SIZE]; unsigned al=0; int ok=1;
    for(;;){ssize_t n=read(fd,b,sizeof(b));if(n<0&&errno==EINTR)continue;if(n<0){ok=0;break;}if(!n)break;if(EVP_DigestUpdate(ctx,b,(size_t)n)!=1){ok=0;break;}}
    if(ok&&(EVP_DigestFinal_ex(ctx,actual,&al)!=1||al!=32||CRYPTO_memcmp(actual,expected,32)))ok=0;
    EVP_MD_CTX_free(ctx);close(fd);return ok;
}
static int decompress_xz(void)
{
    int in=open(ARCHIVE,O_RDONLY|O_NOFOLLOW); if(in<0)return -1;
    char tmp[] = CACHE "/payload.tar.XXXXXX"; int out=mkstemp(tmp);
    if(out<0){close(in);return -1;} (void)fchmod(out,0600);
    lzma_stream z=LZMA_STREAM_INIT;
    if(lzma_stream_decoder(&z,UINT64_MAX,LZMA_CONCATENATED)!=LZMA_OK){close(in);close(out);unlink(tmp);return -1;}
    unsigned char ib[65536],ob[65536]; int eof=0,ok=1; lzma_action act=LZMA_RUN;
    for(;;){
        if(!z.avail_in&&!eof){ssize_t n=read(in,ib,sizeof(ib));if(n<0&&errno==EINTR)continue;if(n<0){ok=0;break;}if(!n){eof=1;act=LZMA_FINISH;}z.next_in=ib;z.avail_in=(size_t)n;}
        z.next_out=ob;z.avail_out=sizeof(ob);lzma_ret rc=lzma_code(&z,act);size_t n=sizeof(ob)-z.avail_out,off=0;
        while(off<n){ssize_t w=write(out,ob+off,n-off);if(w<0&&errno==EINTR)continue;if(w<=0){ok=0;break;}off+=(size_t)w;}
        if(!ok)break;if(rc==LZMA_STREAM_END)break;if(rc!=LZMA_OK){ok=0;break;}
    }
    lzma_end(&z);close(in);if(fsync(out))ok=0;close(out);
    if(!ok){unlink(tmp);return -1;} if(rename(tmp,CACHE "/verified.tar")){unlink(tmp);return -1;}return 0;
}
static int allowed_path(const char *p)
{
    if(!p||!*p||p[0]=='/'||strstr(p,"../")||!strcmp(p,"..")||strstr(p,"/..")||strstr(p,"//"))return 0;
    for(size_t i=0;i<sizeof(roots)/sizeof(roots[0]);i++){
        size_t n=strlen(roots[i]); if(!strncmp(p,roots[i],n)&&(p[n]==0||p[n]=='/'))return 1;
    }
    return 0;
}
/* Inspect archive names before extraction; only known system roots are accepted. */
static int check_tar_names(void)
{
    int fds[2];
    if (pipe(fds) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (pid == 0) {
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
        close(fds[1]);
        execl("/usr/bin/tar", "tar", "-tf", CACHE "/verified.tar", (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    FILE *fp = fdopen(fds[0], "r");
    if (!fp) { close(fds[0]); (void)waitpid(pid, NULL, 0); return -1; }
    char line[PATH_MAX + 2];
    int ok = 1, count = 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n') line[--n] = 0;
        if (!n || n >= PATH_MAX || !allowed_path(line)) { ok = 0; break; }
        if (++count > 200000) { ok = 0; break; }
    }
    if (ferror(fp)) ok = 0;
    fclose(fp);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
    return ok && WIFEXITED(status) && WEXITSTATUS(status) == 0 && count > 0 ? 0 : -1;
}
static int append_journal(char kind,const char *root)
{
    int fd=open(JOURNAL,O_WRONLY|O_CREAT|O_APPEND,0600);if(fd<0)return -1;
    char line[PATH_MAX+8];int n=snprintf(line,sizeof(line),"%c %s\n",kind,root);
    int ok=write(fd,line,(size_t)n)==n&&fsync(fd)==0;close(fd);return ok?0:-1;
}
static int rollback(void)
{
    FILE *fp=fopen(JOURNAL,"r");if(!fp)return errno==ENOENT?0:-1;
    char lines[MAX_OPS][PATH_MAX+8];int n=0;char line[PATH_MAX+8];
    while(fgets(line,sizeof(line),fp)){if(n==MAX_OPS){fclose(fp);return -1;}strlcpy(lines[n++],line,sizeof(lines[0]));}
    fclose(fp);
    /* A durable C record is the transaction commit point. */
    if(n && lines[n-1][0]=='C'){
        if(remove_tree(BACKUP)||remove_tree(STAGING))return -1;
        if(unlink(JOURNAL)&&errno!=ENOENT)return -1;
        (void)sync_dir(CACHE);return 0;
    }
    while(n--){
        char kind=lines[n][0],*name=lines[n]+2;name[strcspn(name,"\r\n")]=0;
        char live[PATH_MAX],saved[PATH_MAX];
        if(snprintf(live,sizeof(live),"/%s",name)>=(int)sizeof(live)||
           snprintf(saved,sizeof(saved),BACKUP "/%s",name)>=(int)sizeof(saved))return -1;
        if(kind=='E'){
            if(exists(saved)){if(remove_tree(live))return -1;if(rename(saved,live))return -1;}
        }else if(kind=='N'){if(remove_tree(live))return -1;}
    }
    if(remove_tree(BACKUP)||remove_tree(STAGING))return -1;
    if(unlink(JOURNAL)&&errno!=ENOENT)return -1;
    (void)sync_dir(CACHE);return 0;
}
static int apply_update(void)
{
    if(exists(JOURNAL)){message("pd-update-installer: recovering interrupted update\n");if(rollback())return -1;}
    if(remove_tree(STAGING)||remove_tree(BACKUP))return -1;
    if(mkdir(STAGING,0700)||mkdir(BACKUP,0700))return -1;
    char *const tarv[]={"/usr/bin/tar","-xf",CACHE "/verified.tar","-C",STAGING,NULL};
    if(run("/usr/bin/tar",tarv)!=0)return -1;
    int count=0;
    for(size_t i=0;i<sizeof(roots)/sizeof(roots[0]);i++){
        char staged[PATH_MAX],live[PATH_MAX],saved[PATH_MAX];
        snprintf(staged,sizeof(staged),STAGING "/%s",roots[i]);
        if(!exists(staged))continue;
        snprintf(live,sizeof(live),"/%s",roots[i]);
        snprintf(saved,sizeof(saved),BACKUP "/%s",roots[i]);
        int had=exists(live);
        if(append_journal(had?'E':'N',roots[i]))return -1;
        if(had&&rename(live,saved))return -1;
        if(rename(staged,live))return -1;
        (void)sync_dir("/");
        if(++count>MAX_OPS)return -1;
    }
    if(!count)return -1;
    if(append_journal('C',"committed"))return -1;
    if(remove_tree(BACKUP)||remove_tree(STAGING))return -1;
    if(unlink(JOURNAL))return -1;
    (void)sync_dir(CACHE);
    return 0;
}
static void boot_launchd(void)
{
    (void)unlink(CACHE "/pending");
    char *const av[]={"/sbin/launchd",NULL};execv(av[0],av);
    message("pd-update-installer: cannot start launchd after rollback\n");for(;;)pause();
}
int main(void)
{
    unsigned char *m=NULL,*s=NULL,digest[32];size_t ml=0,sl=0;uint64_t size=0;
    /* A stale journal is always rolled back before considering a new update. */
    if(exists(JOURNAL)&&rollback()){message("pd-update-installer: rollback failed; refusing startup\n");for(;;)pause();}
    if(read_file(MANIFEST,&m,&ml,MAX_MANIFEST)||read_file(SIGNATURE,&s,&sl,64)){message("pd-update-installer: missing update metadata\n");boot_launchd();}
    if(!verify_signature(m,ml,s,sl)||parse_manifest(m,ml,digest,&size)){free(m);free(s);message("pd-update-installer: signature or manifest rejected\n");boot_launchd();}
    free(m);free(s);
    if(!verify_archive(digest,size)||decompress_xz()||check_tar_names()){message("pd-update-installer: archive verification failed\n");boot_launchd();}
    if(apply_update()){
        message("pd-update-installer: installation failed; rolling back\n");
        if(rollback()){message("pd-update-installer: rollback failed; refusing startup\n");for(;;)pause();}
        (void)unlink(CACHE "/pending");boot_launchd();
    }
    (void)unlink(CACHE "/pending");
    (void)unlink(MANIFEST);(void)unlink(SIGNATURE);(void)unlink(ARCHIVE);(void)unlink(CACHE "/verified.tar");
    message("pd-update-installer: update applied; rebooting\n");
    char *const rv[]={"/sbin/reboot",NULL};execv(rv[0],rv);
    message("pd-update-installer: reboot command failed; starting launchd\n");boot_launchd();
}
