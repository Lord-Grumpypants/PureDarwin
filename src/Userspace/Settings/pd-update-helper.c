#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
#define CACHE "/Library/UpdateCache"
#define KEY "/System/Library/PrivateFrameworks/PDUpdate.framework/Resources/update-ed25519.pub"
#define BASE "https://lord-grumpypants.github.io/PureDarwin/updates/x86_64/"

static int fetch(const char *name, const char *tmp)
{
    char url[512];
    if (snprintf(url,sizeof(url),"%s%s",BASE,name)>=(int)sizeof(url)) return -1;
    char *const av[]={"/usr/bin/curl","--fail","--location","--silent","--show-error",
        "--connect-timeout","15","--max-time","1800","--output",(char *)tmp,url,NULL};
    pid_t pid; int status;
    if(posix_spawn(&pid,av[0],NULL,NULL,av,environ)!=0)return -1;
    while(waitpid(pid,&status,0)<0)if(errno!=EINTR)return -1;
    return WIFEXITED(status)&&WEXITSTATUS(status)==0?0:-1;
}
static int load(const char *p,unsigned char **b,size_t *n)
{
    int fd=open(p,O_RDONLY|O_NOFOLLOW);if(fd<0)return -1;
    struct stat st;if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<1||st.st_size>4096){close(fd);return -1;}
    *n=(size_t)st.st_size;*b=malloc(*n);if(!*b){close(fd);return -1;}
    size_t d=0;while(d<*n){ssize_t r=read(fd,*b+d,*n-d);if(r<0&&errno==EINTR)continue;if(r<=0){free(*b);close(fd);return -1;}d+=(size_t)r;}close(fd);return 0;
}
static int signature_ok(const char *manifest,const char *signature)
{
    unsigned char *m=NULL,*s=NULL;size_t ml=0,sl=0;
    if(load(manifest,&m,&ml)||load(signature,&s,&sl)||sl!=64){free(m);free(s);return 0;}
    FILE *fp=fopen(KEY,"rb");EVP_PKEY *key=fp?PEM_read_PUBKEY(fp,NULL,NULL,NULL):NULL;if(fp)fclose(fp);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    int ok=key&&EVP_PKEY_id(key)==EVP_PKEY_ED25519&&ctx&&EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1&&EVP_DigestVerify(ctx,s,sl,m,ml)==1;
    EVP_MD_CTX_free(ctx);EVP_PKEY_free(key);free(m);free(s);return ok;
}
static int version(const char *path,char *out,size_t cap)
{
    FILE *fp=fopen(path,"r");if(!fp)return -1;
    char line[256];int found=0;
    if(!fgets(line,sizeof(line),fp)||strcmp(line,"PDUPDATE1\n")){fclose(fp);return -1;}
    while(fgets(line,sizeof(line),fp))if(!strncmp(line,"version=",8)){
        size_t n=strcspn(line+8,"\r\n");if(!n||n>=cap){fclose(fp);return -1;}
        memcpy(out,line+8,n);out[n]=0;found=1;break;
    }
    fclose(fp);return found?0:-1;
}
static int sync_path(const char *path)
{
    int fd=open(path,O_RDONLY|O_NOFOLLOW);
    if(fd<0)return -1;
    int rc=fsync(fd);
    if(close(fd))rc=-1;
    return rc;
}
static int sync_cache(void)
{
    int fd=open(CACHE,O_RDONLY);
    if(fd<0)return -1;
    int rc=fsync(fd);
    if(close(fd))rc=-1;
    return rc;
}
static int secure_cache(void)
{
    struct stat st;
    if(lstat(CACHE,&st)){
        if(errno!=ENOENT||mkdir(CACHE,0700)||lstat(CACHE,&st))return -1;
    }
    return S_ISDIR(st.st_mode)&&!S_ISLNK(st.st_mode)&&st.st_uid==0?0:-1;
}
int main(int argc,char **argv)
{
    umask(077);
    if(geteuid()!=0||argc!=2|| (strcmp(argv[1],"check")&&strcmp(argv[1],"install"))){
        fprintf(stderr,"pd-update-helper: privileged helper; usage: check|install\n");return 2;
    }
    if(secure_cache()){fprintf(stderr,"pd-update-helper: update cache is not root-owned\n");return 1;}
    if(!strcmp(argv[1],"install")){
        struct statfs fs;
        if(statfs("/",&fs)==0 && !strcmp(fs.f_fstypename,"apfs")){
            fprintf(stderr,"pd-update-helper: installation is disabled on APFS roots\n");
            return 1;
        }
    }
    const char *mt=CACHE "/.manifest.download",*st=CACHE "/.manifest.sig.download";
    unlink(mt);unlink(st);
    if(fetch("manifest",mt)||fetch("manifest.sig",st)||!signature_ok(mt,st)){
        unlink(mt);unlink(st);fprintf(stderr,"pd-update-helper: no valid signed update is available\n");return 1;
    }
    char ver[128];
    if(version(mt,ver,sizeof(ver))){unlink(mt);unlink(st);return 1;}
    if(!strcmp(argv[1],"check")){
        printf("Available update: %s\n",ver);unlink(mt);unlink(st);return 0;
    }
    const char *at=CACHE "/.update.download";
    unlink(at);
    if(fetch("update.tar.xz",at)){unlink(mt);unlink(st);unlink(at);fprintf(stderr,"pd-update-helper: update download failed\n");return 1;}
    if(sync_path(mt)||sync_path(st)||sync_path(at)||rename(mt,CACHE "/manifest")||rename(st,CACHE "/manifest.sig")||rename(at,CACHE "/update.tar.xz")||sync_cache()){
        unlink(mt);unlink(st);unlink(at);fprintf(stderr,"pd-update-helper: cannot stage downloaded update\n");return 1;
    }
    int fd=open(CACHE "/.pending.tmp",O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,0600);
    if(fd<0)return 1;
    dprintf(fd,"%s\n",ver);
    int failed = fsync(fd);
    if(close(fd))failed = 1;
    if(failed || rename(CACHE "/.pending.tmp",CACHE "/pending") || sync_cache())return 1;
    (void)chmod(CACHE,0700);
    printf("Update %s downloaded; it will be installed on the next reboot.\n",ver);
    return 0;
}
