#include <errno.h>
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
#include <unistd.h>
#include <lzma.h>

#define CACHE       "/Library/UpdateCache"
#define MANIFEST    CACHE "/manifest"
#define SIGNATURE   CACHE "/manifest.sig"
#define ARCHIVE     CACHE "/update.tar.xz"
#define STAGING     CACHE "/staging"
#define JOURNAL     CACHE "/transaction"
#define TRUSTED_KEY "/System/Library/PrivateFrameworks/PDUpdate.framework/Resources/update-ed25519.pub"
#define MAX_MANIFEST 4096
#define MAX_ARCHIVE (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define MAX_PATH 1024

static void fail(const char *what)
{
    fprintf(stderr, "pd-update-installer: %s: %s\n", what, strerror(errno));
    _exit(1);
}

static int read_file(const char *path, unsigned char **out, size_t *length,
                     size_t maximum)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > maximum) {
        close(fd); errno = EINVAL; return -1;
    }
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
    close(fd);
    p[n] = 0;
    *out = p; *length = n;
    return 0;
}

static int parse_manifest(const unsigned char *p, size_t n,
                          char version[128], unsigned char digest[32],
                          uint64_t *archive_size)
{
    if (!n || n >= MAX_MANIFEST || memchr(p, 0, n)) return -1;
    char *copy = strndup((const char *)p, n);
    if (!copy) return -1;
    char *save = NULL;
    char *line = strtok_r(copy, "\n", &save);
    if (!line || strcmp(line, "PDUPDATE1")) { free(copy); return -1; }
    int have_version = 0, have_hash = 0, have_size = 0;
    while ((line = strtok_r(NULL, "\n", &save))) {
        if (!strncmp(line, "version=", 8) && !have_version) {
            size_t l = strlen(line + 8);
            if (!l || l >= 128) { free(copy); return -1; }
            memcpy(version, line + 8, l + 1); have_version = 1;
        } else if (!strncmp(line, "sha256=", 7) && !have_hash) {
            const char *h = line + 7;
            if (strlen(h) != 64) { free(copy); return -1; }
            for (int i = 0; i < 32; ++i) {
                unsigned int v;
                if (sscanf(h + i * 2, "%2x", &v) != 1) {
                    free(copy); return -1;
                }
                digest[i] = (unsigned char)v;
            }
            have_hash = 1;
        } else if (!strncmp(line, "size=", 5) && !have_size) {
            char *end = NULL;
            unsigned long long v = strtoull(line + 5, &end, 10);
            if (!end || *end || !v || v > MAX_ARCHIVE) {
                free(copy); return -1;
            }
            *archive_size = (uint64_t)v; have_size = 1;
        } else {
            free(copy); return -1;
        }
    }
    free(copy);
    return have_version && have_hash && have_size ? 0 : -1;
}

static int verify_signature(const unsigned char *manifest, size_t manifest_len,
                            const unsigned char *signature, size_t signature_len)
{
    if (signature_len != 64) return 0;
    FILE *key_file = fopen(TRUSTED_KEY, "rb");
    if (!key_file) return 0;
    EVP_PKEY *key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!key || EVP_PKEY_id(key) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(key); return 0;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestVerify(ctx, signature, signature_len,
                              manifest, manifest_len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static int verify_archive(const unsigned char expected[32], uint64_t expected_size)
{
    int fd = open(ARCHIVE, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        (uint64_t)st.st_size != expected_size) {
        close(fd); return 0;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); close(fd); return 0;
    }
    unsigned char buffer[65536], actual[EVP_MAX_MD_SIZE];
    unsigned int actual_len = 0;
    int ok = 1;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = 0; break; }
        if (!n) break;
        if (EVP_DigestUpdate(ctx, buffer, (size_t)n) != 1) { ok = 0; break; }
    }
    if (ok && (EVP_DigestFinal_ex(ctx, actual, &actual_len) != 1 ||
               actual_len != 32 || CRYPTO_memcmp(actual, expected, 32)))
        ok = 0;
    EVP_MD_CTX_free(ctx);
    close(fd);
    return ok;
}

/* Decode the complete XZ stream before any installed path is touched. */
static int validate_xz(void)
{
    int in = open(ARCHIVE, O_RDONLY | O_NOFOLLOW);
    if (in < 0) return 0;
    char temp[] = CACHE "/payload.XXXXXX";
    int out = mkstemp(temp);
    if (out < 0) { close(in); return 0; }
    (void)fchmod(out, 0600);

    lzma_stream strm = LZMA_STREAM_INIT;
    if (lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED) != LZMA_OK) {
        close(in); close(out); unlink(temp); return 0;
    }
    unsigned char ibuf[65536], obuf[65536];
    lzma_action action = LZMA_RUN;
    int ok = 1, eof = 0;
    for (;;) {
        if (strm.avail_in == 0 && !eof) {
            ssize_t n = read(in, ibuf, sizeof(ibuf));
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) { ok = 0; break; }
            if (!n) { eof = 1; action = LZMA_FINISH; }
            strm.next_in = ibuf; strm.avail_in = (size_t)n;
        }
        strm.next_out = obuf; strm.avail_out = sizeof(obuf);
        lzma_ret rc = lzma_code(&strm, action);
        size_t produced = sizeof(obuf) - strm.avail_out;
        size_t off = 0;
        while (off < produced) {
            ssize_t n = write(out, obuf + off, produced - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ok = 0; break; }
            off += (size_t)n;
        }
        if (!ok) break;
        if (rc == LZMA_STREAM_END) break;
        if (rc != LZMA_OK || (eof && !strm.avail_in && rc != LZMA_OK)) {
            ok = 0; break;
        }
    }
    lzma_end(&strm);
    close(in); close(out);
    if (!ok) unlink(temp);
    else if (rename(temp, CACHE "/verified-payload.tar") != 0) {
        unlink(temp); ok = 0;
    }
    return ok;
}

/*
 * This binary intentionally refuses to apply an archive until its transaction
 * journal and recovery path are present. Verification is safe to run repeatedly;
 * it never modifies the live system or removes the pending marker.
 */
int main(void)
{
    unsigned char *manifest = NULL, *signature = NULL;
    size_t manifest_len = 0, signature_len = 0;
    char version[128] = {0};
    unsigned char digest[32];
    uint64_t archive_size = 0;

    if (read_file(MANIFEST, &manifest, &manifest_len, MAX_MANIFEST))
        fail("cannot read manifest");
    if (read_file(SIGNATURE, &signature, &signature_len, 64))
        fail("cannot read signature");
    if (!verify_signature(manifest, manifest_len, signature, signature_len)) {
        fprintf(stderr, "pd-update-installer: manifest signature rejected\n");
        return 1;
    }
    if (parse_manifest(manifest, manifest_len, version, digest, &archive_size)) {
        fprintf(stderr, "pd-update-installer: malformed manifest\n");
        return 1;
    }
    free(manifest); free(signature);

    if (!verify_archive(digest, archive_size)) {
        fprintf(stderr, "pd-update-installer: archive hash/size mismatch\n");
        return 1;
    }
    if (!validate_xz()) {
        fprintf(stderr, "pd-update-installer: XZ stream validation failed\n");
        return 1;
    }

    fprintf(stderr,
        "pd-update-installer: verified update %s; installation is disabled "
        "until transaction recovery is configured\n", version);
    return 2;
}
