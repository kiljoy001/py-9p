#ifndef PY9P_H
#define PY9P_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PY9P_MAXWELEM 16

typedef struct Py9pQid {
    uint8_t type;
    uint32_t vers;
    uint64_t path;
} Py9pQid;

typedef struct Py9pDir {
    uint16_t type;
    uint32_t dev;
    Py9pQid qid;
    uint32_t mode;
    uint32_t atime;
    uint32_t mtime;
    int64_t length;
    const char *name;
    const char *uid;
    const char *gid;
    const char *muid;
} Py9pDir;

typedef struct Py9pFcall {
    uint8_t type;
    uint16_t tag;
    uint32_t fid;
    uint32_t msize;
    const char *version;
    uint16_t oldtag;
    const char *ename;
    Py9pQid qid;
    uint32_t iounit;
    Py9pQid aqid;
    uint32_t afid;
    const char *uname;
    const char *aname;
    uint32_t perm;
    const char *name;
    uint8_t mode;
    uint32_t newfid;
    uint16_t nwname;
    const char *wname[PY9P_MAXWELEM];
    uint16_t nwqid;
    Py9pQid wqid[PY9P_MAXWELEM];
    int64_t offset;
    uint32_t count;
    const uint8_t *data;
    uint16_t nstat;
    const uint8_t *stat;
    int32_t unixfd;
    int32_t errornum;
    int32_t uidnum;
    const char *extension;
} Py9pFcall;

const char *py9p_lasterror(void);
void py9p_clear_error(void);

int py9p_size_fcall(const Py9pFcall *src, uint32_t *out_size);
int py9p_encode_fcall(
    const Py9pFcall *src,
    uint8_t *buf,
    uint32_t cap,
    uint32_t *out_len
);
int py9p_decode_fcall(
    const uint8_t *buf,
    uint32_t len,
    Py9pFcall *dst,
    uint8_t *scratch,
    uint32_t scratch_len
);

int py9p_size_dir(const Py9pDir *src, uint32_t *out_size);
int py9p_encode_dir(
    const Py9pDir *src,
    uint8_t *buf,
    uint32_t cap,
    uint32_t *out_len
);
int py9p_decode_dir(
    const uint8_t *buf,
    uint32_t len,
    Py9pDir *dst,
    uint8_t *scratch,
    uint32_t scratch_len,
    uint32_t *out_len
);
int py9p_statcheck(const uint8_t *buf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
