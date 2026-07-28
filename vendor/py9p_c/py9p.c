#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <u.h>
#include <libc.h>
#include <fcall.h>

#include "py9p.h"

static __thread char py9p_error[256] = "no error";
static unsigned char empty_payload[1];

const char *
py9p_lasterror(void)
{
    return py9p_error;
}

void
py9p_clear_error(void)
{
    snprintf(py9p_error, sizeof py9p_error, "no error");
}

static int
set_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(py9p_error, sizeof py9p_error, fmt, ap);
    va_end(ap);
    return -1;
}

static int
check_string(const char *s, const char *field)
{
    if(s == nil)
        return 0;
    if(strlen(s) > 0xFFFF)
        return set_error("%s is longer than the 9P 16-bit string limit", field);
    return 0;
}

static void
pyqid_to_qid(const Py9pQid *src, Qid *dst)
{
    dst->type = src->type;
    dst->vers = src->vers;
    dst->path = src->path;
}

static void
qid_to_pyqid(const Qid *src, Py9pQid *dst)
{
    dst->type = src->type;
    dst->vers = (uint32_t)src->vers;
    dst->path = src->path;
}

static int
validate_fcall(const Py9pFcall *src)
{
    int i;

    if(src == nil)
        return set_error("fcall is NULL");
    if(src->nwname > PY9P_MAXWELEM)
        return set_error("Twalk has too many path elements");
    if(src->nwqid > PY9P_MAXWELEM)
        return set_error("Rwalk has too many qids");
    if(src->count > 0 && src->data == nil &&
        (src->type == Twrite || src->type == Rread))
        return set_error("message data pointer is NULL");
    if(src->nstat > 0 && src->stat == nil &&
        (src->type == Twstat || src->type == Rstat))
        return set_error("message stat pointer is NULL");

    if(check_string(src->version, "version") < 0 ||
        check_string(src->ename, "ename") < 0 ||
        check_string(src->uname, "uname") < 0 ||
        check_string(src->aname, "aname") < 0 ||
        check_string(src->name, "name") < 0 ||
        check_string(src->extension, "extension") < 0)
        return -1;

    for(i = 0; i < src->nwname; i++)
        if(check_string(src->wname[i], "wname") < 0)
            return -1;

    return 0;
}

static void
pyfcall_to_fcall(const Py9pFcall *src, Fcall *dst)
{
    int i;

    memset(dst, 0, sizeof *dst);
    dst->type = src->type;
    dst->fid = src->fid;
    dst->tag = src->tag;
    dst->msize = src->msize;
    dst->version = (char*)src->version;
    dst->oldtag = src->oldtag;
    dst->ename = (char*)src->ename;
    pyqid_to_qid(&src->qid, &dst->qid);
    dst->iounit = src->iounit;
    pyqid_to_qid(&src->aqid, &dst->aqid);
    dst->afid = src->afid;
    dst->uname = (char*)src->uname;
    dst->aname = (char*)src->aname;
    dst->perm = src->perm;
    dst->name = (char*)src->name;
    dst->mode = src->mode;
    dst->newfid = src->newfid;
    dst->nwname = src->nwname;
    for(i = 0; i < src->nwname; i++)
        dst->wname[i] = (char*)src->wname[i];
    dst->nwqid = src->nwqid;
    for(i = 0; i < src->nwqid; i++)
        pyqid_to_qid(&src->wqid[i], &dst->wqid[i]);
    dst->offset = src->offset;
    dst->count = src->count;
    dst->data = src->data == nil ? (char*)empty_payload : (char*)src->data;
    dst->nstat = src->nstat;
    dst->stat = src->stat == nil ? empty_payload : (uchar*)src->stat;
    dst->unixfd = src->unixfd;
    dst->errornum = src->errornum;
    dst->uidnum = src->uidnum;
    dst->extension = (char*)src->extension;
}

static void
fcall_to_pyfcall(const Fcall *src, Py9pFcall *dst)
{
    int i;

    memset(dst, 0, sizeof *dst);
    dst->type = src->type;
    dst->fid = src->fid;
    dst->tag = src->tag;
    dst->msize = src->msize;
    dst->version = src->version;
    dst->oldtag = src->oldtag;
    dst->ename = src->ename;
    qid_to_pyqid(&src->qid, &dst->qid);
    dst->iounit = src->iounit;
    qid_to_pyqid(&src->aqid, &dst->aqid);
    dst->afid = src->afid;
    dst->uname = src->uname;
    dst->aname = src->aname;
    dst->perm = src->perm;
    dst->name = src->name;
    dst->mode = src->mode;
    dst->newfid = src->newfid;
    dst->nwname = src->nwname;
    for(i = 0; i < src->nwname && i < PY9P_MAXWELEM; i++)
        dst->wname[i] = src->wname[i];
    dst->nwqid = src->nwqid;
    for(i = 0; i < src->nwqid && i < PY9P_MAXWELEM; i++)
        qid_to_pyqid(&src->wqid[i], &dst->wqid[i]);
    dst->offset = src->offset;
    dst->count = src->count;
    dst->data = (const uint8_t*)src->data;
    dst->nstat = src->nstat;
    dst->stat = (const uint8_t*)src->stat;
    dst->unixfd = src->unixfd;
    dst->errornum = src->errornum;
    dst->uidnum = src->uidnum;
    dst->extension = src->extension;
}

int
py9p_size_fcall(const Py9pFcall *src, uint32_t *out_size)
{
    Fcall f;
    uint size;

    py9p_clear_error();
    if(out_size == nil)
        return set_error("out_size is NULL");
    if(validate_fcall(src) < 0)
        return -1;
    pyfcall_to_fcall(src, &f);
    size = sizeS2M(&f);
    if(size == 0)
        return set_error("invalid or unsupported 9P message type %u", src->type);
    *out_size = size;
    return 0;
}

int
py9p_encode_fcall(const Py9pFcall *src, uint8_t *buf, uint32_t cap, uint32_t *out_len)
{
    Fcall f;
    uint size;
    uint written;

    py9p_clear_error();
    if(buf == nil)
        return set_error("output buffer is NULL");
    if(out_len == nil)
        return set_error("out_len is NULL");
    if(validate_fcall(src) < 0)
        return -1;
    pyfcall_to_fcall(src, &f);
    size = sizeS2M(&f);
    if(size == 0)
        return set_error("invalid or unsupported 9P message type %u", src->type);
    if(size > cap)
        return set_error("output buffer too small");
    written = convS2M(&f, (uchar*)buf, cap);
    if(written != size)
        return set_error("plan9port convS2M failed");
    *out_len = written;
    return 0;
}

int
py9p_decode_fcall(
    const uint8_t *buf,
    uint32_t len,
    Py9pFcall *dst,
    uint8_t *scratch,
    uint32_t scratch_len
)
{
    Fcall f;
    uint decoded;

    py9p_clear_error();
    if(buf == nil)
        return set_error("input buffer is NULL");
    if(dst == nil)
        return set_error("destination fcall is NULL");
    if(scratch == nil)
        return set_error("scratch buffer is NULL");
    if(scratch_len < len)
        return set_error("scratch buffer too small");

    memcpy(scratch, buf, len);
    memset(&f, 0, sizeof f);
    decoded = convM2S((uchar*)scratch, len, &f);
    if(decoded != len)
        return set_error("plan9port convM2S rejected message");
    fcall_to_pyfcall(&f, dst);
    return 0;
}

static int
validate_dir(const Py9pDir *src)
{
    if(src == nil)
        return set_error("dir is NULL");
    if(check_string(src->name, "dir.name") < 0 ||
        check_string(src->uid, "dir.uid") < 0 ||
        check_string(src->gid, "dir.gid") < 0 ||
        check_string(src->muid, "dir.muid") < 0)
        return -1;
    return 0;
}

static void
pydir_to_dir(const Py9pDir *src, Dir *dst)
{
    memset(dst, 0, sizeof *dst);
    dst->type = src->type;
    dst->dev = src->dev;
    pyqid_to_qid(&src->qid, &dst->qid);
    dst->mode = src->mode;
    dst->atime = src->atime;
    dst->mtime = src->mtime;
    dst->length = src->length;
    dst->name = (char*)src->name;
    dst->uid = (char*)src->uid;
    dst->gid = (char*)src->gid;
    dst->muid = (char*)src->muid;
}

static void
dir_to_pydir(const Dir *src, Py9pDir *dst)
{
    memset(dst, 0, sizeof *dst);
    dst->type = src->type;
    dst->dev = src->dev;
    qid_to_pyqid(&src->qid, &dst->qid);
    dst->mode = (uint32_t)src->mode;
    dst->atime = (uint32_t)src->atime;
    dst->mtime = (uint32_t)src->mtime;
    dst->length = src->length;
    dst->name = src->name;
    dst->uid = src->uid;
    dst->gid = src->gid;
    dst->muid = src->muid;
}

int
py9p_size_dir(const Py9pDir *src, uint32_t *out_size)
{
    Dir d;
    uint size;

    py9p_clear_error();
    if(out_size == nil)
        return set_error("out_size is NULL");
    if(validate_dir(src) < 0)
        return -1;
    pydir_to_dir(src, &d);
    size = sizeD2M(&d);
    if(size > 0xFFFF)
        return set_error("dir stat is longer than the 9P nstat field");
    *out_size = size;
    return 0;
}

int
py9p_encode_dir(const Py9pDir *src, uint8_t *buf, uint32_t cap, uint32_t *out_len)
{
    Dir d;
    uint size;
    uint written;

    py9p_clear_error();
    if(buf == nil)
        return set_error("output buffer is NULL");
    if(out_len == nil)
        return set_error("out_len is NULL");
    if(validate_dir(src) < 0)
        return -1;
    pydir_to_dir(src, &d);
    size = sizeD2M(&d);
    if(size > 0xFFFF)
        return set_error("dir stat is longer than the 9P nstat field");
    if(size > cap)
        return set_error("output buffer too small");
    written = convD2M(&d, (uchar*)buf, cap);
    if(written != size)
        return set_error("plan9port convD2M failed");
    *out_len = written;
    return 0;
}

int
py9p_decode_dir(
    const uint8_t *buf,
    uint32_t len,
    Py9pDir *dst,
    uint8_t *scratch,
    uint32_t scratch_len,
    uint32_t *out_len
)
{
    Dir d;
    uint decoded;

    py9p_clear_error();
    if(buf == nil)
        return set_error("input buffer is NULL");
    if(dst == nil)
        return set_error("destination dir is NULL");
    if(scratch == nil)
        return set_error("scratch buffer is NULL");
    if(out_len == nil)
        return set_error("out_len is NULL");
    if(scratch_len < len + 4)
        return set_error("scratch buffer too small");
    if(statcheck((uchar*)buf, len) < 0)
        return set_error("plan9port statcheck rejected stat buffer");

    memset(&d, 0, sizeof d);
    decoded = convM2D((uchar*)buf, len, &d, (char*)scratch);
    if(decoded == 0)
        return set_error("plan9port convM2D rejected stat buffer");
    dir_to_pydir(&d, dst);
    *out_len = decoded;
    return 0;
}

int
py9p_statcheck(const uint8_t *buf, uint32_t len)
{
    py9p_clear_error();
    if(buf == nil)
        return set_error("input buffer is NULL");
    if(statcheck((uchar*)buf, len) < 0)
        return set_error("plan9port statcheck rejected stat buffer");
    return 0;
}
