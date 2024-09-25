
enum ndef_flags {
    NDEF_FLAG_MB   = 0x80,
    NDEF_FLAG_ME   = 0x40,
    NDEF_FLAG_CF   = 0x20,
    NDEF_FLAG_SR   = 0x10,
    NDEF_FLAG_IL   = 0x08,
    NDEF_FLAGS_TNF = 0x07,
};

enum ndef_tnf {
    NDEF_TNF_EMPTY = 0,
    NDEF_TNF_WELLKNOWN = 1,
    NDEF_TNF_MEDIATYPE = 2,
    NDEF_TNF_URI = 3,
    NDEF_TNF_EXTERNAL = 4,
    NDEF_TNF_UNKNOWN = 5,
    NDEF_TNF_UNCHANGED = 6,
};

#define NDEF_WKT_U "U"
#define NDEF_WKT_T "T"


typedef int (*ndef_record_cb) (ndef_tnf_t tnf,
			       const char *type, size_t typelen,
			       const char *id, size_t idlen,
			       const char *payload, size_t payloadlen,
			       void *cookie);

#pragma pack (push)
#pragma pack (1)
struct ndef_header {
    uint8_t  ndef_flags;
    uint8_t  ndef_type_length;
    uint32_t ndef_payload_length;
    uint8_t  ndef_id_length;
};
#pragma pack (pop)

struct ndef_generator {
    size_t  gen_maxlen;
    char   *gen_buf;
    size_t  gen_len;
};


struct ndef_processor {
    ndef_record_cb  prc_callback;
    void           *prc_cookie;
    size_t          prc_numrec;
    ndef_header_t   prc_prevhdr;
    const char     *prc_type_buf;
    size_t          prc_type_len;
    const char     *prc_id_ptr;
    size_t          prc_id_buf;
    uint8_t        *prc_payload_buf;
    size_t          prc_payload_len;
};

int ndef_generator_begin(ndef_generator_t *gen, char *buf, size_t len)
{
}
int ndef_generator_feed(ndef_processor_t *gen)
{
}
int ndef_generator_finish(ndef_generator_t *gen)
{
}
int ndef_generator_reset(ndef_processor_t *prc)
{
}

int ndef_processor_begin(ndef_processor_t *prc, ndef_record_cb callback, void *cookie)
{
    /* Reset, ignoring errors */
    ndef_processor_reset(prc);
    /* Set the callback */
    prc->prc_callback = callback;
    prc->prc_cookie = cookie;
    /* Done */
    return 0;
}
int ndef_processor_feed(ndef_processor_t *prc, bool last, const char *buf, size_t len)
{
    size_t hdrlen;
    ndef_flags_t flags;
    uint8_t tlen;
    uint8_t ilen;
    uint32_t plen;
    ndef_tnf_t tnf;
    off_t off = 0;
    size_t rem = len;

    /* Get flags */
    if(rem < 1) {
	return -1;
    }
    flags = buf[off++];
    rem--;
    /* Get type length */
    if(rem < 1) {
	return -1;
    }
    tlen = cur[off++];
    rem--;
    /* Get payload length */
    if(flags & NDEF_FLAGS_SR) {
	if(rem < 1) {
	    return -1;
	}
	plen = cur[off++];
	rem--;
    } else {
	if(rem < 4) {
	    return -1;
	}
	plen = ntoh(*((uint32_t*)(buf + off)));
	cur += 4;
	rem -= 4;
    }
    /* Get ID length */
    if(flags & NDEF_FLAGS_IL) {
	if(rem < 1) {
	    return -1;
	}
	ilen = cur[off++];
	rem--;
    } else {
	ilen = 0;
    }
    /* Extract TNF */
    tnf = flags & NDEF_FLAGS_TNF;
    /* Check begin flag */
    if(flags & NDEF_FLAG_MB && prc.prc_numrec) {
	return -1;
    }
    /* Check end flag */
    if(flags & NDEF_FLAG_ME && !last) {
	return -1;
    }
    /* Process as chunk or record */
    if(!prc.prc_type_buf) {
	/* Process as first/unchunked */
	if(flags & NDEF_FLAG_CF) {
	    /* this is a first chunk */
	} else {
	    /* unchunked record */
	}
    } else {
	/* Check TNF */
	if(tnf != NDEF_TNF_UNCHANGED) {
	    return -1;
	}
	/* Process as middle/last */
	if(flags & NDEF_FLAG_CF) {
	    /* this is a middle chunk */
	} else {
	    /* this is the last chunk */
	}
    }
}
int ndef_processor_reset(ndef_processor_t *prc)
{
    if(prc->prc_type_buf) {
	free(prc->prc_type_buf);
	prc->prc_type_buf = NULL;
	prc->prc_type_len = 0;
    }
    if(prc->prc_id_buf) {
	free(prc->prc_id_buf);
	prc->prc_id_buf = NULL;
	prc->prc_id_len = 0;
    }
    if(prc->prc_payload_buf) {
	free(prc->prc_payload_buf);
	prc->prc_payload_buf = NULL;
	prc->prc_payload_len = 0;
    }
}
