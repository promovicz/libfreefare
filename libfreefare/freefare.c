#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <freefare.h>

#include "freefare_internal.h"

const char *
freefare_version(void)
{
    return PACKAGE_VERSION;
}

const char *
freefare_strerror(FreefareTag tag)
{
    const char *p = "Unknown error";
    if (nfc_device_get_last_error(tag->device) < 0) {
	p = nfc_strerror(tag->device);
    } else {
	if (tag->type == MIFARE_DESFIRE) {
	    if (MIFARE_DESFIRE(tag)->last_pcd_error) {
		p = mifare_desfire_error_lookup(MIFARE_DESFIRE(tag)->last_pcd_error);
	    } else if (MIFARE_DESFIRE(tag)->last_picc_error) {
		p = mifare_desfire_error_lookup(MIFARE_DESFIRE(tag)->last_picc_error);
	    }
	} else if (tag->type == NTAG_21x) {
	    p = ntag21x_error_lookup(NTAG_21x(tag)->last_error);
	}
    }
    return p;
}

int
freefare_strerror_r(FreefareTag tag, char *buffer, size_t len)
{
    return (snprintf(buffer, len, "%s", freefare_strerror(tag)) < 0) ? -1 : 0;
}

void
freefare_perror(FreefareTag tag, const char *string)
{
    fprintf(stderr, "%s: %s\n", string, freefare_strerror(tag));
}

/*
 * Internal utility
 */

void *
freefare_memdup(const void *p, const size_t n)
{
    void *res;
    if ((res = malloc(n))) {
	memcpy(res, p, n);
    }
    return res;
}
