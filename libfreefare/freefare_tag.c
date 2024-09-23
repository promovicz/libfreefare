/* Freefare tag functions */

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <freefare.h>

#include "freefare_internal.h"

/*
 * Automagically allocate a FreefareTag given a device and target info.
 */
FreefareTag
freefare_tag_new(nfc_device *device, nfc_target target)
{
    FreefareTag tag = NULL;

    if (felica_taste(device, target)) {
	tag = felica_tag_new(device, target);
    } else if (mifare_mini_taste(device, target)) {
	tag = mifare_mini_tag_new(device, target);
    } else if (mifare_classic1k_taste(device, target)) {
	tag = mifare_classic1k_tag_new(device, target);
    } else if (mifare_classic4k_taste(device, target)) {
	tag = mifare_classic4k_tag_new(device, target);
    } else if (mifare_desfire_taste(device, target)) {
	tag = mifare_desfire_tag_new(device, target);
    } else if (ntag21x_taste(device, target)) {
	tag = ntag21x_tag_new(device, target);
    } else if (mifare_ultralightc_taste(device, target)) {
	tag = mifare_ultralightc_tag_new(device, target);
    } else if (mifare_ultralight_taste(device, target)) {
	tag = mifare_ultralight_tag_new(device, target);
    }

    // Set default timeout
    if (tag)
	tag->timeout = MIFARE_DEFAULT_TIMEOUT;

    return tag;
}

/*
 * Returns the type of the provided tag.
 */
enum freefare_tag_type
freefare_get_tag_type(FreefareTag tag) {
    return tag->type;
}

/*
 * Returns the friendly name of the provided tag.
 */
const char *
freefare_get_tag_friendly_name(FreefareTag tag)
{
    switch (tag->type) {
    case FELICA:
	return "FeliCA";
    case MIFARE_MINI:
	return "Mifare Mini 0.3k";
    case MIFARE_CLASSIC_1K:
	return "Mifare Classic 1k";
    case MIFARE_CLASSIC_4K:
	return "Mifare Classic 4k";
    case MIFARE_DESFIRE:
	return "Mifare DESFire";
    case MIFARE_ULTRALIGHT_C:
	return "Mifare UltraLightC";
    case MIFARE_ULTRALIGHT:
	return "Mifare UltraLight";
    case NTAG_21x:
	return "NTAG21x";
    default:
	return "UNKNOWN";
    }
}

/*
 * Returns the UID of the provided tag.
 */
char *
freefare_get_tag_uid(FreefareTag tag)
{
    char *res = NULL;
    switch (tag->info.nm.nmt) {
    case NMT_FELICA:
	if ((res = malloc(17))) {
	    for (size_t i = 0; i < 8; i++)
		snprintf(res + 2 * i, 3, "%02x", tag->info.nti.nfi.abtId[i]);
	}
	break;
    case NMT_ISO14443A:
	if ((res = malloc(2 * tag->info.nti.nai.szUidLen + 1))) {
	    for (size_t i = 0; i < tag->info.nti.nai.szUidLen; i++)
		snprintf(res + 2 * i, 3, "%02x", tag->info.nti.nai.abtUid[i]);
	}
	break;
    case NMT_DEP:
    case NMT_ISO14443B2CT:
    case NMT_ISO14443B2SR:
    case NMT_ISO14443B:
    case NMT_ISO14443BI:
    case NMT_JEWEL:
    case NMT_BARCODE:
	res = strdup("UNKNOWN");
    }
    return res;
}

/*
 * Returns true if last selected tag is still present.
 */
bool freefare_selected_tag_is_present(nfc_device *device)
{
    return (nfc_initiator_target_is_present(device, NULL) == NFC_SUCCESS);
}

/*
 * Set NFC operation timeout
 */
void
freefare_set_tag_timeout(FreefareTag tag, int timeout)
{
    tag->timeout = timeout;
}

/*
 * Free the provided tag.
 */
void
freefare_free_tag(FreefareTag tag)
{
    if (tag) {
	tag->free_tag(tag);
    }
}

/*
 * Free the provided tag list.
 */
void
freefare_free_tags(FreefareTag *tags)
{
    if (tags) {
	for (int i = 0; tags[i]; i++) {
	    freefare_free_tag(tags[i]);
	}
	free(tags);
    }
}
