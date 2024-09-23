/* Freefare scanning functions */

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <freefare.h>

#include "freefare_internal.h"

#define MAX_CANDIDATES 16

#define NXP_MANUFACTURER_CODE 0x04

/*
 * Get a list of the MIFARE targets near to the provided NFC initiator.
 *
 * The list has to be freed using the freefare_free_tags() function.
 */
FreefareTag *
freefare_get_tags(nfc_device *device)
{
    FreefareTag *tags = NULL;
    int tag_count = 0;

    nfc_initiator_init(device);

    // Drop the field for a while
    nfc_device_set_property_bool(device, NP_ACTIVATE_FIELD, false);

    // Configure the CRC and Parity settings
    nfc_device_set_property_bool(device, NP_HANDLE_CRC, true);
    nfc_device_set_property_bool(device, NP_HANDLE_PARITY, true);
    nfc_device_set_property_bool(device, NP_AUTO_ISO14443_4, true);

    // Enable field so more power consuming cards can power themselves up
    nfc_device_set_property_bool(device, NP_ACTIVATE_FIELD, true);

    // Poll for a ISO14443A (MIFARE) tag
    nfc_target candidates[MAX_CANDIDATES];
    int candidates_count;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if ((candidates_count = nfc_initiator_list_passive_targets(device, modulation, candidates, MAX_CANDIDATES)) < 0)
	return NULL;

    tags = malloc(sizeof(void *));
    if (!tags) return NULL;
    tags[0] = NULL;

    for (int c = 0; c < candidates_count; c++) {
	FreefareTag t;
	if ((t = freefare_tag_new(device, candidates[c]))) {
	    /* (Re)Allocate memory for the found MIFARE targets array */
	    FreefareTag *p = realloc(tags, (tag_count + 2) * sizeof(FreefareTag));
	    if (p)
		tags = p;
	    else
		return tags; // FAIL! Return what has been found so far.
	    tags[tag_count++] = t;
	    tags[tag_count] = NULL;
	}
    }

    // Poll for a FELICA tag
    modulation.nmt = NMT_FELICA;
    modulation.nbr = NBR_424; // FIXME NBR_212 should also be supported
    if ((candidates_count = nfc_initiator_list_passive_targets(device, modulation, candidates, MAX_CANDIDATES)) < 0)
	return NULL;

    for (int c = 0; c < candidates_count; c++) {
	FreefareTag t;
	if ((t = freefare_tag_new(device, candidates[c]))) {
	    /* (Re)Allocate memory for the found FELICA targets array */
	    FreefareTag *p = realloc(tags, (tag_count + 2) * sizeof(FreefareTag));
	    if (p)
		tags = p;
	    else
		return tags; // FAIL! Return what has been found so far.
	    tags[tag_count++] = t;
	    tags[tag_count] = NULL;
	}
    }

    return tags;
}
