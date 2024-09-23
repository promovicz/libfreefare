#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

#define MAX_NFC_DEVICES 32

uint8_t key_data_picc[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct {
    bool noconfirm;
} options = {
    .noconfirm = false
};

static void
usage(char *progname)
{
    fprintf(stderr, "usage: %s [-d device] [-y] [-K 11223344AABBCCDD]\n", progname);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -d  NFC device string\n");
    fprintf(stderr, "  -y  Do not ask for confirmation (dangerous)\n");
    fprintf(stderr, "  -K  Provide another PICC key than the default one\n");
}

static int
getopts(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "hyK:")) != -1) {
	switch (opt) {
	case 'h':
	    return 1; /* help requested */
	case 'y':
	    options.noconfirm = true;
	    break;
	case 'K':
	    if (strlen(optarg) != 16) {
		return -1;
	    }
	    uint64_t n = strtoull(optarg, NULL, 16);
	    int i;
	    for (i = 7; i >= 0; i--) {
		key_data_picc[i] = (uint8_t) n;
		n >>= 8;
	    }
	    break;
	default:
	    return -1;
	}
    }
    // Remaining args, if any, are in argv[optind .. (argc-1)]
    return 0;
}

int
main(int argc, char *argv[])
{
    int res;
    nfc_context *context;
    nfc_connstring devices[MAX_NFC_DEVICES];
    size_t device_count;
    nfc_device *device;
    FreefareTag *tags;

    /* Parse options */
    res = getopts(argc, argv);
    if(res != 0) {
	usage(argv[0]);
	return (res < 0);
    }

    /* Initialize libnfc */
    nfc_init(&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    /* List NFC devices */
    device_count = nfc_list_devices(context, devices, MAX_NFC_DEVICES);
    if (device_count <= 0)
	errx(EXIT_FAILURE, "No NFC device found.");

    /* Scan devices */
    for (size_t d = 0; d < device_count; d++) {

	/* Open the device */
	device = nfc_open(context, devices[d]);
	if (!device) {
	    warnx("nfc_open() failed.");
	    continue;
	}

	/* List tags */
	tags = freefare_get_tags(device);
	if (!tags) {
	    nfc_close(device);
	    errx(EXIT_FAILURE, "Error listing Mifare DESFire tags.");
	}

	/* Scan tags */
	for (int i = 0; tags[i]; i++) {
	    FreefareTag tag = tags[i];

	    /* Ignore non-DESFire tags */
	    if (MIFARE_DESFIRE != freefare_get_tag_type(tag)) {
		continue;
	    }

	    /* Get tag UID */
	    char *tag_uid = freefare_get_tag_uid(tag);
	    printf("Found %s with UID %s. ", freefare_get_tag_friendly_name(tag), tag_uid);

	    /* Ask for confirmation */
	    bool format = true;
	    char buffer[BUFSIZ];
	    if (!options.unconfirmed) {
		printf("Format [yN] ");
		fgets(buffer, BUFSIZ, stdin);
		format = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    }

	    /* Perform operation if requested */
	    if (format) {
		/* Connect to the tag */
		res = mifare_desfire_connect(tag);
		if (res < 0) {
		    warnx("Can't connect to Mifare DESFire target.");
		    break;
		}

		MifareDESFireKey key_picc = mifare_desfire_des_key_new_with_version(key_data_picc);
		res = mifare_desfire_authenticate(tag, 0, key_picc);
		if (res < 0) {
		    warnx("Can't authenticate on Mifare DESFire target.");
		    break;
		}
		mifare_desfire_key_free(key_picc);

		// Send Mifare DESFire ChangeKeySetting to change the PICC master key settings into :
		// bit7-bit4 equal to 0000b
		// bit3 equal to 1b, the configuration of the PICC master key MAY be changeable or frozen
		// bit2 equal to 1b, CreateApplication and DeleteApplication commands are allowed without PICC master key authentication
		// bit1 equal to 1b, GetApplicationIDs, and GetKeySettings are allowed without PICC master key authentication
		// bit0 equal to 1b, PICC masterkey MAY be frozen or changeable
		res = mifare_desfire_change_key_settings(tag, 0x0F);
		if (res < 0)
		    errx(EXIT_FAILURE, "ChangeKeySettings failed");
		res = mifare_desfire_format_picc(tag);
		if (res < 0) {
		    warn("Can't format PICC.");
		    break;
		}

		mifare_desfire_disconnect(tags[i]);
	    }

	    free(tag_uid);
	}

	freefare_free_tags(tags);
	nfc_close(device);
    }
    nfc_exit(context);

    return 0;
} /* main() */

