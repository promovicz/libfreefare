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

uint8_t secret_default[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct {
    /* NFC device string */
    const char *device;
    /* Skip confirmation */
    bool noconfirm;
    /* Card master key */
    MifareDESFireKey cmk;
} options = {
    .device = NULL,
    .noconfirm = false,
    .cmk = NULL,
};

static void
usage(char *progname)
{
    fprintf(stderr, "Usage: %s [-y] [-d device] [-K 11223344AABBCCDD]\n\n", progname);
    fprintf(stderr, "Perform a formatting procedure on Mifare DESFire NFC tags.\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d  NFC device string\n");
    fprintf(stderr, "  -k  Reset card master key\n");
    fprintf(stderr, "  -y  Skip confirmation (dangerous)\n");
    fprintf(stderr, "  -K  Card master key (see below for syntax)\n");
    fprintf(stderr, "  -h  Request help (this message)\n");
}

static int
getopts(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "hyK:")) != -1) {
	switch (opt) {
	case 'h':
	    return 1; /* help requested */
	case 'd':
	    options.device = optarg;
	    break;
	case 'y':
	    options.noconfirm = true;
	    break;
	case 'K':
	    /* FIXME */
	    break;
	default:
	    return -1;
	}
    }
    // Remaining args, if any, are in argv[optind .. (argc-1)]
    return 0;
}

char ask_options(const char *question, const char *options)
{
}

bool ask_yesno(const char *question)
{
    const char options = "yN";
    return false;
}

int
do_format(FreefareTag tag)
{
    int res;
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

    /* Construct default key */
    MifareDESFireKey key_default = mifare_desfire_des_key_new_with_version(secret_default);

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

    /* Determine card master key */
    MifareDESFireKey key = key_default;
    if(options.cmk) {
	key = options.cmk;
    }

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
	    if (!options.noconfirm) {
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

		/* Authenticate to master application */
		res = mifare_desfire_authenticate(tag, 0, key);
		if (res < 0) {
		    warnx("Can't authenticate on Mifare DESFire target.");
		    break;
		}

		/* Reset master key settings */
		res = mifare_desfire_change_key_settings(tag, 0x0F);
		if (res < 0) {
		    errx(EXIT_FAILURE, "ChangeKeySettings failed");
		}

		/* Perform formatting */
		res = mifare_desfire_format_picc(tag);
		if (res < 0) {
		    warn("Can't format PICC.");
		    break;
		}

		/* Disconnect from the tag */
		mifare_desfire_disconnect(tags[i]);
	    }

	    /* Free the tag UID */
	    free(tag_uid);
	}

	/* Free the tag list */
	freefare_free_tags(tags);

	/* Close the device */
	nfc_close(device);
    }

    /* Free the default key */
    mifare_desfire_key_free(key_default);

    /* Finalize libnfc */
    nfc_exit(context);

    /* Done */
    return 0;
} /* main() */
