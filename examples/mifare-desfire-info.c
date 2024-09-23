#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>

/* Maximum number of NFC devices */
#define MAX_NFC_DEVICES 32

/* Declarations */

static void scan_tag(FreefareTag tag);
static void scan_file(FreefareTag tag, MifareDESFireAID app, uint8_t fid);
static void scan_application(FreefareTag tag, MifareDESFireAID app);

/* Main program */

int
main(int argc, char *argv[])
{
    nfc_context *context;
    nfc_connstring devices[MAX_NFC_DEVICES];
    size_t device_count;
    size_t tags_found = 0;

    if (argc > 1)
	errx(EXIT_FAILURE, "usage: %s", argv[0]);

    /* Initialize libnfc */
    nfc_init(&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    /* List NFC devices */
    device_count = nfc_list_devices(context, devices, MAX_DEVICES);
    if (device_count <= 0)
	errx(EXIT_FAILURE, "No NFC device found.");

    /* Scan each device */
    for (size_t d = 0; d < device_count; d++) {

	/* Open the device */
	nfc_device *device = nfc_open(context, devices[d]);
	if (!device) {
	    warnx("nfc_open() failed.");
	    goto skip_all;
	}

	/* Retrieve list of tags */
	FreefareTag *tags = freefare_get_tags(device);
	if (!tags) {
	    nfc_close(device);
	    warnx("Error listing tags.");
	    goto skip_tags;
	}

	/* Scan tags (we allow errors) */
	for (int i = 0; tags[i]; i++) {
	    FreefareTag tag = tags[i];

	    /* We are only interested in DESFire tags */
	    if (MIFARE_DESFIRE != freefare_get_tag_type(tag))
		continue;

	    /* Count the tags that we have found */
	    tags_found++;

	    /* Print whitespace */
	    printf("\n");

	    /* Scan the tag and print info */
	    scan_tag(tag);
	}

	/* Free tag list */
	freefare_free_tags(tags);

    skip_tags:
	/* Close the device */
	nfc_close(device);

    skip_all:
    }

    /* Print whitespace */
    if(tags_found > 0) {
	printf("\n");
    }

    /* Finalize libnfc */
    nfc_exit(context);

    /* Done */
    return 0;
}

/* Implementation functions */

static void scan_tag(FreefareTag tag) {
    int res;

    /* Get and print the announced UID */
    char *tag_uid = freefare_get_tag_uid(tags[i]);
    printf("desfire %s via %s\n", tag_uid, devices[d]);
    if (strlen(tag_uid) / 2 == 4) {
	printf("  uid randomized\n");
    } else {
	printf("  uid not randomized\n");
    }

    /* Connect to tag */
    res = mifare_desfire_connect(tag);
    if (res < 0) {
	warnx("Can't connect to Mifare DESFire target.");
	goto skip_reading;
    }

    /* Get and print version information */
    struct mifare_desfire_version_info info;
    res = mifare_desfire_get_version(tag, &info);
    if (res < 0) {
	freefare_perror(tags[i], "mifare_desfire_get_version");
    } else {
	printf("  version information:\n", tag_uid);
	printf("    UID:                      0x%02x%02x%02x%02x%02x%02x%02x\n", info.uid[0], info.uid[1], info.uid[2], info.uid[3], info.uid[4], info.uid[5], info.uid[6]);
	printf("    Batch number:             0x%02x%02x%02x%02x%02x\n", info.batch_number[0], info.batch_number[1], info.batch_number[2], info.batch_number[3], info.batch_number[4]);
	printf("    Production date:          week %x, 20%02x\n", info.production_week, info.production_year);
	printf("    Hardware Information:\n");
	printf("      Vendor ID:            0x%02x\n", info.hardware.vendor_id);
	printf("      Type:                 0x%02x\n", info.hardware.type);
	printf("      Subtype:              0x%02x\n", info.hardware.subtype);
	printf("      Version:              %d.%d\n", info.hardware.version_major, info.hardware.version_minor);
	printf("      Storage size:         0x%02x (%s%d bytes)\n", info.hardware.storage_size, (info.hardware.storage_size & 1) ? ">" : "=", 1 << (info.hardware.storage_size >> 1));
	printf("      Protocol:             0x%02x\n", info.hardware.protocol);
	printf("    Software Information:\n");
	printf("      Vendor ID:            0x%02x\n", info.software.vendor_id);
	printf("      Type:                 0x%02x\n", info.software.type);
	printf("      Subtype:              0x%02x\n", info.software.subtype);
	printf("      Version:              %d.%d\n", info.software.version_major, info.software.version_minor);
	printf("      Storage size:         0x%02x (%s%d bytes)\n", info.software.storage_size, (info.software.storage_size & 1) ? ">" : "=", 1 << (info.software.storage_size >> 1));
	printf("      Protocol:             0x%02x\n", info.software.protocol);
    }

    /* Get and print memory information */
    uint32_t size;
    res = mifare_desfire_free_mem(tag, &size);
    if (0 == res) {
	printf("  %d bytes free memory\n", size);
    } else {
	printf("  free memory UNKNOWN\n");
    }

    /* Get and print master key version */
    uint8_t version;
    res = mifare_desfire_get_key_version(tag, 0, &version);
    if(0 == res) {
	printf("  master key version %d (0x%02x)\n", version, version);
    } else {
	printf("  master key version UNKNOWN\n", version, version);
    }

    /* Get and print master key settings */
    uint8_t settings;
    uint8_t max_keys;
    res = mifare_desfire_get_key_settings(tag, &settings, &max_keys);
    if (res == 0) {
	printf("  master key settings 0x%02x:\n", settings);
	printf("    0x%02x configuration changeable;\n", settings & 0x08);
	printf("    0x%02x PICC Master Key not required for create / delete;\n", settings & 0x04);
	printf("    0x%02x Free directory list access without PICC Master Key;\n", settings & 0x02);
	printf("    0x%02x Allow changing the Master Key;\n", settings & 0x01);
    } else if (AUTHENTICATION_ERROR == mifare_desfire_last_picc_error(tag)) {
	printf("  master key settings LOCKED\n");
    } else {
	freefare_perror(tag, "mifare_desfire_get_key_settings");
    }

    /* List applications */
    MifareDESFireAID *apps;
    size_t app_count;
    res = mifare_desfire_get_application_ids(tag, &apps, &app_count);
    if(res != 0) {
	if (AUTHENTICATION_ERROR == mifare_desfire_last_picc_error(tag)) {
	    printf("  application list LOCKED\n");
	} else {
	    freefare_perror(tags[i], "mifare_desfire_get_application_ids");
	}
    } else {
	if(app_count == 0) {
	    printf("  no applications\n");
	    goto skip_applications;
	}
    }

    /* Scan applications */
    for(int k = 0; k < app_count; k++) {
	scan_application(tag, apps[k]);
    }

    /* Free the application list */
    mifare_desfire_free_application_ids(apps);

 skip_applications:

    /* Disconnect from tag */
    mifare_desfire_disconnect(tag);

 skip_reading:
    /* Free the UID */
    free(tag_uid);
}

static void scan_application(FreefareTag tag, MifareDESFireAID app) {
    int res;

    printf("  application %06x\n", mifare_desfire_aid_get_aid(app));

    /* Select the application */
    res = mifare_desfire_select_application(tag, app);
    if(res != 0) {
	freefare_perror(tag, "mifare_select_application");
	continue;
    }

    /* Get settings and number of keys */
    uint8_t app_settings;
    uint8_t app_maxkeys;
    res = mifare_desfire_get_key_settings(tag, &app_settings, &app_maxkeys);
    if (res == 0) {
	printf("    %d maximum keys\n", app_maxkeys);
	printf("    application key settings 0x%02x\n", app_settings);
    } else if (AUTHENTICATION_ERROR == mifare_desfire_last_picc_error(tag)) {
	printf("    application key settings LOCKED\n");
    } else {
	freefare_perror(tag, "mifare_desfire_get_key_settings");
    }

    /* List files */
    uint8_t *files;
    size_t file_count;
    res = mifare_desfire_get_file_ids(tag, &files, &file_count);
    if (res != 0) {
	if (AUTHENTICATION_ERROR == mifare_desfire_last_picc_error(tag)) {
	    printf("    file listing LOCKED\n");
	} else {
	    freefare_perror(tag, "mifare_desfire_get_file_ids");
	}
	goto skip_files;
    }

    /* Scan files */
    printf("    %d files\n", file_count);
    for(int i = 0; i < file_count; i++) {
	scan_file(tag, app, files[i]);
    }

    /* Free the file list */
    freefare_free(files);

 skip_files:
}

static void scan_file(FreefareTag tag, MifareDESFireAID app, uint8_t fid) {
    printf("    file %02x\n", fid);
}
