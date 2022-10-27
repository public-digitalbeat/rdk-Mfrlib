#include <errno.h>
#include "bootloader_avb.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>


static void dump_boot_info(AvbABData* info)
{
    printf("info->magic 0x%x 0x%x 0x%x 0x%x\n", info->magic[0], info->magic[1], info->magic[2], info->magic[3]);
    printf("info->version_major = %d\n", info->version_major);
    printf("info->version_minor = %d\n", info->version_minor);
    printf("info->slots[0].priority = %d\n", info->slots[0].priority);
    printf("info->slots[0].tries_remaining = %d\n", info->slots[0].tries_remaining);
    printf("info->slots[0].successful_boot = %d\n", info->slots[0].successful_boot);
    printf("info->slots[1].priority = %d\n", info->slots[1].priority);
    printf("info->slots[1].tries_remaining = %d\n", info->slots[1].tries_remaining);
    printf("info->slots[1].successful_boot = %d\n", info->slots[1].successful_boot);

    printf("info->crc32 = %d\n", info->crc32);
}

static int get_bootloader_message_block(char * miscbuf, int size) {
    const char *misc_device = "/dev/misc";
    printf ("read misc for emmc device\n");
    FILE* f = fopen(misc_device, "rb");
    if (f == NULL) {
        printf("Can't open %s\n(%s)\n", misc_device, strerror(errno));
        return -1;
    }

    int count = fread(miscbuf, 1, size, f);
    if (count != size) {
        printf("Failed reading %s\n(%s)\n", misc_device, strerror(errno));
        return -1;
    }
    if (fclose(f) != 0) {
        printf("Failed closing %s\n(%s)\n", misc_device, strerror(errno));
        return -1;
    }

    return 0;
}

/* Converts a 32-bit unsigned integer from host to big-endian byte order. */
uint32_t avb_htobe32(uint32_t in) {
  union {
    uint32_t word;
    uint8_t bytes[4];
  } ret;
  ret.bytes[0] = (in >> 24) & 0xff;
  ret.bytes[1] = (in >> 16) & 0xff;
  ret.bytes[2] = (in >> 8) & 0xff;
  ret.bytes[3] = in & 0xff;
  return ret.word;
}


static int set_bootloader_message_block(char * miscbuf, int size, AvbABData *info) {
    const char *misc_device = "/dev/misc";

    info->crc32 = avb_htobe32(
      avb_crc32((const uint8_t*)info, sizeof(AvbABData) - sizeof(uint32_t)));

    memcpy(miscbuf+AB_METADATA_MISC_PARTITION_OFFSET, info, AVB_AB_DATA_SIZE);
    dump_boot_info(info);

    printf ("write misc for emmc device\n");
    FILE* f = fopen(misc_device, "wb");
    if (f == NULL) {
        printf("Can't open %s\n(%s)\n", misc_device, strerror(errno));
        return -1;
    }
    int count = fwrite(miscbuf, 1, MISCBUF_SIZE, f);
    if (count != MISCBUF_SIZE) {
        printf("Failed writing %s\n(%s)\n", misc_device, strerror(errno));
        return -1;
    }
    if (fclose(f) != 0) {
        printf("Failed closing %s\n(%s)\n", misc_device, strerror(errno));
        return -1;
    }
    return 0;
}


int get_active_slot_from_misc(int *slot) {
    int ret = 0;
    AvbABData info;
    char miscbuf[MISCBUF_SIZE] = {0};

    ret = get_bootloader_message_block(miscbuf, MISCBUF_SIZE);
    if (ret != 0) {
        printf("get_bootloader_message failed!\n");
        return -1;
    }

    memcpy(&info, miscbuf + AB_METADATA_MISC_PARTITION_OFFSET, AVB_AB_DATA_SIZE);
    dump_boot_info(&info);
    if (info.slots[0].priority > info.slots[1].priority)
        *slot = 0;
    else
        *slot = 1;

    return 0;
}

bool boot_info_validate(AvbABData* info)
{
    if (memcmp(info->magic, AVB_AB_MAGIC, AVB_AB_MAGIC_LEN) != 0) {
        printf("Magic %s is incorrect.\n", info->magic);
        return false;
    }
    if (info->version_major > AVB_AB_MAJOR_VERSION) {
        printf("No support for given major version.\n");
        return false;
    }
    return true;
}

int boot_info_set_active_slot(AvbABData* info, int slot)
{
    unsigned int other_slot_number;

    /* Make requested slot top priority, unsuccessful, and with max tries. */
    info->slots[slot].priority = AVB_AB_MAX_PRIORITY;
    info->slots[slot].tries_remaining = AVB_AB_MAX_TRIES_REMAINING;
    info->slots[slot].successful_boot = 0;

    /* Ensure other slot doesn't have as high a priority. */
    other_slot_number = 1 - slot;
    if (info->slots[other_slot_number].priority == AVB_AB_MAX_PRIORITY) {
        info->slots[other_slot_number].priority = AVB_AB_MAX_PRIORITY - 1;
    }

    dump_boot_info(info);

    return 0;
}

void boot_info_reset(AvbABData* info)
{
    memset(info, '\0', sizeof(AvbABData));
    memcpy(info->magic, AVB_AB_MAGIC, AVB_AB_MAGIC_LEN);
    info->version_major = AVB_AB_MAJOR_VERSION;
    info->version_minor = AVB_AB_MINOR_VERSION;
    info->slots[0].priority = AVB_AB_MAX_PRIORITY;
    info->slots[0].tries_remaining = AVB_AB_MAX_TRIES_REMAINING;
    info->slots[0].successful_boot = 0;
    info->slots[1].priority = AVB_AB_MAX_PRIORITY - 1;
    info->slots[1].tries_remaining = AVB_AB_MAX_TRIES_REMAINING;
    info->slots[1].successful_boot = 0;
}

int set_active_slot(int slot) {
    char miscbuf[MISCBUF_SIZE] = {0};
    AvbABData info;

    get_bootloader_message_block(miscbuf, MISCBUF_SIZE);
    memcpy(&info, miscbuf+AB_METADATA_MISC_PARTITION_OFFSET, AVB_AB_DATA_SIZE);
    dump_boot_info(&info);

   if (!boot_info_validate(&info)) {
        printf("boot-info is invalid. Resetting.\n");
        boot_info_reset(&info);
    }


    boot_info_set_active_slot(&info, slot);

    set_bootloader_message_block(miscbuf, MISCBUF_SIZE, &info);
    return 0;
}
