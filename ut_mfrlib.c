#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "mfrApi.h"
#include "bootloader_message.h"
#include "aml_upgrade.h"

//#define UT_SET_ACTIVE_SLOT_AB 1
#define UT_WRITE_PACKAGE 1

/* Keep order matching with _mfrImageType_t */
const char* mfrSerializedTypeString[] = {
    "manufacturer",
    "manufactureroui",
    "modelname",
    "description",
    "productclass",
    "serialnumber",
    "hardwareversion",
    "softwareversion",
    "provisioningcode",
    "firstusedate",
    "devicemac",
    "mocamac",
    "hdmihdcp",
    "pdriversion",
    "wifimac",
    "bluetoothmac",
     "chipsetinfo",
    NULL
};

int update_firmware(char *pImageFile)
{
    int ret = 0;
    int _cur_active_slot; // 0=_a, 1=_b
    int _active_slot;

    ret = get_system_type();

#ifdef UT_SET_ACTIVE_SLOT_AB
    ret = get_active_slot(&_cur_active_slot);
    printf ("_cur_active_slot= %d\n", _cur_active_slot);
    if (_cur_active_slot == 0) {
        printf ("Active slot from cmdline is boot_a\n");
    }
    else {
        printf ("Active slot from comdline is boot_b\n");
    }

    ret = get_active_slot_misc(&_cur_active_slot);
    if (_cur_active_slot == 0) {
        printf ("Active slot from misc is boot_a\n");
    }
    else {
        printf ("Active slot from misc is boot_b\n");
    }

    // Test switching A/B
    if (_cur_active_slot == 0) {
        printf ("set active slot from A to B\n");
        ret = set_active_slot (1);
        ret = get_active_slot_misc(&_active_slot);
        if (_active_slot == 0) {
            printf ("new active slot is boot_a after reboot\n");
        }
        else {
            printf ("new active slot is boot_b after reboot\n");
        }
    }
    else {
        printf ("set active slot from B to A\n");
        ret = set_active_slot(0);
        ret = get_active_slot_misc(&_active_slot);
        if (_active_slot == 0) {
            printf ("new active slot is boot_a after reboot\n");
        }
        else {
            printf ("new active slot is boot_b after reboot\n");
        }
    }

    ret = set_active_slot(_cur_active_slot); //force back to boot_a
#endif

#ifdef UT_WRITE_PACKAGE
    mfrUpgradeStatusNotify_t upgradeStatus = {};

    ret = get_active_slot_misc(&_cur_active_slot);
    printf ("before install image: _cur_active_slot= %d\n", _cur_active_slot);
    printf ("Start to install AML upgrade package\n");

    ret = install_aml_package(pImageFile, upgradeStatus);

    system("sync");
    sleep(1);

    ret = get_active_slot_misc(&_cur_active_slot);
    printf ("after install image: _cur_active_slot= %d\n", _cur_active_slot);
#endif

    return ret;
}

mfrSerializedType_t getmfrSerializedTypeFromString(char *pString)
{
    int i;
    for (i= 0; mfrSerializedTypeString[i]; i++) {
        if (!strcmp(pString, mfrSerializedTypeString[i])) {
            /* Keep sync with mfrSERIALIZED_TYPE_MANUFACTURER which is the first offset. */
            i += mfrSERIALIZED_TYPE_MANUFACTURER;
            break;
        }
    }
    return ((mfrSerializedType_t)i);
}

int readMfrSerializedInfo(char *pStringType)
{
    int retVal = -1;
    mfrSerializedData_t mfrSerializedData;

    mfrSerializedType_t type = getmfrSerializedTypeFromString(pStringType);
    if (type >= mfrSERIALIZED_TYPE_MAX) {
        printf("readMfrSerializedInfo: type[%d] is not matching.\n", type);
        return retVal;
    }
    retVal = mfrGetSerializedData(type, &mfrSerializedData);
    if ((mfrERR_NONE == retVal) && mfrSerializedData.bufLen) {
        printf("mfrSerializedData.bufLen = %d\n", (int)mfrSerializedData.bufLen);
        printf("mfrSerializedData.buf = %s\n", mfrSerializedData.buf);
        if (mfrSerializedData.freeBuf) {
            mfrSerializedData.freeBuf(mfrSerializedData.buf);
        }
    }
    return retVal;
}

void showUsage(char *pName)
{
    int i;
    
    printf("Usage: %s [-u firmwareImageWithAbsolutePath] [-r serializationInfoType]\n"
            "\t-u: update device with firmware file\n"
            "\t-r: read any of the Serialization Information of matching 'Type'\n"
            "\t\tType: ",  pName);
    for (i= 0; mfrSerializedTypeString[i]; i++) {
        printf("%s ", mfrSerializedTypeString[i]);
        if (i && !(i % 5)) {
            printf("\n\t\t      ");
        }
    }
    printf("\n\t\tNote: 'Type' arguments are case sensitive.\n");
}

int main(int argc, char **argv)
{
    int c;
    char *cvalue = NULL;
    opterr = 0;
    int retVal = -1;

    if (argc == 3) {
        while ((c = getopt(argc, argv, "r:u:")) != -1) {
            cvalue = optarg;
            switch (c) {
                case 'r':
                    retVal = readMfrSerializedInfo(cvalue);
                    break;
                case 'u':
                    printf("Update with firmware %s\n", cvalue);
                    retVal = update_firmware(cvalue);
                    break;
                case '?':
                default:
                    showUsage(argv[0]);
                    exit(0);
            }
        }
    } else {
        showUsage(argv[0]);
    }
    return retVal;
}
