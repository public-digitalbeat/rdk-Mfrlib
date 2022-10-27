#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mfrApi.h"
#include "aml_upgrade.h"

#define MAX_BUF_LEN 255
#define SIZE 50
#define MAC_ADDRESS_SIZE 12
#define SERIAL_MAX_SIZE 16
#define MAX_COMMAND_SIZE 100

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

//#define DEBUG

const char defaultManufacturer[] = "SEI-Robotics";
const char defaultManufacturerOUI[] = "S905X4";
const char defaultModelName[] = "AH212";
const char defaultDescription[] = "AML S905X4 mediaclient thunder";
const char defaultProductClass[] = "RDK4-Firebolt";
const char defaultSerialNumber[] = "0000000000000000";
const char defaultHardwareVersion[] = "AH212";
const char defaultSoftwareVersion[] = "0.1";
const char defaultMacAddress[] = "000000000000";

static const struct amlSocFamily_t {
	uint32_t idMask;
	const char *Class;
	const char *Chip;
	const char *DeviceName;
} amlSocFamily[] = {
	/* 'FF' in idMask makes logical AND passable for match */
	{ 0x28ff10, "MBX", "G12A",  "S905D2" },
	{ 0x28ff30, "MBX", "G12A",  "S905Y2" },
	{ 0x28ff40, "MBX", "G12A",  "S905X2" },
	{ 0x29ffff, "MBX", "G12B",  "T931G"  },
	{ 0x29ffff, "MBX", "G12B",  "S922X"  },
	{ 0x32fa02, "MBX", "SC2",   "S905X4" },
	{ 0x320b04, "MBX", "C2",    "S905C2" },
	{ 0x370a02, "MBX", "S4",    "S805X2" },
	{ 0x370a03, "MBX", "S4",    "S905Y4" },
	{ 0x3a0a03, "MBX", "S4D",   "S905Y4D" },
	{ 0x3a0c04, "MBX", "C3",    "S905C3" },
};

char* getChipsetFromId(char *pSlNo)
{
	int i;
	char slNo[8] = {'\0'};
	strncpy(slNo, pSlNo, 6);
	uint32_t chipID = strtoul(slNo, NULL, 16);
	for (i = 0; i < ARRAY_SIZE(amlSocFamily); i++) {
		if (chipID == (chipID & amlSocFamily[i].idMask)) {
			return(amlSocFamily[i].DeviceName);
		}
	}
	return defaultManufacturerOUI;
}

void mfrlib_log(const char *format, ...)
{
    int total = 0;
    va_list args;
    int buf_index;
#ifdef DEBUG
    va_start(args, format);
    // log to console
    total = vfprintf(stdout, format, args);
    fflush(stdout);
    va_end(args);
#endif
}

void mfrFreeBuffer(char *buf)
{
    if (buf)
        free(buf);
}

mfrError_t mfrGetSerializedData(mfrSerializedType_t param, mfrSerializedData_t *data)
{
    char cmd[MAX_COMMAND_SIZE];
    char buffer[MAX_BUF_LEN];
    FILE *fp = NULL;
    mfrError_t ret = mfrERR_NONE;
    if (!data)
        return mfrERR_INVALID_PARAM;
    data->freeBuf = mfrFreeBuffer;
    switch (param)
    {
    case mfrSERIALIZED_TYPE_MANUFACTURER:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(buffer, 0, MAX_BUF_LEN);
        /* retrieving tag MANUFACTURE from /etc/device.properties */
        sprintf(cmd, "cat /etc/device.properties | grep MANUFACTURE | sed -e 's/.*=//g'");
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultManufacturer);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            if (strlen(buffer) > 1) {
                strncpy(data->buf, buffer, strlen(buffer) - 1);
            } else {
                strcpy(data->buf, defaultManufacturer);
            }
            data->bufLen = strlen(data->buf);
            pclose(fp);
        }
        mfrlib_log("Manufacturer= %s\t len=%d\n", data->buf, data->bufLen);
        break;
    /* unique identifier of the Manufacturer :: we are using the first 6 chars of the mac address */
    case mfrSERIALIZED_TYPE_MANUFACTUREROUI:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(buffer, 0, MAX_BUF_LEN);
        //sprintf(cmd, "ifconfig | grep `ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d' | head -n1` | tr -s ' ' | cut -d ' ' -f5 | sed -e 's/://g'");
        sprintf(cmd, "ifconfig | grep eth0 | awk '{print $5}' | sed -e 's/://g'"); //ethernet or wi-fi need?
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultManufacturerOUI);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            if (strlen(buffer) > 1) {
                strncpy(data->buf, buffer, 6);
            } else {
                strcpy(data->buf, defaultManufacturerOUI);
            }
            data->bufLen = strlen(data->buf);
            pclose(fp);
        }
        mfrlib_log("Manufacturer OUI= %s\t len=%d\n", data->buf, data->bufLen);
        break;
    case mfrSERIALIZED_TYPE_MODELNAME:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(buffer, 0, MAX_BUF_LEN);
        /* retrieving tag MODEL_NUM from /etc/device.properties */
        sprintf(cmd, "cat /etc/device.properties | grep MODEL_NUM | sed -e 's/.*=//g'");
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultModelName);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            if (strlen(buffer) > 1) {
                strncpy(data->buf, buffer, strlen(buffer) - 1);
            } else {
                strcpy(data->buf, defaultModelName);
            }
            data->bufLen = strlen(data->buf);
            pclose(fp);
        }
        mfrlib_log("Model Name= %s\t len=%d\n", data->buf, data->bufLen);
        break;
    case mfrSERIALIZED_TYPE_DESCRIPTION:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(buffer, 0, MAX_BUF_LEN);
        /* retrieving tag DEVICE_TYPE from /etc/device.properties */
        sprintf(cmd, "cat /etc/device.properties | grep DEVICE_TYPE | sed -e 's/.*=//g'");
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultDescription);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            sprintf(data->buf, "%s ", defaultModelName);
            if (strlen(buffer) > 1) {
                strncat(data->buf, buffer, strlen(buffer) - 1);
            } else {
                strcpy(data->buf, defaultDescription);
            }
            data->bufLen = strlen(data->buf);
            pclose(fp);
        }
        mfrlib_log("DESCRIPTION= %s\t len=%d\n", data->buf, data->bufLen);
        break;
    case mfrSERIALIZED_TYPE_PRODUCTCLASS:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(buffer, 0, MAX_BUF_LEN);
        /* retrieving tag DEVICE_NAME from /etc/device.properties */
        sprintf(cmd, "cat /etc/device.properties | grep DEVICE_NAME | sed -e 's/.*=//g'");
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultProductClass);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            if (strlen(buffer) > 1) {
                strncpy(data->buf, buffer, strlen(buffer) - 1);
            } else {
                strcpy(data->buf, defaultProductClass);
            }
            data->bufLen = strlen(data->buf);
            pclose(fp);
        }
        mfrlib_log("PRODUCT CLASS= %s\t len=%d\n", data->buf, data->bufLen);
        break;
    case mfrSERIALIZED_TYPE_SERIALNUMBER:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(buffer, 0, MAX_BUF_LEN);
        /* retrieving tag Serial from /proc/cpuinfo */
        //sprintf(cmd, "cat /proc/cpuinfo | grep Serial | sed -e 's/.*: //g'");
        sprintf(cmd, "cat /proc/cmdline | awk -F\"[ ]\" '{for(i=1;i<=NF;i++){print $(i)}}' | grep serialno | cut -d \"=\" -f2");
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultSerialNumber);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            if (strlen(buffer) > 1) {
                buffer[strcspn(buffer, "\r\n")] = '\0';
                strncpy(data->buf, buffer, SERIAL_MAX_SIZE);
            } else {
                strcpy(data->buf, defaultSerialNumber);
            }
            data->bufLen = strlen(data->buf);
            pclose(fp);
        }
        mfrlib_log("Serial Number =  %s\t len=%d\n", data->buf, data->bufLen);
        break;
    case mfrSERIALIZED_TYPE_HARDWAREVERSION:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(buffer, 0, MAX_BUF_LEN);
        /* retrieving tag Revision from /proc/cpuinfo */
        sprintf(cmd, "cat /proc/cpuinfo | grep Hardware | sed -e 's/.*: //g'");
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultHardwareVersion);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            if (strlen(buffer) > 1) {
                strncpy(data->buf, buffer, strlen(buffer) - 1);
            } else {
                strcpy(data->buf, defaultHardwareVersion);
            }
            data->bufLen = strlen(data->buf);
            pclose(fp);
        }
        mfrlib_log("Hardware Version= %s\t len=%d\n", data->buf, data->bufLen);
        break;
    case mfrSERIALIZED_TYPE_SOFTWAREVERSION:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(buffer, 0, MAX_BUF_LEN);
        /* retrieving tag BUILD_VERSION from /etc/device.properties */
        sprintf(cmd, "cat /etc/device.properties | grep BUILD_VERSION | sed -e 's/.*=//g'");
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultSoftwareVersion);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            if (strlen(buffer) > 1) {
                strncpy(data->buf, buffer, strlen(buffer) - 1);
            } else {
                strcpy(data->buf, defaultSoftwareVersion);
            }
            data->bufLen = strlen(data->buf);
            pclose(fp);
        }
        mfrlib_log("Build Version =  %s\t len=%d\n", data->buf, data->bufLen);
        break;
    case mfrSERIALIZED_TYPE_PROVISIONINGCODE:
    case mfrSERIALIZED_TYPE_FIRSTUSEDATE:
    case mfrSERIALIZED_TYPE_MOCAMAC:
    case mfrSERIALIZED_TYPE_HDMIHDCP:
    case mfrSERIALIZED_TYPE_PDRIVERSION:
    case mfrSERIALIZED_TYPE_WIFIMAC:
    case mfrSERIALIZED_TYPE_BLUETOOTHMAC:
    case mfrSERIALIZED_TYPE_MAX:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        strcpy(data->buf, "XXXX");
        data->bufLen = strlen(data->buf);
        break;
    case mfrSERIALIZED_TYPE_DEVICEMAC:
        data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        memset(cmd, 0, sizeof(char) * 100);
        memset(buffer, 0, MAX_BUF_LEN);
        //sprintf(cmd, "ifconfig | grep `ifconfig -a | sed 's/[ \t].*//;/^\(lo\|\)$/d' | head -n1` | tr -s ' ' | cut -d ' ' -f5 | sed -e 's/://g'");
#ifndef USE_RDKSERVICES
        sprintf(cmd,"ifconfig | grep `ifconfig -a | sed 's/[ \t].*//;/^\(lo\\|\\)$/d' | head -n1` | tr -s ' ' | cut -d ' ' -f5 | sed -e 's/://g'");
#else
        sprintf(cmd, "ifconfig | grep eth0 | awk '{print $5}' | sed -e 's/://g'"); //ethernet or wi-fi need?
#endif
        if ((fp = popen(cmd, "r")) == NULL)
        {
            mfrlib_log("popen failed.");
            strcpy(data->buf, defaultMacAddress);
            data->bufLen = strlen(data->buf);
        }
        if (fp)
        {
            fgets(buffer, sizeof(buffer), fp);
            if (strlen(buffer) > 1) {
                strncpy(data->buf, buffer, MAC_ADDRESS_SIZE);
            } else {
                strcpy(data->buf, defaultMacAddress);
            }
            data->bufLen = MAC_ADDRESS_SIZE;
            pclose(fp);
        }
        mfrlib_log("MAC Address = %s\t len=%d\n", data->buf, data->bufLen);
        break;
	case mfrSERIALIZED_TYPE_CHIPSETINFO:
		data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
		memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
		memset(cmd, 0, sizeof(char) * 100);
		memset(buffer, 0, MAX_BUF_LEN);
		/* retrieving tag Revision from /proc/cpuinfo */
		sprintf(cmd, "cat /proc/cpuinfo | grep Hardware | sed -e 's/.*: //g'");
		if ((fp = popen(cmd, "r")) == NULL)
		{
			mfrlib_log("popen failed.");
			strcpy(data->buf, defaultHardwareVersion);
			data->bufLen = strlen(data->buf);
		}
		if (fp)
		{
			fgets(buffer, sizeof(buffer), fp);
			pclose(fp);
			if (strlen(buffer) > 1) {
				FILE *sfp = NULL;
				strncpy(data->buf, buffer, strlen(buffer) - 1);
				strncat(data->buf, " ", MAX_BUF_LEN);
				/* Extract Serial Number and map chipset. */
				memset(cmd, 0, sizeof(char) * 100);
				memset(buffer, 0, MAX_BUF_LEN);
				/* retrieving tag Serial from /proc/cpuinfo */
				sprintf(cmd, "cat /proc/cpuinfo | grep Serial | sed -e 's/.*: //g'");
				if ((sfp = popen(cmd, "r")) == NULL)
				{
					mfrlib_log("popen failed.");
					strncpy(buffer, defaultSerialNumber, 6);
				}
				if (sfp)
				{
					fgets(buffer, sizeof(buffer), sfp);
					pclose(sfp);
					if (strlen(buffer) < 6) {
						strncpy(buffer, defaultSerialNumber, 6);
					}
					strncat(data->buf, getChipsetFromId(buffer), (MAX_BUF_LEN - strlen(data->buf) - 2));
				}
			}
			data->bufLen = strlen(data->buf);
		}
		mfrlib_log("Chipset Info= %s\t len=%d\n", data->buf, data->bufLen);
		break;
	default:
		data->buf = (char *)malloc(sizeof(char) * MAX_BUF_LEN);
        memset(data->buf, '\0', sizeof(char) * MAX_BUF_LEN);
        data->bufLen = strlen(data->buf);
        break;
    }
    return mfrERR_NONE;
}
mfrError_t mfrDeletePDRI()
{
    return mfrERR_NONE;
}
mfrError_t mfrScrubAllBanks()
{
    return mfrERR_NONE;
}
mfrError_t mfrWriteImage(const char *pFileName, const char *pFilePath,
                         mfrImageType_t imageType, mfrUpgradeStatusNotify_t upgradeStatus)
{
    // name and path seems in reversed order.  confused??
	mfrError_t retStatus = mfrERR_NONE;
    char _package[1024] = {'\0'};
    sprintf (_package, "%s/%s", pFilePath, pFileName);
	int length = -1;
	length = snprintf(_package, (sizeof(_package)-1), "%s/%s", pFilePath, pFileName);
	if (length != (strlen(pFilePath)+strlen(pFileName))) {
		printf ("Package with absolute path = %s\n", _package);
#ifdef USE_VALIDATION_FWFILE
		retStatus = install_aml_package("/data/aml_upgrade_package.img", upgradeStatus);
#else /* !USE_VALIDATION_FWFILE */
		retStatus = install_aml_package(_package, upgradeStatus);
#endif /* !USE_VALIDATION_FWFILE */
	} else {
		printf("Error: _package [%d] cannot hold absolute firmware file name[%s] and path[%s].\n",
				sizeof(_package), pFileName, pFilePath);
		retStatus = mfrERR_GENERAL;
	}
    return retStatus;
}
mfrError_t mfr_init()
{
    return mfrERR_NONE;
}
mfrError_t mfrFWUpgradeInit(void)
{
    return mfrERR_NONE;
}
mfrError_t mfrFWUpgradeTerm(void)
{
    return mfrERR_NONE;
}
