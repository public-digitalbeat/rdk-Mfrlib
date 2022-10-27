/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
//#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/input.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>

//C+= libraries
//#include <algorithm>
//#include <chrono>
//#include <memory>
//#include <string>
//#include <vector>

//#include <ziparchive/zip_archive.h>

#include "sparse.h"
#include "sparse_format.h"
#include "ImgHead.h"
#include "aml_upgrade.h"
#include "bootloader_message.h"

static const int RETRY_LIMIT = 4;
static mfrUpgradeStatusNotify_t cb_notify = {NULL, NULL, 0};
static mfrUpgradeStatus_t mfrUpgradeStatus = {mfrUPGRADE_PROGRESS_NOT_STARTED, mfrERR_NONE, 0};

int64_t g_totalSz;
int64_t g_writtenSz;
int64_t g_sparseWriteSz;
bool modified_flash = false;
bool cbUpdateThreadCreated;

//extern void amlogic_get_args(std::vector<std::string>& args);

enum {
    INSTALL_SUCCESS,
    INSTALL_ERROR,
    INSTALL_CORRUPT,
    INSTALL_NONE,
    INSTALL_SKIPPED,
    INSTALL_RETRY
};

#define BUFSIZE     1024*16
static unsigned int crc_table[256];
#define MMCBLK_BOOTLOADER  "/dev/bootloader"
#define MMCBLK_BOOT0       "/dev/mmcblk0boot0"
#define MMCBLK_BOOT1       "/dev/mmcblk0boot1"

#define DEFEND_KEY         "/dev/defendkey"
#define CMD_SECURE_CHECK   _IO('d', 0x01)
#define ARRAY_SIZE(x)      (int)(sizeof(x)/sizeof(x[0]))

int    g_num = 0;
char g_partition_list[16][24];

static void init_crc_table(void)
{
    unsigned int c;
    unsigned int i, j;

    for (i = 0; i < 256; i++) {
        c = (unsigned int)i;
        for (j = 0; j < 8; j++) {
            if (c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[i] = c;
    }
}


static unsigned int crc32(unsigned int crc,unsigned char *buffer, unsigned int size)
{
    unsigned int i;
    for (i = 0; i < size; i++) {
        crc = crc_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
    }
    return crc ;
}


int calc_img_crc(int fd, off_t offset)
{
    int ret;
    int nread;
    unsigned char buf[BUFSIZE];
    unsigned int crc = 0xffffffff;

    if (fd < 0) {
        printf("bad param, fd error!!\n");
        return -1;
    }

    init_crc_table();
    ret = lseek(fd,offset,SEEK_SET);
    if (ret < 0) {
        printf("fseek failed\n");
        return -1;
    }

    while ((nread = read(fd, buf, BUFSIZE)) > 0) {
        crc = crc32(crc, buf, nread);
    }

    if (nread < 0) {
        printf("read %s.\n",  strerror(errno));
        return -1;
    }

    return crc;
}

int image_read(ITEMINFO_V2 *item, int fd, int readsize, char *buffer) {

    int readlen = 0;

    //printf("++item->curoffsetInItem:%lld\n", item->curoffsetInItem);
    //printf("offset:%lld\n", item->offsetInImage + item->curoffsetInItem);

    int ret = lseek(fd, item->offsetInImage + item->curoffsetInItem, SEEK_SET);
    if (ret < 0) {
        printf("fseek failed [%s]\n", strerror(errno));
        return -1;
    }

    if (readsize + item->curoffsetInItem >= item->itemSz) {
        readlen = item->itemSz - item->curoffsetInItem;
    } else {
        readlen = readsize;
    }
    //printf("readlen:%d\n", readlen);

    ret = read(fd, buffer, readlen);
    if (ret != readlen) {
        printf("Read item date error! Read item buffer failed! [%s]\n", strerror(errno));
        return -1;
    }

    item->curoffsetInItem += readlen;

    return readlen;
}

int normal_image_update(int fd, char *buffer, int size) {
    int ret = write(fd, buffer, size);
    if (ret != size) {
        return -1;
    }

    return 0;
}

static int read_sysfs_val(const char* path, char* rBuf, const unsigned bufSz, int * readCnt) {
    int ret = 0;
    int fd  = -1;
    int count = 0;

    if (access(path, F_OK)) {
            printf("path[%s] not existed\n", path);
            return 1;
    }

    if (access(path, R_OK)) {
            printf("path[%s] cannot read\n", path);
            return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
            printf("fail in open[%s] in O_RDONLY\n", path);
            goto _exit;
    }

    count = read(fd, rBuf, bufSz);
    if (count <= 0) {
            printf("read %s failed (count:%d)\n", path, count);
            close(fd);
            return -1;
    }

    *readCnt = count;
    ret = 0;

_exit:
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}

static int getBootloaderOffset(int* bootloaderOffset) {
    const char* PathBlOff = "/sys/class/aml_store/bl_off_bytes" ;
    int             iret  = 0;
    char  buf[16]         = { 0 };
    int           readCnt = 0;

    iret = read_sysfs_val(PathBlOff, buf, 16, &readCnt);
    if (iret < 0) {
            printf("fail when read path[%s], default is 512\n", PathBlOff);
            *bootloaderOffset = 512;
            return 0;
    }
    buf[readCnt] = 0;
    *bootloaderOffset = atoi(buf);
    printf("bootloaderOffset is %s\n", buf);

    return 0;
}

static int _mmcblOffBytes = 0;

int bootloader_backup_update(int offset, int size) {

    int ret = -1;
    int len = 0;
    int readsz = 0;
    int writesz = 0;
    int fd = -1;
    int fd_boot0 = -1;
    int fd_boot1 = -1;
    char *tmpbuf = NULL;

    fd = open(MMCBLK_BOOTLOADER, O_RDWR);
    if (fd < 0) {
        printf("open %s failed\n", MMCBLK_BOOTLOADER);
        goto err;
    }

    fd_boot0 = open(MMCBLK_BOOT0, O_RDWR);
    if (fd_boot0 < 0) {
        printf("open %s failed\n", MMCBLK_BOOT0);
        goto err;
    }

    fd_boot1 = open(MMCBLK_BOOT1, O_RDWR);
    if (fd_boot1 < 0) {
        printf("open %s failed\n", MMCBLK_BOOT1);
        goto err;
    }

    ret = lseek(fd, offset, SEEK_SET);
    if (ret == -1) {
        printf("lseek %s failed\n", MMCBLK_BOOTLOADER);
        goto err;
    }

    ret = lseek(fd_boot0, offset, SEEK_SET);
    if (ret == -1) {
        printf("lseek %s failed\n", MMCBLK_BOOT0);
        goto err;
    }

    ret = lseek(fd_boot1, offset, SEEK_SET);
    if (ret == -1) {
        printf("lseek %s failed\n", MMCBLK_BOOT1);
        goto err;
    }

    tmpbuf = (char *)malloc(RW_MAX_SIZE);
    if (tmpbuf == NULL) {
        printf("malloc failed\n");
        goto err;
    }

    while (writesz < size) {
        readsz = (size - writesz) > RW_MAX_SIZE ? RW_MAX_SIZE : (size - writesz);
        readsz = read(fd, tmpbuf, readsz);
        if (readsz <= 0) {
            printf("readsz:%d\n", readsz);
            goto err;
        }

        len = write(fd_boot0, tmpbuf, readsz);
        if (len != readsz) {
            printf("len:%d\n", len);
            goto err;
        }

        len = write(fd_boot1, tmpbuf, readsz);
        if (len != readsz) {
            printf("len:%d\n", len);
            goto err;
        }

        writesz += len;
    }

    if (writesz == size) {
        ret = 0;
    }

err:
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }

    if (fd_boot0 >= 0) {
        close(fd_boot0);
        fd_boot0 = -1;
    }

    if (fd_boot1>= 0) {
        close(fd_boot1);
        fd_boot1 = -1;
    }

    if (tmpbuf != NULL) {
        free(tmpbuf);
        tmpbuf = NULL;
    }

    return ret;
}


char *rtrim(char *str) {
    if (str == NULL || *str == '\0') {
        return str;
    }

    int len = strlen(str);
    char *p = str + len - 1;
    while (p >= str  && isspace(*p)) {
        *p = '\0';
        --p;
    }

    return str;
}


char *ltrim(char *str) {
    if (str == NULL || *str == '\0') {
        return str;
    }

    int len = 0;
    char *p = str;
    while (*p != '\0' && isspace(*p)) {
        ++p;
        ++len;
    }
    memmove(str, p, strlen(str) - len + 1);
    return str;
}

char *trim(char *str)
{
    str = rtrim(str);
    str = ltrim(str);
    return str;
}

void update_conf_init() {
    int i = 0;

    for (i=0; i<g_num; i++) {
        memset(g_partition_list[i], 0, 24);
    }

    g_num = 0;
}

void update_conf_parse(char *conf_data) {
    update_conf_init();
    char* type = strtok(conf_data, " \n");
    printf("%s\n", type);
    if (type != NULL) {
        strcpy(g_partition_list[g_num], trim(type));
        g_num++;
    }

    while (1) {
        char* type1 = strtok(NULL, "\n");
        if (type1 != NULL) {
            printf("%s\n", type1);
            strcpy(g_partition_list[g_num], trim(type1));
            g_num++;
        } else {
            break;
        }
    }
}

int get_update_flag(char *name) {

    int i = 0;
    int ret = 0;

    if (g_num == 0) {
        return 1;
    }

    for (i=0; i<g_num; i++) {
        if (!strcmp(name, g_partition_list[i])) {
            ret = 1;
            break;
        }
    }

    return ret;
}

// Function to support size check and encrypted signed check
static unsigned long long get_block_device_size(int fd)
{
    unsigned long long size = 0;
    int ret;

    ret = ioctl(fd, BLKGETSIZE64, &size);
    if (ret) {
        return 0;
    }
    return size;
}

int IsPlatformEncryptedByIoctl(void)
{
    int ret = -1;
    unsigned int operation = 0;

    if (access(DEFEND_KEY, F_OK)) {
        printf("/dev/defendkey not exist");
        return -1;  // kernel doesn't support
    }

    int fd = open(DEFEND_KEY, O_RDWR);
    if (fd < 0) {
        printf("open %s failed!\n", DEFEND_KEY);
        return -1;
    }

    ret = ioctl(fd, CMD_SECURE_CHECK, &operation);
    close(fd);

    if (ret == 0) {
        printf("check platform: unencrypted\n");
    } else if (ret > 0) {
        printf("check platform: encrypted\n");
    } else {
        printf("check platform: failed\n");
    }

    return ret;
}

int ImageReadFromPackage(ITEMINFO_V2 *item, int fd, int readsize, char *buffer)
{
    int readlen = 0;
    int ret = lseek(fd, item->offsetInImage + item->curoffsetInItem, SEEK_SET);
    if (ret < 0) {
        printf("fseek failed [%s]\n", strerror(errno));
        return -1;
    }

    if (readsize + item->curoffsetInItem >= item->itemSz) {
        readlen = item->itemSz - item->curoffsetInItem;
    } else {
        readlen = readsize;
    }

    ret = read(fd, buffer, readlen);
    if (ret != readlen) {
        printf("Read item date error! Read item buffer failed! [%s]\n", strerror(errno));
        return -1;
    }
    item->curoffsetInItem += readlen;

    return readlen;
}

static int IsBootloaderImageEncrypted(const unsigned char *imageBuffer)
{
    const unsigned char *pImageAddr = imageBuffer;
    const unsigned char *pEncryptedBootloaderInfoBufAddr = NULL;

    // Don't modify. unencrypt bootloader info
    const int newbootloaderEncryptInfoOffset = 0x10;
    const unsigned char newunencryptedBootloaderInfoBuf[] = { 0x40, 0x41, 0x4D, 0x4C};

    //check image whether encrypted
    pEncryptedBootloaderInfoBufAddr = pImageAddr + newbootloaderEncryptInfoOffset;
    if (!memcmp(newunencryptedBootloaderInfoBuf, pEncryptedBootloaderInfoBufAddr,
                ARRAY_SIZE(newunencryptedBootloaderInfoBuf))) {
        printf("bootloader.img unencrypted\n");
        return 0; //unencrypted
    }

    printf("bootloader.img encrypted\n");
    return 1;  // encrypted
}

static int IsKernelImageEncrypted(const unsigned char *imageBuffer)
{
    const unsigned char *pImageAddr = imageBuffer;
    const unsigned char *pEncryptedKernelInfoBufAddr = NULL;

    // Don't modify. Encrypt Kernel info
    const int newKernelEncryptInfoOffset = 0x800;
    const unsigned char newEncryptedKernelInfoBuf[] = { 0x40, 0x41, 0x4D, 0x4C};

    //check image whether encrypted
    pEncryptedKernelInfoBufAddr = pImageAddr + newKernelEncryptInfoOffset;
    if (!memcmp(newEncryptedKernelInfoBuf, pEncryptedKernelInfoBufAddr,
                ARRAY_SIZE(newEncryptedKernelInfoBuf))) {
        printf("boot.img encrypted\n");
        return 1;  // encrypted
    }

    printf("boot.img unencrypted\n");
    return 0; //unencrypted
}

static int IsDtbImageEncrypted(const unsigned char *imageBuffer)
{
    const unsigned char *pImageAddr = imageBuffer;
    const unsigned char *pEncryptedDtbInfoBufAddr = NULL;

    // Don't modify. Encrypt DTB info
    const int newDtbEncryptInfoOffset = 0x0;
    const unsigned char newEncryptedDtbInfoBuf[] = { 0x40, 0x41, 0x4D, 0x4C};

    //check image whether encrypted
    pEncryptedDtbInfoBufAddr = pImageAddr + newDtbEncryptInfoOffset;
    if (!memcmp(newEncryptedDtbInfoBuf, pEncryptedDtbInfoBufAddr,
                ARRAY_SIZE(newEncryptedDtbInfoBuf))) {
        printf("dtb.img encrypted\n");
        return 1;  // encrypted
    }

    printf("dtb.img unencrypted\n");
    return 0; //unencrypted
}

// 1  -> match
// 0  -> not match
//-1 -> failed
static int IsImageSignedRight(ITEMINFO_V2 *item, int fd) {

    int  ret = 0;
    int  readSz = 0;
    int  imageSz = item->itemSz;

    char *buffer = (char *)malloc(imageSz);
    if (buffer == NULL) {
        printf("Malloc buffer(%d) failed\n", imageSz);
        return -1;
    }

    memset(buffer, 0, imageSz);

    readSz = ImageReadFromPackage(item, fd, imageSz, buffer);
    item->curoffsetInItem = 0;
    if (readSz != imageSz) {
        printf("Read image for check failed\n");
        free(buffer);
        return -1;
    }

    int fd_defend = open(DEFEND_KEY, O_RDWR);
    if (fd_defend < 0) {
        printf("open %s failed!\n", DEFEND_KEY);
        free(buffer);
        return -1;
    }

    ret = write(fd_defend, buffer, imageSz);
    close(fd_defend);
    free(buffer);
    printf("defendkey_write ret (%d)\n", ret);

    if (ret == 1) {
        return 1;//match
    } else if (ret == -2) {
        return 0;//not match
    } else {
        return -1;//failed
    }
}

int IsPartitionNeedUpdate(char *name)
{
    int i = 0;
    int ret = 0;

    if (g_num == 0) {
        return 1;
    }
    for (i=0; i<g_num; i++) {
        if (!strcmp(name, g_partition_list[i])) {
            ret = 1;
            break;
        }
    }
    return ret;
}

/***
 * @brief   : Worker thread to trigger the callback function for status update.
 * @info    : Spawned only if the mfrUpgradeStatusNotify_t.interval is not Zero.
 * @return  : NULL
 */
void* cbUpdateWorkerThread(void *pArgs)
{
    int percentage = 0;
    int sleepTime = cb_notify.interval;
    printf("cbUpdateWorkerThread: cb_notify.interval = %d percentage = %d\n",
            sleepTime, percentage);

    /* Trigger callback untill the % becomes 100. */
    while (percentage != 100) {
        sleep(((sleepTime)? sleepTime : 1));

        /* Calculate update percentage. Keep in mind - Chance for division by Zero ? */
        percentage = 0;
        if ((mfrUpgradeStatus.progress == mfrUPGRADE_PROGRESS_STARTED) && g_totalSz) {
            percentage = (int)(((g_writtenSz + g_sparseWriteSz) * 100)/g_totalSz);
        }

        /* 100% means all sequence is error free;
           which will be updated from main update routine. */
        if (cb_notify.cb && (mfrUpgradeStatus.percentage != 100)) {
            mfrUpgradeStatus.percentage = percentage;
            /* Trigger the callback by passing `mfrUpgradeStatus` buffer. */
            cb_notify.cb(mfrUpgradeStatus, cb_notify.cbData);
        } else {
            /* Only log when no callback registered to reduce load. */
            printf("[g_writtenSz/g_sparseWriteSz/g_totalSz/percentage] = [%llu/%llu/%llu/%d]\n",
                    g_writtenSz, g_sparseWriteSz, g_totalSz, percentage);
        }
    }
    printf("cbUpdateWorkerThread: exit triggered.\n");
}

/**
  * @brief      : sparse write status callback function
  * @param1[in] : pointer to destination
  * @param2[in] : sprase file write status
  * @return     : always return 0 since sparse library considers others as error.
  */
int updateWriteProgress(int64_t *pwriteLen, int64_t writeLen)
{
    if (pwriteLen) {
        *pwriteLen = writeLen;
    }
    return 0;
}

int install_aml_package(const char *path, mfrUpgradeStatusNotify_t upgradeStatus)
{
    int ret = 0;
    int itemSz = 0;
    int writeSz = 0;
    unsigned int i = 0;
    int bootloaderIndex = -1;
    int kernelIndex = -1;
    int dtbIndex = -1;
    int write_bytes = 0;
    struct sparse_file *s;
    unsigned int crc_32 = 0;
    char* unPackBuf = NULL;
    const char *_dtb = "_aml_dtb";
    char partition[NAME_SIZE_V2] = {0};
    IMG_HEAD m_amlImage;
    int iHeadSz = sizeof(IMG_HEAD);
    int iItemInfoSzV2 = sizeof(ITEMINFO_V2);
    ITEMINFO_V2  m_vecItemV2[MAX_PARTITIONS];
    int status = mfrERR_NONE;
    cbUpdateThreadCreated = false;
    pthread_t cbUpdateTID = -1;
    
    /* Reset the global progress track variables. */
    g_totalSz = 0;
    g_writtenSz = 0;
    g_sparseWriteSz = 1;

    cb_notify = upgradeStatus;

    if ((NULL == path) || (-1 == access(path, R_OK))) {
        printf("Usb package path[%s] is NULL or access R_OK failed.\n", path);
        status = mfrERR_UPDATE_PKG_ACCESS_FAILED;

        /* Update the status via callback. */
        if (cb_notify.cb) {
            mfrUpgradeStatus.progress = mfrUPGRADE_PROGRESS_ABORTED;
            mfrUpgradeStatus.error = status;
            mfrUpgradeStatus.percentage = 0;
            cb_notify.cb(mfrUpgradeStatus, cb_notify.cbData);
        }

        return status;
    } else {
        mfrUpgradeStatus.progress = mfrUPGRADE_PROGRESS_NOT_STARTED;
        mfrUpgradeStatus.error = 0;
        mfrUpgradeStatus.percentage = 0;
    }

    if (cb_notify.interval) {
        /* Periodic callback requested. */
        if (!pthread_create(&cbUpdateTID, NULL, cbUpdateWorkerThread, NULL)) {
            cbUpdateThreadCreated = true;
        } else {
            printf("pthread_create cbUpdateWorkerThread failed.");
        }
    } else {
        /* Final status update only is requested;
           Nothing to do here. */
    }

    //TODO: need to add logic to check if package is not existed??
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("Open update package %s failed\n", path);
        status = mfrERR_UPDATE_PKG_ACCESS_FAILED;
        goto StatusUpdateAndExit;
    }

    ret = lseek(fd, 0, SEEK_SET);
    if (ret == -1) {
        printf("Lseek offset 0 failed\n");
        status = mfrERR_SEEK_FAILED_FOR_UPDATE;
        goto StatusUpdateAndExit;
    }

    /* read aml_upgrade_package.img head */
    memset(&m_amlImage, 0, iHeadSz);
    if (read(fd, &m_amlImage, iHeadSz) != iHeadSz) {
        printf("Read %s failed [%s]\n", path, strerror(errno));
        status = mfrERR_UPDATE_PKG_ACCESS_FAILED;
        goto StatusUpdateAndExit;
    }

    /* check the image magic */
    if (IMAGE_MAGIC != m_amlImage.magic) {
        printf("Err aml pkg magic 0x%x\n", m_amlImage.magic);
        status = mfrERR_UPDATE_PKG_MAGIC_NUMBER_MALFORMED;
        goto StatusUpdateAndExit;
    }

    /* check the image version */
    if (VERSION_V2 != m_amlImage.verh.version) {
        printf("Err aml pkg verh.version 0x%x\n", m_amlImage.verh.version);
        status = mfrERR_UPDATE_PKG_VERSION_MISMATCH;
        goto StatusUpdateAndExit;
    }

    /* calculate crc32 and verify it */
    crc_32 = calc_img_crc(fd, 4);
    if (crc_32 != m_amlImage.verh.crc) {
        printf("Err aml pkg verh.crc 0x%x, but expect 0x%x\n", m_amlImage.verh.crc ,crc_32);
        status = mfrERR_UPDATE_PKG_CRC_FAILURE;
        goto StatusUpdateAndExit;
    }

    printf("Verify update package crc success\n");
    ret = lseek(fd, iHeadSz, SEEK_SET);
    if (ret == -1) {
        printf("Lseek offset ihead failed\n");
        status = mfrERR_SEEK_FAILED_FOR_UPDATE;
        goto StatusUpdateAndExit;
    }

    for (i = 0; i < m_amlImage.itemNum; ++i) {
        memset(&m_vecItemV2[i], 0, iItemInfoSzV2);
        if (read(fd, &m_vecItemV2[i], iItemInfoSzV2) != iItemInfoSzV2) {
            printf("Read v2 image info failed [%s]\n", strerror(errno));
            status = mfrERR_SEEK_FAILED_FOR_ITEMINFO;
            goto StatusUpdateAndExit;
        }
    }

    unPackBuf = (char *)malloc(RW_MAX_SIZE);
    if (unPackBuf == NULL) {
        printf("Malloc buffer(%d) failed\n", RW_MAX_SIZE);
        status = mfrERR_BUFFER_ALLOC_FAILED;
        goto StatusUpdateAndExit;
    }

    for (i = 0; i < m_amlImage.itemNum; ++i) {
        if (!strcmp(m_vecItemV2[i].itemSubType, "update")) {
            ret = image_read(&m_vecItemV2[i], fd, m_vecItemV2[i].itemSz, unPackBuf);
            if (ret < 0) {
                status = mfrERR_SEEK_FAILED_FOR_UPDATE;
                goto StatusUpdateAndExit;
            }
            update_conf_parse(unPackBuf);
        }
    }

    /* verify the sub-images size vs partition size and
       get total size for install percentage calculation. */
    for (i = 0, g_totalSz = 0; i < m_amlImage.itemNum; ++i) {
        if (!strcmp(m_vecItemV2[i].itemMainType, "PARTITION")) {
            if (!strcmp(m_vecItemV2[i].itemSubType, "bootloader")) {
                bootloaderIndex = i;
            } else if (!strcmp(m_vecItemV2[i].itemSubType, "boot") ||
                       !strcmp(m_vecItemV2[i].itemSubType, "boot_a")) {
                kernelIndex = i;
            }
            //dtb size is 256K
            if (!strcmp(m_vecItemV2[i].itemSubType, _dtb)) {
                if (m_vecItemV2[i].itemSz > 256*1024) {
                    printf("dt.img size(%llu) > 256K\n", m_vecItemV2[i].itemSz);
                    status = mfrERR_SEEK_FAILED_FOR_UPDATE;
                    goto StatusUpdateAndExit;
                }
                dtbIndex = i;
                continue;
            }

            //others
            char tmp_path[128] = {'\0'};
            sprintf(tmp_path, "/dev/%s", m_vecItemV2[i].itemSubType);
            int tmp_fd = open(tmp_path, O_RDWR);
            if (tmp_fd < 0) {
                printf("Open %s failed, skip to next...\n", tmp_path);
                continue;
            }

            unsigned long long device_size = get_block_device_size(tmp_fd);
            if (device_size == 0) {
                printf("Get %s size failed, skip to next...\n", tmp_path);
                close(tmp_fd);
                continue;
            }
            close(tmp_fd);

            /* "unsigned long long" will be overflowed by a large sparse file. For example, */
            /* blk_sz (0x1000) * total_blks (0x11_21e0) = 0x1_121e_0000 will become 0x121e_0000 */
            /* So use "double" here. */
            double real_img_size = m_vecItemV2[i].itemSz;
            if (m_vecItemV2[i].fileType == IMAGE_ITEM_TYPE_SPARSE) {
                memset(unPackBuf, 0, RW_MAX_SIZE);
                int readlen = ImageReadFromPackage(&m_vecItemV2[i], fd, sizeof(sparse_header_t), unPackBuf);
                m_vecItemV2[i].curoffsetInItem = 0;
                if (readlen == sizeof(sparse_header_t)) {
                    sparse_header_t *sh = (sparse_header_t *) unPackBuf;
                    real_img_size = sh->blk_sz * (double)sh->total_blks;
                } else {
                    status = mfrERR_SEEK_FAILED_FOR_UPDATE;
                    goto StatusUpdateAndExit;
                }
            }

            printf("check image size(%.0llf)  partition size(%llu)\n", real_img_size, device_size);
            if (real_img_size > device_size) {
                printf("check image size(%.0llf) > partition size(%llu)\n", real_img_size, device_size);
                status = mfrERR_SEEK_FAILED_FOR_UPDATE;
                goto StatusUpdateAndExit;
            }

            /* Calculate the total write size for progress percentage. */
            if (m_vecItemV2[i].fileType == IMAGE_ITEM_TYPE_SPARSE) {
                /* Sparse file gets expanded to max drive size?. */
                g_totalSz += device_size;
            } else {
                g_totalSz += m_vecItemV2[i].itemSz;
            }
        }
    }

    printf("Estimated size values [g_writtenSz/g_totalSz] = [%llu/%llu]\n", g_writtenSz, g_totalSz);
    
    //check bootloader.img is encrypted match withe encryped board
    ret = IsPlatformEncryptedByIoctl();
    if (ret >= 0) {
        if (bootloaderIndex >= 0) {
            memset(unPackBuf, 0, RW_MAX_SIZE);
            int readlen = ImageReadFromPackage(&m_vecItemV2[bootloaderIndex], fd, RW_MAX_SIZE, unPackBuf);
            m_vecItemV2[bootloaderIndex].curoffsetInItem = 0;
            if (readlen == RW_MAX_SIZE) {
                int isencrypt = IsBootloaderImageEncrypted((const unsigned char *)unPackBuf);
                if (((ret == 0) && (isencrypt == 1)) || ((ret > 0) && (isencrypt == 0))) {
                    printf("Verify failed, the encrypt of bootloader.img dismatch with the board\n");
                    close(fd);
                    free(unPackBuf);
                    unPackBuf = NULL;
                    status = mfrERR_SPARSEIMAGE_ENCRYPTION_MISMATCH;
                    goto StatusUpdateAndExit;
                } else if (isencrypt == 1 && 1 != IsImageSignedRight(&m_vecItemV2[bootloaderIndex], fd)) {
                    printf("Bad signed bootloader.img\n");
                    close(fd);
                    free(unPackBuf);
                    unPackBuf = NULL;
                    status = mfrERR_SPARSEIMAGE_ENCRYPTION_MISMATCH;
                    goto StatusUpdateAndExit;
                }
            }
        }
        if (kernelIndex >= 0) {
            memset(unPackBuf, 0, RW_MAX_SIZE);
            int readlen = ImageReadFromPackage(&m_vecItemV2[kernelIndex], fd, RW_MAX_SIZE, unPackBuf);
            m_vecItemV2[kernelIndex].curoffsetInItem = 0;
            if (readlen == RW_MAX_SIZE) {
                int isencrypt = IsKernelImageEncrypted((const unsigned char *)unPackBuf);
                if (((ret == 0) && (isencrypt == 1)) || ((ret > 0) && (isencrypt == 0))) {
                    printf("Verify failed, the encrypt of boot.img dismatch with the board\n");
                    close(fd);
                    free(unPackBuf);
                    unPackBuf = NULL;
                    status = mfrERR_SPARSEIMAGE_ENCRYPTION_MISMATCH;
                    goto StatusUpdateAndExit;
                } else if (isencrypt == 1 && 1 != IsImageSignedRight(&m_vecItemV2[kernelIndex], fd)) {
                    printf("Bad signed boot.img\n");
                    close(fd);
                    free(unPackBuf);
                    unPackBuf = NULL;
                    status = mfrERR_SPARSEIMAGE_ENCRYPTION_MISMATCH;
                    goto StatusUpdateAndExit;
                }
            }
        }
        if (dtbIndex >= 0) {
            memset(unPackBuf, 0, RW_MAX_SIZE);
            int readlen = ImageReadFromPackage(&m_vecItemV2[dtbIndex], fd, RW_MAX_SIZE, unPackBuf);
            m_vecItemV2[dtbIndex].curoffsetInItem = 0;
            if (readlen <= RW_MAX_SIZE) {
                int isencrypt = IsDtbImageEncrypted((const unsigned char *)unPackBuf);
                if (((ret == 0) && (isencrypt == 1)) || ((ret > 0) && (isencrypt == 0))) {
                    printf("Verify failed, the encrypt of dtb.img dismatch with the board\n");
                    close(fd);
                    free(unPackBuf);
                    unPackBuf = NULL;
                    status = mfrERR_SPARSEIMAGE_ENCRYPTION_MISMATCH;
                    goto StatusUpdateAndExit;
                } else if (isencrypt == 1 && 1 != IsImageSignedRight(&m_vecItemV2[dtbIndex], fd)) {
                    printf("Bad signed dtb.img\n");
                    close(fd);
                    free(unPackBuf);
                    unPackBuf = NULL;
                    status = mfrERR_SPARSEIMAGE_ENCRYPTION_MISMATCH;
                    goto StatusUpdateAndExit;
                }
            }
        }
    } else {
// SC2 platform kernel doesn't support secure check
#if 0
        /* ABORT !!! DEFEND_KEY access failed/not supported. */
        printf("IsPlatformEncryptedByIoctl check failed(%d), aborting...\n", ret);
        close(fd);
        free(unPackBuf);
        unPackBuf = NULL;
        status = mfrERR_SPARSEIMAGE_ENCRYPTION_MISMATCH;
        goto StatusUpdateAndExit;
#endif
    }

    ret = lseek(fd, iHeadSz + iItemInfoSzV2*(m_amlImage.itemNum), SEEK_SET);
    if (ret == -1) {
        printf("Lseek offset ihead and iteminfo failed\n");
        status = mfrERR_SEEK_FAILED_FOR_ITEMINFO;
        goto StatusUpdateAndExit;
    }

    // start to write sub images based on the CONF
    /* Update the status via callback. */
    mfrUpgradeStatus.progress = mfrUPGRADE_PROGRESS_STARTED;
    mfrUpgradeStatus.error = status;
    mfrUpgradeStatus.percentage = 0;
    if (cb_notify.cb) {
        if (0 == cb_notify.interval) {
            cb_notify.cb(mfrUpgradeStatus, cb_notify.cbData);
        } else {
            /* Nothing to do here; cbUpdateWorkerThread will take care. */
        }
    } else {
        /* Nothing to do here. */
    }

    int _cur_active_slot;
    int bootloader_ret;
    bootloader_ret = get_system_type();
    bootloader_ret = get_active_slot_misc(&_cur_active_slot);

    if (_cur_active_slot == 0) {
       printf ("Active slot from misc is boot_a\n");
    }
    else {
       printf ("Active slot from misc is boot_b\n");
    }

    for (i = 0; i < m_amlImage.itemNum; ++i) {
        if (!strcmp(m_vecItemV2[i].itemMainType, "PARTITION")) {

            if (!get_update_flag(m_vecItemV2[i].itemSubType)) {
                printf("No need to update '%s'\n", m_vecItemV2[i].itemSubType);
                continue;
            }

            if (!strcmp(m_vecItemV2[i].itemSubType, _dtb)) {
                sprintf(partition, "/dev/dtb");
            } else {
                sprintf(partition, "/dev/%s", m_vecItemV2[i].itemSubType);
            }

            //TODO: add logic here to write inactive slots
            if (_cur_active_slot == 0) {
            // write to boot_b and system_b
               if (!strcmp(partition, "/dev/boot_a")) {
                  sprintf(partition,"/dev/boot_b");
               }
               else if (!strcmp(partition, "/dev/system_a")) {
                  sprintf(partition,"/dev/system_b");
               }
               else if (!strcmp(partition, "/dev/vendor_a")) {
                  sprintf(partition,"/dev/vendor_b");
               }
#ifdef AVB
               if (!strcmp(partition, "/dev/vbmeta_a")) {
                   sprintf(partition,"/dev/vbmeta_b");
               }
#endif
            }
            else {
            // write to boot_a and system_a
               if (!strcmp(partition, "/dev/boot_b")) {
                  sprintf(partition, "/dev/boot_a");
               }
               else if (!strcmp(partition, "/dev/system_b")) {
                  sprintf(partition, "/dev/system_a");
               }
               else if (!strcmp(partition, "/dev/vendor_b")) {
                  sprintf(partition, "/dev/vendor_a");
               }
#ifdef AVB
               if (!strcmp(partition, "/dev/vbmeta_b")) {
                   sprintf(partition,"/dev/vbmeta_a");
               }
#endif
            }
            printf ("burning partition: %s\n", partition);
            int fd_out = open(partition, O_RDWR);
            if (fd_out < 0) {
                printf("Open file %s for write failed\n", partition);
                status = mfrERR_BURN_FAILED_PARTITION;
                break;
            }

            if (!strcmp(m_vecItemV2[i].itemSubType, "bootloader")) {
                getBootloaderOffset(&_mmcblOffBytes);
                ret = lseek(fd_out, _mmcblOffBytes, SEEK_SET);
                if (ret == -1) {
                    /* TODO: What if this fails ? */
                    /* Logic should take care that following code
                       should not cause any issue if executed. */
                    printf("Lseek offset for bootloader failed\n");
                    status = mfrERR_BURN_FAILED_BOOTLOADER;
                    break;
                }
            }

            itemSz = m_vecItemV2[i].itemSz;
            writeSz = 0;

            if (m_vecItemV2[i].fileType == IMAGE_ITEM_TYPE_NORMAL) {
                while (writeSz < itemSz)
                {
                    write_bytes = image_read(&m_vecItemV2[i], fd, RW_MAX_SIZE, unPackBuf);
                    ret = normal_image_update(fd_out, unPackBuf, write_bytes);
                    if (ret != 0) {
                        break;
                    }

                    writeSz += write_bytes;
                    /* Upgdate progress percentage */
                    g_writtenSz += write_bytes;
				}

                if (writeSz != itemSz) {
                    close(fd_out);
                    status = mfrERR_NORMALIMAGE_UPDATE_FAILED;
                    break;
                }

                if (!strcmp(m_vecItemV2[i].itemSubType, "bootloader")) {
                    //need write bootloader backup, /dev/block/mmcblk0boot0&1
                    ret = bootloader_backup_update(itemSz, _mmcblOffBytes);
                    if (ret != 0) {
                        status = mfrERR_NORMALIMAGE_BOOTLOADER_BKUP_FAILED;
                        break;
                    }
                    /* Upgdate progress percentage */
                    g_writtenSz += _mmcblOffBytes;
                }
            } else if (m_vecItemV2[i].fileType == IMAGE_ITEM_TYPE_SPARSE) {
                //TODO: add logic for checking Active Slot
                int cur_offset = m_vecItemV2[i].offsetInImage + m_vecItemV2[i].curoffsetInItem;
                ret = lseek(fd, cur_offset, SEEK_SET);
                if (ret == -1) {
                    printf("Lseek offset %d failed\n", cur_offset);
                    status = mfrERR_SPARSEIMAGE_SEEK_FAILED;
                    break;
                }

                s = sparse_file_import(fd, cur_offset, true, false);
                if (!s) {
                    printf("Failed to read sparse file\n");
                    status = mfrERR_SPARSEIMAGE_IMPORT_FAILED;
                    break;
                }

                if (sparse_file_write_with_progress_cb(s, fd_out, false, false, false,
							updateWriteProgress, &g_sparseWriteSz) < 0) {
					printf("Write partition data failed\n");
                    status = mfrERR_SPARSEIMAGE_WRITE_FAILED;
                    break;
				}

                sparse_file_destroy(s);
            }

            close(fd_out);
        }
    }

    printf("Package write completed [percent/g_writtenSz/g_totalSz](g_sparseWriteSz) = [%llu/%llu/%llu](%llu)\n",
            (((g_writtenSz + g_sparseWriteSz) * 100)/g_totalSz), g_writtenSz, g_totalSz, g_sparseWriteSz);

    if (status == mfrERR_NONE) {
        //ui->SetProgress(1.0);
       printf ("Install completed and Success!\n");
       if (_cur_active_slot == 0) {
          printf ("Set active slot to boot_b after reboot\n");
          bootloader_ret = set_active_slot(1);
       }
       else {
          printf ("Set active slot to boot_a after reboot\n");
          bootloader_ret = set_active_slot(0);
       }
    }

    update_conf_init();

StatusUpdateAndExit:
    if (-1 != fd) {
        close(fd);
    }
    if (unPackBuf) {
        free(unPackBuf);
        unPackBuf = NULL;
    }

    if (cb_notify.interval && cbUpdateThreadCreated) {
        if (pthread_cancel(cbUpdateTID)) {
            printf("pthread_cancel cbUpdateTID = 0x%x failed.\n", (unsigned int)cbUpdateTID);
        }
        pthread_join(cbUpdateTID, NULL);
    }

    /* Update the status via callback. */
    if (cb_notify.cb) {
        mfrUpgradeStatus.progress = ((status == mfrERR_NONE)?
                mfrUPGRADE_PROGRESS_COMPLETED: mfrUPGRADE_PROGRESS_ABORTED);
        mfrUpgradeStatus.error = status;
        mfrUpgradeStatus.percentage = ((status == mfrERR_NONE)? (int)(((g_writtenSz + g_sparseWriteSz) * 100)/g_totalSz) : 0);
        cb_notify.cb(mfrUpgradeStatus, cb_notify.cbData);
    } else {
        printf("Install completed [progress/error/percentage] = [%d/%d/%d]\n", ((status == mfrERR_NONE)?
                mfrUPGRADE_PROGRESS_COMPLETED: mfrUPGRADE_PROGRESS_ABORTED), status,
                ((status == mfrERR_NONE)? (int)(((g_writtenSz + g_sparseWriteSz) * 100)/g_totalSz) : 0));
    }

    return status;
}

