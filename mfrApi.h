/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _MFR_TYPES_H
#define _MFR_TYPES_H

#include <stdlib.h>
#include <stdint.h>

typedef enum _mfrError_t {
    mfrERR_NONE = 0,
    mfrERR_GENERAL = 0x1000,
    mfrERR_INVALID_PARAM,
    mfrERR_INVALID_STATE,
    mfrERR_OPERATION_NOT_SUPPORTED,
    mfrERR_UNKNOWN,
    /* BSP/OEM Specific Error Codes */
    mfrERR_BUFFER_ALLOC_FAILED = 0x2000,
    mfrERR_UPDATE_PKG_ACCESS_FAILED,
    mfrERR_UPDATE_PKG_MAGIC_NUMBER_MALFORMED,
    mfrERR_UPDATE_PKG_VERSION_MISMATCH,
    mfrERR_UPDATE_PKG_CRC_FAILURE,
    mfrERR_SEEK_FAILED_FOR_UPDATE,
    mfrERR_SEEK_FAILED_FOR_ITEMINFO,
    mfrERR_BURN_FAILED_PARTITION,
    mfrERR_BURN_FAILED_BOOTLOADER,
    mfrERR_NORMALIMAGE_UPDATE_FAILED,
    mfrERR_NORMALIMAGE_BOOTLOADER_BKUP_FAILED,
    mfrERR_SPARSEIMAGE_SEEK_FAILED,
    mfrERR_SPARSEIMAGE_IMPORT_FAILED,
    mfrERR_SPARSEIMAGE_WRITE_FAILED,
    mfrERR_SPARSEIMAGE_ENCRYPTION_MISMATCH,
} mfrError_t;

typedef struct _mfrSerializedData_t {
    char * buf;                        // buffer containing the data read.
    size_t bufLen;                     // length of the data buffer;
    void (* freeBuf) (char *buf);      // function used to free the buffer. If NULL, the user does not need to free the buffer.
} mfrSerializedData_t;

typedef enum _mfrSerializedType_t {
    mfrSERIALIZED_TYPE_MANUFACTURER = 0,
    mfrSERIALIZED_TYPE_MANUFACTUREROUI,
    mfrSERIALIZED_TYPE_MODELNAME,
    mfrSERIALIZED_TYPE_DESCRIPTION,
    mfrSERIALIZED_TYPE_PRODUCTCLASS,
    mfrSERIALIZED_TYPE_SERIALNUMBER,
    mfrSERIALIZED_TYPE_HARDWAREVERSION,
    mfrSERIALIZED_TYPE_SOFTWAREVERSION,
    mfrSERIALIZED_TYPE_PROVISIONINGCODE,
    mfrSERIALIZED_TYPE_FIRSTUSEDATE,
    mfrSERIALIZED_TYPE_DEVICEMAC,
    mfrSERIALIZED_TYPE_MOCAMAC,
    mfrSERIALIZED_TYPE_HDMIHDCP,
    mfrSERIALIZED_TYPE_PDRIVERSION,
    mfrSERIALIZED_TYPE_WIFIMAC,
    mfrSERIALIZED_TYPE_BLUETOOTHMAC,
    mfrSERIALIZED_TYPE_CHIPSETINFO,
    mfrSERIALIZED_TYPE_MAX,
} mfrSerializedType_t;

typedef enum _mfrImageType_t {
    mfrIMAGE_TYPE_CDL,
    mfrIMAGE_TYPE_RCDL,
} mfrImageType_t;

typedef enum _mfrUpgradeProgress_t {
  mfrUPGRADE_PROGRESS_NOT_STARTED = 0,
  mfrUPGRADE_PROGRESS_STARTED,
  mfrUPGRADE_PROGRESS_ABORTED,
  mfrUPGRADE_PROGRESS_COMPLETED,
} mfrUpgradeProgress_t;

typedef struct _mfrUpgradeStatus_t {
  mfrUpgradeProgress_t progress;
  mfrError_t error;
  int percentage;
} mfrUpgradeStatus_t;

typedef struct _mfrUpgradeStatusNotify_t {
    void * cbData;
    void (*cb) (mfrUpgradeStatus_t status, void *cbData);
    int interval; // number of seconds between two callbacks. 0 means invoking callback only once to report final upgrade result.
} mfrUpgradeStatusNotify_t;


/**
 * @brief Initialize the mfr library.
 * This function should be call once before the functions in this API can be used.
 *
 * @param [in]  :  None.
 * @param [out] :  None.
 *
 * @return Error Code:  If error code is returned, the init has failed.
 */
mfrError_t mfr_init( void );


/**
 * @brief Retrieve Serialized Read-Only data from device.  The serialized data is returned as a byte stream. It is upto the
 * application to deserialize and make sense of the data returned.   Please note that even if the serialized data returned is
 * "string", the buffer is not required to contain the null-terminator
 *
 * @param [in] type:  specifies the serialized data to read.
 * @param [in]data:  contains information about the returned data (buffer location, length, and func to free the buffer).
 *
 * @return Error Code:  If error code is returned, the read has failed and values in data should not be used.
 */
mfrError_t mfrGetSerializedData( mfrSerializedType_t type,  mfrSerializedData_t *data );

/**
* @brief Validate and  Write the image into flash.  The process should follow these major steps:
*    1) Validate headers, manufacturer, model.
*    2) Perform Signature check.
*    3) Flash the image.
*    4) Perform CRC on flashed nvram.
*    5) Update boot params and switch banks to prepare for a reboot event.
*    6) All upgrades should be done in the alternate bank. The current bank should not be disturbed at any cost.
*         i.e. a second upgrade will before a reboot will overwrite the non-current bank only.
*
*    State Transition:
*    0) Before the API is invoked, the Upgrade process should be in PROGRESS_NOT_STARTED state.
*    1) After the API returnes with success, the Upgrade process moves to PROGRESS_STARTED state.
*    2) After the API returnew with error,   the Upgrade process stays in PROGRESS_NO_STARTED state. Notify function will not be invoked.
*    3) The notify function is called at regular interval with proress = PROGRESS_STARTED.
*    4) The last invocation of notify function should have either progress = PROGRESS_COMPLETED or progress = PROGRESS_ABORTED with error code set.
*
* @param [in] name:  the path of the image file in the STB file system.
* @param [in] path:  the filename of the image file.
* @param [in] type:  the type (e.g. format, signature type) of the image.  This can dictate the handling of the image within the MFR library.
* @param[in] callback: function to provide status of the image flashing process.
* @return Error Code:  If error code is returned, the image flashing is not initiated..
*/
mfrError_t mfrWriteImage(const char *name,  const char *path, mfrImageType_t type,  mfrUpgradeStatusNotify_t notify);

/**
* @brief Delete the P-DRI image if it is present
*
* @return Error Code:  Return mfrERR_NONE if P-DRI is succesfully deleted or not present, mfrERR_GENERAL if deletion fails
*/
mfrError_t mfrDeletePDRI(void);

/**
* @brief Delete the platform images
*
* @return Error Code:  Return mfrERR_NONE if the images are scrubbed, mfrERR_GENERAL if scrubbing fails
*/
mfrError_t mfrScrubAllBanks(void);

/**
* @brief    Initialization for platform firmware Upgrade sequence
* @return   Dummy; always returns mfrERR_NONE
*/
mfrError_t mfrFWUpgradeInit(void);

/**
* @brief    Termination for platform firmware Upgrade sequence
* @return   Dummy; always returns mfrERR_NONE
*/
mfrError_t mfrFWUpgradeTerm(void);

/**
* @brief    Free the allocated buffers
*
* @return Void
*/
void mfrFreeBuffer(char *buf);

/**
* @brief    Loging system for debug
*
* @return   Void
*/
void mfrlib_log(const char *format, ...);

#endif

