#include <stdio.h>
#include "mfr_wifi_types.h"
#include "mfr_wifi_api.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static const char g_wifi_credentials_filename[] = "/home/root/wifi_credentials.config";

/** Read a number of chars from an open file descriptor
* @param [in] fd an open file descriptor
* @param [out] write_ptr where to write the data to
* @param [in] size number of chars to read
*/
static WIFI_API_RESULT read_from_file(int fd, char *write_ptr, ssize_t size)
{
    const char *const end_ptr = &write_ptr[size];
    ssize_t bytes_read = 0;
    do {
        bytes_read = read(fd, write_ptr, end_ptr - write_ptr);
        if (bytes_read != -1) {
            write_ptr += bytes_read;
        } else if ((errno != EAGAIN) || (errno != EINTR)) {
            perror("read_from_file() error:");
            break;
        }
    } while (bytes_read != 0);

    if (write_ptr != end_ptr) {
        printf("WARNING: only read: %ld chars\n", size + write_ptr - end_ptr);
        return WIFI_API_RESULT_FAILED; /* failed to read all data */
    }
    return WIFI_API_RESULT_SUCCESS;
}

/**
 * @brief
 *
 * @param None
 * @return    Error Code.
 * @retval    ::WIFI_API_RESULT
 */
WIFI_API_RESULT WIFI_GetCredentials(WIFI_DATA *pData)
{
    WIFI_API_RESULT rc = WIFI_API_RESULT_SUCCESS;
    int fd = -1;

    if (pData == NULL) {
        rc = WIFI_API_RESULT_INVALID_PARAM;
    } else {
        fd = open(g_wifi_credentials_filename, O_RDONLY);
        if (fd <= 0) {
            printf("Could not open file: %s\n", g_wifi_credentials_filename);
            perror("WIFI_GetCredentials() error");
            rc = WIFI_API_RESULT_FAILED;
        }
    }

    if (rc == WIFI_API_RESULT_SUCCESS) {
        rc = read_from_file(fd, &pData->cSSID[0], sizeof(pData->cSSID));
        if (rc == WIFI_API_RESULT_SUCCESS) {
            rc = read_from_file(fd, &pData->cPassword[0], sizeof(pData->cPassword));
        }
        close(fd);
    }

    if (pData) {
        if (rc != WIFI_API_RESULT_SUCCESS) {
            pData->cSSID[0] = '\0';
            pData->cPassword[0] = '\0';
            rc = WIFI_API_RESULT_SUCCESS; /* always suceed if pData!=nullptr */
            printf("WARNING: using defaults WIFI_GetCredentials(SSID:'%s', password:'%s')\n",
                    pData->cSSID, pData->cPassword);
        } else {
            printf("WIFI_GetCredentials(SSID:'%s', password:'%s')\n",
                    pData->cSSID, pData->cPassword);
        }
    }
    return rc;
}

/** Write a number of chars to an open file descriptor
 * @pre fd is open and writable
 * @param [in] fd an open file descriptor
 * @param [out] read_ptr where to read the data from
 * @param [in] size number of chars to read from read_ptr
 */
static WIFI_API_RESULT write_to_file(int fd, const char *read_ptr, ssize_t size)
{
    const char *const end_ptr = &read_ptr[size];
    ssize_t bytes_written = 0;
    do {
        bytes_written = write(fd, read_ptr, end_ptr - read_ptr);
        if (-1 != bytes_written) {
            read_ptr += bytes_written;
        } else if ((errno != EAGAIN) || (errno != EINTR)) {
            perror("write_to_file() error:");
            break;
        }
    } while (bytes_written != 0);

    if (read_ptr != end_ptr) {
        printf("WARNING: only wrote: %ld chars\n", size + read_ptr - end_ptr);
        return WIFI_API_RESULT_FAILED; /* failed to write all data */
    }
    return WIFI_API_RESULT_SUCCESS;
}

/**
 * @brief
 *
 * @param None
 * @return    Error Code.
 * @retval    ::WIFI_API_RESULT
 */
WIFI_API_RESULT WIFI_SetCredentials(WIFI_DATA *pData)
{
    WIFI_API_RESULT rc = WIFI_API_RESULT_SUCCESS;
    int fd = -1;

    if (pData == NULL) {
        rc = WIFI_API_RESULT_INVALID_PARAM;
    } else {
        fd = open(g_wifi_credentials_filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd <= 0) {
            printf("Could not open file: %s\n", g_wifi_credentials_filename);
            perror("Error: ");
            rc = WIFI_API_RESULT_FAILED;
        }
    }

    if (rc == WIFI_API_RESULT_SUCCESS) {
        WIFI_DATA data_to_write;
        memset(&data_to_write, 0, sizeof(data_to_write));
        snprintf(data_to_write.cSSID, sizeof(data_to_write.cSSID), "%s", pData->cSSID);
        snprintf(data_to_write.cPassword, sizeof(data_to_write.cPassword), "%s", pData->cPassword);

        rc = write_to_file(fd, &data_to_write.cSSID[0], sizeof(data_to_write.cSSID));
        if (rc == WIFI_API_RESULT_SUCCESS) {
            rc = write_to_file(fd, &data_to_write.cPassword[0], sizeof(data_to_write.cPassword));
        }
        close(fd);
    }
    return rc;
}


#if 0

int main()
{
    WIFI_DATA wifi_data;
    WIFI_DATA write_wifi_data = { "00040008001200160020002400280032",
        "0004000800120016002000240028003200360040004400480052005600600064" };
    printf("> Test no file\n");

    remove(g_wifi_credentials_filename);
    WIFI_API_RESULT rc = WIFI_GetCredentials(&wifi_data);
    printf("- rc:%d\n", rc);
    printf("> Test no file2\n");
    rc = WIFI_GetCredentials(&wifi_data);
    printf("- rc:%d\n", rc);


    printf("> Test write data\n");
    rc = WIFI_SetCredentials(&write_wifi_data);
    printf("- rc:%d\n", rc);

    printf("> Test read\n");
    rc = WIFI_GetCredentials(&wifi_data);
    printf("- rc:%d\n", rc);
    printf("wr.ssid:'%s' wr.password:'%s'\n", write_wifi_data.cSSID, write_wifi_data.cPassword);
    printf("rd.ssid:'%s' rd.password:'%s'\n", wifi_data.cSSID, wifi_data.cPassword);

    int fd = open(g_wifi_credentials_filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd <= 0) {
        printf("Could not open file: %s\n", g_wifi_credentials_filename);
        perror("Error: ");
        rc = WIFI_API_RESULT_FAILED;
    } else {
        write_to_file(fd, "short", 6);
    }
    printf("> Test read truncated file\n");
    rc = WIFI_GetCredentials(&wifi_data);
    printf("- rc:%d\n", rc);
    printf("wr.ssid:'%s' wr.password:'%s'\n", write_wifi_data.cSSID, write_wifi_data.cPassword);
    printf("rd.ssid:'%s' rd.password:'%s'\n", wifi_data.cSSID, wifi_data.cPassword);
}

#endif
