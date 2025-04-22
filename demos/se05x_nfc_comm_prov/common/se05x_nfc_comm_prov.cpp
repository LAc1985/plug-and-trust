/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <errno.h>
#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <stdio.h>
#include <string.h>
#include "se05x_APDU.h"

#define FABRIC_ACL_ID       0x7D300013
#define FABRIC_GROUP_ID     0x7D300014
#define FABRIC_ICAC_ID      0x7D300015
#define FABRIC_KEYSET_ID    0x7D300016
#define FABRIC_METADATA_ID  0x7D300017
#define FABRIC_NOC_ID       0x7D300018
#define FABRIC_KEY          0x7D300019
#define FABRIC_RCAC_ID      0x7D300020
#define FABRIC_SESSION_ID   0x7D300021
#define FABRIC_INDEX_ID     0x7D300022
#define FABRIC_RES_ID       0x7D300023

#define CT_CONF_PATH  "/tmp/chip_tool_config.alpha.ini"

static ex_sss_boot_ctx_t gex_sss_nfc_comm_prov_ctx;

static sss_status_t write_config_data(const char *file_path,  const char *file_data)
{
    sss_status_t status = kStatus_SSS_Success;
    FILE *file = NULL;

    if(access(file_path,  F_OK) == 0) {
        if(remove(file_path) != 0) {
            LOG_E("Failed to remove File:%s\n",  file_path);
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }

    file=fopen(file_path,  "wb");
    if(!file) {
        LOG_E("Failed to open file %s",  file_path);
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    if(fwrite(file_data,  1,  strlen(file_data),  file) != strlen(file_data)) {
        LOG_E("Failed to write file_data");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

cleanup:
    if(file) {
        fclose(file);
    }
    return status;
}

void se05x_delete_key(uint32_t keyid) {

    smStatus_t smstatus   = SM_NOT_OK;
    SE05x_Result_t exists = kSE05x_Result_NA;

    if (gex_sss_nfc_comm_prov_ctx.ks.session != NULL)
    {
        smstatus = Se05x_API_CheckObjectExists(&((sss_se05x_session_t *) &gex_sss_nfc_comm_prov_ctx.session)->s_ctx, keyid, &exists);
        if (smstatus == SM_OK)
        {
            if (exists == kSE05x_Result_SUCCESS)
            {
                smstatus = Se05x_API_DeleteSecureObject(&((sss_se05x_session_t *) &gex_sss_nfc_comm_prov_ctx.session)->s_ctx, keyid);
                if (smstatus != SM_OK)
                {
                    LOG_E("Error in deleting key");
                }
            }
            else
            {
                LOG_E("Key doesnot exists");
            }
        }
        else
        {
            LOG_E("Error in Se05x_API_CheckObjectExists");
        }
    }
    return;
}

static sss_status_t se05xSetBinaryData(sss_key_store_t *keyStore,  uint32_t keyId,  const uint8_t *buf,  size_t buflen)
{
    sss_object_t keyObject = { 0 };
    sss_status_t status = kStatus_SSS_Fail;

    se05x_delete_key(keyId);

    status = sss_key_object_init(&keyObject,  keyStore);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyObject,  keyId,  kSSS_KeyPart_Default,  kSSS_CipherType_Binary,  buflen, 
                                            kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_set_key(keyStore,  &keyObject,  buf,  buflen,  buflen * 8,  NULL,  0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    sss_key_object_free(&keyObject);
    return status;

}

static sss_status_t se05xSetEcKey(sss_key_store_t *keyStore, uint32_t keyId, const uint8_t *buf, size_t buflen)
{
   sss_status_t status = kStatus_SSS_Fail;
   sss_object_t keyObject = { 0 };

   se05x_delete_key(keyId);

   status = sss_key_object_init(&keyObject, keyStore);
   ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

   status = sss_key_object_allocate_handle(&keyObject, keyId, kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, buflen, kKeyObject_Mode_Persistent);
   ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
   
   status = sss_key_store_set_key(keyStore, &keyObject, buf, buflen, 256 , NULL, 0);
   ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
   sss_key_object_free(&keyObject);
   return status;
}

void se05xReset() {

    se05x_delete_key(FABRIC_ACL_ID);
    se05x_delete_key(FABRIC_GROUP_ID);
    se05x_delete_key(FABRIC_ICAC_ID);
    se05x_delete_key(FABRIC_KEYSET_ID);
    se05x_delete_key(FABRIC_METADATA_ID);
    se05x_delete_key(FABRIC_NOC_ID);
    se05x_delete_key(FABRIC_KEY);
    se05x_delete_key(FABRIC_SESSION_ID);
    se05x_delete_key(FABRIC_RCAC_ID);
    se05x_delete_key(FABRIC_INDEX_ID);
    se05x_delete_key(FABRIC_RES_ID);

    if(access(CT_CONF_PATH,  F_OK) == 0) {
        if(remove(CT_CONF_PATH) != 0) {
            LOG_E("Failed to remove File:%s\n",  CT_CONF_PATH);
            return;
        }
    }

    LOG_I("Reset Success !");
}

void se05x_nfc_comm_prov(bool doReset)
{
    sss_status_t status = kStatus_SSS_Success;
    const char *portName = nullptr;
    ex_sss_boot_ctx_t *pCtx = NULL;

    const uint8_t chip_kvs_ac[] = "\x15\x24\x01\x05\x24\x02\x02\x36\x03\x06\x69\xb6\x01\x00\x18\x34\x04\x18";

    const uint8_t chip_kvs_g[] = "\x15\x24\x01\x00\x24\x02\x00\x24\x03\x00\x24\x04\x00\x24\x05\x00\x24\x06\x01\x24\x07\x00\x18";

    const uint8_t chip_kvs_i[] = "\x15\x30\x01\x01\x01\x24\x02\x01\x37\x03\x24\x14\x01\x18\x26\x04\x80\x22\x81\x27\x26\x05\x80\x25\x4d\x3a\x37\x06\x24\x13\x02\x18\x24\x07\x01\x24\x08\x01\x30\x09\x41\x04\xb6\xd9\x9a\x2e\x9b\xa2\x68\xf4\x97\x37\x27\x5b\x5a\xcc\xf0\x68\x70\x00\x09\x8e\x50\xe9\x77\xaa\xe6\x35\x24\x3e\x97\x97\xe2\xb5\x04\x07\x1d\x4e\x2c\xc6\x44\xa9\x6b\x29\x50\xb6\xfb\x17\x58\xbd\x99\xc3\x12\x33\x2d\x09\x6a\x83\xa9\xbf\xca\x48\x96\x5e\x2d\x0a\x37\x0a\x35\x01\x29\x01\x18\x24\x02\x60\x30\x04\x14\xf4\xe9\x9e\x6c\xd2\x78\xd0\x4e\xc3\xa1\x32\xce\xf7\xb4\xac\x1e\xbc\x4f\x41\x4c\x30\x05\x14\xa3\x12\xb0\x3c\x02\x75\x76\xdd\x29\x99\x1b\x7b\x7c\x68\x2c\x49\xf4\xd2\xa9\x7a\x18\x30\x0b\x40\x3d\x59\x84\x7d\xac\x6e\x55\xae\x7d\x8d\x03\x5b\xdb\xc3\x36\x72\x7c\xe5\xc7\xea\x03\xdf\x72\x00\xa0\x57\xcb\x4f\x80\xbb\x94\xe7\xe3\xbc\xb3\x09\x40\x75\x16\x02\xe0\x64\xe8\x20\x12\xf1\x55\x91\x6c\x2c\x37\xb7\x58\x6b\x11\x2f\x14\xa4\xea\xbd\x30\x31\x85\xa0\x18";

    const uint8_t chip_kvs_keySet[] = "\x15\x24\x01\x00\x24\x02\x01\x36\x03\x15\x24\x04\x00\x25\x05\xa5\x74\x30\x06\x10\x3e\x3a\x48\xb6\x8f\xc6\x6f\x48\x35\x0b\xea\xd4\x50\xff\x87\xe6\x18\x15\x24\x04\x00\x24\x05\x00\x30\x06\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x15\x24\x04\x00\x24\x05\x00\x30\x06\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x18\x25\x07\xff\xff\x18";

    const uint8_t chip_kvs_m[] = "\x15\x25\x00\xf1\xff\x2c\x01\x00\x18";

    const uint8_t chip_kvs_n[] = "\x15\x30\x01\x01\x01\x24\x02\x01\x37\x03\x24\x13\x02\x18\x26\x04\x80\x22\x81\x27\x26\x05\x80\x25\x4d\x3a\x37\x06\x24\x15\x01\x24\x11\x01\x18\x24\x07\x01\x24\x08\x01\x30\x09\x41\x04\x5c\x74\x7c\xd6\x91\xc4\x6c\x1d\xeb\xc7\xc4\x15\x66\xda\xca\xc9\x0e\x46\x90\x9f\x87\xa4\x1a\x8c\x1f\xce\xa5\x12\xa2\xaa\x7b\x1c\x76\x2f\xa1\xd3\xe6\x4e\xd1\x3b\xaf\xab\xbc\xeb\xc2\x4d\x4f\xf0\x29\x04\xc0\x47\xc8\xd1\x84\x68\x26\x1f\x59\x19\xad\x86\xa1\xef\x37\x0a\x35\x01\x28\x01\x18\x24\x02\x01\x36\x03\x04\x02\x04\x01\x18\x30\x04\x14\xb4\xc2\xc2\xb6\x9d\x0d\xf4\xdb\xa6\xf4\x11\xd2\xa1\x61\xcd\xaf\xbe\x50\x02\xda\x30\x05\x14\xf4\xe9\x9e\x6c\xd2\x78\xd0\x4e\xc3\xa1\x32\xce\xf7\xb4\xac\x1e\xbc\x4f\x41\x4c\x18\x30\x0b\x40\xf4\xc2\x8c\xb9\x57\xde\xf4\xd7\x7f\xa4\x7a\x5d\xfe\x1e\xab\x2e\xfb\x31\xab\xe3\x36\xa9\x1f\x73\x6d\x99\xdd\x41\x0a\x70\xdc\x1a\x6b\xe5\x61\xb9\x25\x0b\x1c\x0f\x20\xf2\x77\xc4\xd5\x2c\xee\x16\xd8\x9e\x4b\xa9\xf4\x7f\x7f\xf0\x87\x51\xdc\xe0\x88\x01\x6d\x17\x18";

    const uint8_t chip_kvs_o[] = {
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xCD, 0xCD, 0xCD,
        0x93, 0x04, 0x99, 0xD6, 0x9E, 0x2D, 0x6E, 0xF9, 0xA5, 0x4C,
        0x32, 0x80, 0x62, 0x20, 0xD0, 0x92, 0x06, 0xF5, 0x24, 0xEC,
        0x9C, 0xFE, 0x0A, 0xF8, 0xF8, 0x51, 0xB1, 0x96, 0x22, 0xA0,
        0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 
        0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x5C, 0x74, 0x7C,
        0xD6, 0x91, 0xC4, 0x6C, 0x1D, 0xEB, 0xC7, 0xC4, 0x15, 0x66,
        0xDA, 0xCA, 0xC9, 0x0E, 0x46, 0x90, 0x9F, 0x87, 0xA4, 0x1A,
        0x8C, 0x1F, 0xCE, 0xA5, 0x12, 0xA2, 0xAA, 0x7B, 0x1C, 0x76,
        0x2F, 0xA1, 0xD3, 0xE6, 0x4E, 0xD1, 0x3B, 0xAF, 0xAB, 0xBC,
        0xEB, 0xC2, 0x4D, 0x4F, 0xF0, 0x29, 0x04, 0xC0, 0x47, 0xC8,
        0xD1, 0x84, 0x68, 0x26, 0x1F, 0x59, 0x19, 0xAD, 0x86, 0xA1,
        0xEF
    };

    const uint8_t chip_kvs_r[] = "\x15\x30\x01\x01\x01\x24\x02\x01\x37\x03\x24\x14\x01\x18\x26\x04\x80\x22\x81\x27\x26\x05\x80\x25\x4d\x3a\x37\x06\x24\x14\x01\x18\x24\x07\x01\x24\x08\x01\x30\x09\x41\x04\x9c\xc3\x38\x98\xfd\x9c\x3d\xdc\x51\x8f\xcc\x0c\x33\x9c\x8f\x6c\x87\xda\xa9\xb7\x03\xa5\x6c\xd2\xaf\x81\x2f\xe2\x65\xc0\x21\xe3\xa6\x74\x7f\x83\x26\x70\x45\x36\x7b\xd1\x77\x75\x6c\x03\x2f\xdb\x4e\xeb\xd5\x2d\xae\xb9\xae\xf9\x68\xd5\xfe\x6b\x49\x49\x54\xf8\x37\x0a\x35\x01\x29\x01\x18\x24\x02\x60\x30\x04\x14\xa3\x12\xb0\x3c\x02\x75\x76\xdd\x29\x99\x1b\x7b\x7c\x68\x2c\x49\xf4\xd2\xa9\x7a\x30\x05\x14\xa3\x12\xb0\x3c\x02\x75\x76\xdd\x29\x99\x1b\x7b\x7c\x68\x2c\x49\xf4\xd2\xa9\x7a\x18\x30\x0b\x40\x49\x51\x03\x7c\x6c\x72\xd6\x17\x2d\x25\xb8\xb3\xf7\xb0\xfc\x5c\xcf\x19\x69\xb9\xd5\x33\x78\xd0\x66\xaf\xa5\x0d\xef\xbb\x38\x63\xa6\x62\xd0\xcb\x9a\x9a\x77\x06\xe2\x10\xb0\xcb\xf4\x7e\x5d\x13\xa1\x6a\x1c\x55\x36\xb2\xef\x28\x58\x2a\x1d\xad\x74\x39\x1d\x4f\x18";

    const uint8_t chip_kvs_s[] = "\x15\x30\x03\x10\xa6\x4e\xa5\xab\x0c\x43\x79\xd6\x24\x73\x2f\x6e\x91\x12\x2e\x0b\x30\x04\x20\x0f\xa8\xb8\xd3\xc6\x4c\x1a\xb6\x90\xcb\xe5\x32\x54\x9d\xec\x83\x9e\x61\x18\x88\x7f\xb9\x29\x81\x20\x7f\x40\xb6\x07\xc1\xda\xee\x30\x05\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18";

    const uint8_t chip_kvs_fidx[] = "\x15\x24\x00\x02\x36\x01\x04\x01\x18\x18";

    const uint8_t chip_kvs_rID[] = "\x15\x24\x01\x01\x26\x02\x69\xb6\x01\x00\x18";

    const char *ct_conf_data =
    "[Default]\n"
    "ExampleCAIntermediateCert0=MIIBljCCATygAwIBAgIBATAKBggqhkjOPQQDAjAiMSAwHgYKKwYBBAGConwBBAwQMDAwMDAwMDAwMDAwMDAwMTAeFw0yMTAxMDEwMDAwMDBaFw0zMDEyMzAwMDAwMDBaMCIxIDAeBgorBgEEAYKifAEDDBAwMDAwMDAwMDAwMDAwMDAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEttmaLpuiaPSXNydbWszwaHAACY5Q6Xeq5jUkPpeX4rUEBx1OLMZEqWspULb7F1i9mcMSMy0JaoOpv8pIll4tCqNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFPTpnmzSeNBOw6Eyzve0rB68T0FMMB8GA1UdIwQYMBaAFKMSsDwCdXbdKZkbe3xoLEn00ql6MAoGCCqGSM49BAMCA0gAMEUCID1ZhH2sblWufY0DW9vDNnJ85cfqA99yAKBXy0+Au5TnAiEA47yzCUB1FgLgZOggEvFVkWwsN7dYaxEvFKTqvTAxhaA=\n"
    "ExampleCARootCert0=MIIBljCCATygAwIBAgIBATAKBggqhkjOPQQDAjAiMSAwHgYKKwYBBAGConwBBAwQMDAwMDAwMDAwMDAwMDAwMTAeFw0yMTAxMDEwMDAwMDBaFw0zMDEyMzAwMDAwMDBaMCIxIDAeBgorBgEEAYKifAEEDBAwMDAwMDAwMDAwMDAwMDAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnMM4mP2cPdxRj8wMM5yPbIfaqbcDpWzSr4Ev4mXAIeOmdH+DJnBFNnvRd3VsAy/bTuvVLa65rvlo1f5rSUlU+KNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFKMSsDwCdXbdKZkbe3xoLEn00ql6MB8GA1UdIwQYMBaAFKMSsDwCdXbdKZkbe3xoLEn00ql6MAoGCCqGSM49BAMCA0gAMEUCIElRA3xsctYXLSW4s/ew/FzPGWm51TN40GavpQ3vuzhjAiEApmLQy5qadwbiELDL9H5dE6FqHFU2su8oWCodrXQ5HU8=\n"
    "ExampleOpCredsCAKey0=BJzDOJj9nD3cUY/MDDOcj2yH2qm3A6Vs0q+BL+JlwCHjpnR/gyZwRTZ70Xd1bAMv207r1S2uua75aNX+a0lJVPh+z1MIR5yi157lN68w7vygFC04j7cWhXYs4TVvT1eHcQ==\n"
    "ExampleOpCredsICAKey0=BLbZmi6bomj0lzcnW1rM8GhwAAmOUOl3quY1JD6Xl+K1BAcdTizGRKlrKVC2+xdYvZnDEjMtCWqDqb/KSJZeLQo81SkGWmpdNni6YXODRC9SXT2C4wg549p8QQ2MtOKCiA==\n";

    memset(&gex_sss_nfc_comm_prov_ctx,  0,  sizeof(gex_sss_nfc_comm_prov_ctx));

    status = ex_sss_boot_connectstring(0,  NULL,  (char**)&portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("se05x error: %s\n",  "ex_sss_boot_connectstring failed");
        goto cleanup;
    }

    status = ex_sss_boot_open(&gex_sss_nfc_comm_prov_ctx,  portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("se05x error: %s\n",  "ex_sss_boot_open failed");
    } else {

        status = ex_sss_key_store_and_object_init(&gex_sss_nfc_comm_prov_ctx);
        if (kStatus_SSS_Success != status) {
            LOG_E("se05x error: %s\n",  "ex_sss_key_store_and_object_init failed");
            goto cleanup;
        }

        if(doReset) {
            se05xReset();
            return;
        }

        pCtx = &gex_sss_nfc_comm_prov_ctx;

        LOG_I("Writing ACL data to SE05x at Key id = %x",  FABRIC_ACL_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_ACL_ID,  chip_kvs_ac,  sizeof(chip_kvs_ac) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing GroupData to SE05x at Key id = %x",  FABRIC_GROUP_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_GROUP_ID,  chip_kvs_g,  sizeof(chip_kvs_g) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing ICAC to SE05x at Key id = %x", FABRIC_ICAC_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_ICAC_ID,  chip_kvs_i,  sizeof(chip_kvs_i) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing KeySet Data to SE05x at Key id = %x", FABRIC_KEYSET_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_KEYSET_ID,  chip_kvs_keySet,  sizeof(chip_kvs_keySet) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing Fabric Metadata to SE05x at Key id = %x", FABRIC_METADATA_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_METADATA_ID,  chip_kvs_m,  sizeof(chip_kvs_m) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing NOC to SE05x at Key id = %x", FABRIC_NOC_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_NOC_ID,  chip_kvs_n,  sizeof(chip_kvs_n) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing ECkey to SE05x at Key id = %x", FABRIC_KEY);
        status = se05xSetEcKey(&pCtx->ks,  FABRIC_KEY,  chip_kvs_o,  sizeof(chip_kvs_o));
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing RCAC Data to SE05x at Key id = %x", FABRIC_RCAC_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_RCAC_ID,  chip_kvs_r,  sizeof(chip_kvs_r) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing Session Data to SE05x at Key id = %x", FABRIC_SESSION_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_SESSION_ID,  chip_kvs_s,  sizeof(chip_kvs_s) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing IndexInfo Data to SE05x at Key id = %x", FABRIC_INDEX_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_INDEX_ID,  chip_kvs_fidx,  sizeof(chip_kvs_fidx) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        LOG_I("Writing Resumption Data to SE05x at Key id = %x", FABRIC_RES_ID);
        status = se05xSetBinaryData(&pCtx->ks,  FABRIC_RES_ID,  chip_kvs_rID,  sizeof(chip_kvs_rID) - 1);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    }

    LOG_I("writing chip_tool_config_alpha data %s",  CT_CONF_PATH);
    status = write_config_data(CT_CONF_PATH,  ct_conf_data);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:

    if (kStatus_SSS_Success == status) {
        LOG_I("se05x_nfc_comm_prov Example Success !!!...");
    } else {
        LOG_E("se05x_nfc_comm_prov Example Failed !!!...");
    }

    return;
}