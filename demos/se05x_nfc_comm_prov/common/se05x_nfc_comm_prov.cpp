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

#define FABRIC_GROUP_ID     0x7D300022
#define FABRIC_ICAC_ID      0x7D300013
#define FABRIC_KEYSET_ID    0x7D300014
#define FABRIC_METADATA_ID  0x7D300015
#define FABRIC_NOC_ID       0x7D300016
#define FABRIC_KEY          0x7D300020
#define FABRIC_RCAC_ID      0x7D300017
#define FABRIC_INDEX_ID     0x7D300018
#define FABRIC_RES_ID       0x7D300019

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

    se05x_delete_key(FABRIC_GROUP_ID);
    se05x_delete_key(FABRIC_ICAC_ID);
    se05x_delete_key(FABRIC_KEYSET_ID);
    se05x_delete_key(FABRIC_METADATA_ID);
    se05x_delete_key(FABRIC_NOC_ID);
    se05x_delete_key(FABRIC_KEY);
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

    const uint8_t chip_kvs_g[] = "\x15\x24\x01\x00\x24\x02\x00\x24\x03\x00\x24\x04\x00\x24\x05\x00\x24\x06\x01\x24\x07\x00\x18";

    const uint8_t chip_kvs_i[] = "\x15\x30\x01\x01\x01\x24\x02\x01\x37\x03\x24\x14\x01\x18\x26\x04\x80\x22\x81\x27\x26\x05\x80\x25\x4d\x3a\x37\x06\x24\x13\x02\x18\x24\x07\x01\x24\x08\x01\x30\x09\x41\x04\x52\x4a\xa4\x43\x0a\xf2\xd1\x41\x3b\x5e\xc2\x7f\x79\x08\xa6\xfc\xd6\x17\x1e\x62\x78\xc3\xf7\x3f\x0d\x0e\x24\x01\x0e\xcd\xd1\x0d\xc3\xca\xc5\x79\x76\xc6\x0c\x66\xf8\x5a\xac\x04\x7a\xac\x8c\x61\x5a\x99\xdf\xe0\x02\xe7\x0e\x14\x08\xc8\x12\x71\xf8\x8f\x61\xe0\x37\x0a\x35\x01\x29\x01\x18\x24\x02\x60\x30\x04\x14\x25\xde\x2a\xff\x9c\x5f\xce\x96\xf0\x71\x81\x67\x56\xeb\x0a\xca\x28\xd6\xec\x79\x30\x05\x14\x72\x39\x2e\x78\x40\x14\x1f\x6c\x35\x58\x7b\x4a\x98\x97\x1d\x1a\x6d\x1d\x2e\x21\x18\x30\x0b\x40\x24\x36\xee\xb7\x47\xf2\x08\x29\x99\x51\xc8\x6e\x18\x79\x18\x41\x87\x29\x4a\x3a\x04\x5d\xe5\x43\x47\x27\xcb\xe1\xfe\x6f\xed\xc7\x88\xa5\x0f\x85\x4a\xe0\x57\xef\x7c\x12\xe7\xac\xa7\xb0\xfb\x53\x93\x8c\xdd\xa6\xb2\x3b\xf1\xcb\x0a\x61\x83\xe4\x78\x2e\x4d\x4d\x18";

    const uint8_t chip_kvs_keySet[] = "\x15\x24\x01\x00\x24\x02\x01\x36\x03\x15\x24\x04\x00\x25\x05\xf7\x34\x30\x06\x10\x6d\xcb\x76\xc2\xb8\x2d\x67\x26\x01\xda\x9b\x82\x1b\xbe\xbd\x74\x18\x15\x24\x04\x00\x24\x05\x00\x30\x06\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x15\x24\x04\x00\x24\x05\x00\x30\x06\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x18\x25\x07\xff\xff\x18";

    const uint8_t chip_kvs_m[] = "\x15\x25\x00\xF1\xFF\x2C\x01\x00\x18";

    const uint8_t chip_kvs_n[] = "\x15\x30\x01\x01\x01\x24\x02\x01\x37\x03\x24\x13\x02\x18\x26\x04\x80\x22\x81\x27\x26\x05\x80\x25\x4d\x3a\x37\x06\x24\x15\x01\x24\x11\x01\x18\x24\x07\x01\x24\x08\x01\x30\x09\x41\x04\x3c\xc8\x95\x3f\xbf\xe0\xe9\x83\x3a\xd5\x3b\x01\x61\xc4\x18\x7a\x25\xfe\x60\xe3\x4e\x52\x21\x94\x53\x0d\x4c\x70\xe0\x39\x17\x60\x20\x96\x3c\xd7\x6d\xde\xe1\x41\x74\xc9\x85\x10\xba\x5c\x0f\x7b\x08\x32\x3e\xfc\x64\x4e\xe1\xb2\xd8\xd1\x4f\x69\xca\x67\x8b\xf1\x37\x0a\x35\x01\x28\x01\x18\x24\x02\x01\x36\x03\x04\x02\x04\x01\x18\x30\x04\x14\x06\xb3\x65\x35\x6e\xba\x75\x45\xe9\x55\xf9\x7d\xdf\xe5\x5f\xbc\xdb\x28\x51\xae\x30\x05\x14\x25\xde\x2a\xff\x9c\x5f\xce\x96\xf0\x71\x81\x67\x56\xeb\x0a\xca\x28\xd6\xec\x79\x18\x30\x0b\x40\x15\x19\x61\x11\x25\xf7\xec\x77\xd2\x92\x52\x89\x55\x13\xae\xe6\x61\x0d\xc6\x91\x79\xd8\x91\x9c\x61\x91\xfe\x57\xb4\x3a\xd8\x33\x49\x9a\x0b\xa1\x13\xf3\xdd\x30\x16\x53\xb8\xfb\x47\xf5\xc1\xe1\xf2\xae\xac\x68\x65\x71\x40\x1c\x44\xf3\x66\xfd\x53\xad\x34\x13\x18";

    const uint8_t chip_kvs_o[] = {
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x51, 0xD4, 0x14, 
        0x7B, 0xBF, 0xFB, 0xED, 0xDD, 0x47, 0x21, 0x7E, 0xF5, 0xC5, 
        0x44, 0xD6, 0xAB, 0x88, 0x16, 0xCB, 0x58, 0x90, 0x92, 0xAB, 
        0x7B, 0x62, 0x7B, 0x01, 0x9F, 0x6B, 0xF9, 0x84, 0xEE, 0xA0, 
        0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 
        0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x3C, 0xC8, 0x95, 
        0x3F, 0xBF, 0xE0, 0xE9, 0x83, 0x3A, 0xD5, 0x3B, 0x01, 0x61, 
        0xC4, 0x18, 0x7A, 0x25, 0xFE, 0x60, 0xE3, 0x4E, 0x52, 0x21, 
        0x94, 0x53, 0x0D, 0x4C, 0x70, 0xE0, 0x39, 0x17, 0x60, 0x20, 
        0x96, 0x3C, 0xD7, 0x6D, 0xDE, 0xE1, 0x41, 0x74, 0xC9, 0x85, 
        0x10, 0xBA, 0x5C, 0x0F, 0x7B, 0x08, 0x32, 0x3E, 0xFC, 0x64, 
        0x4E, 0xE1, 0xB2, 0xD8, 0xD1, 0x4F, 0x69, 0xCA, 0x67, 0x8B, 
        0xF1
    };

    const uint8_t chip_kvs_r[] = "\x15\x30\x01\x01\x01\x24\x02\x01\x37\x03\x24\x14\x01\x18\x26\x04\x80\x22\x81\x27\x26\x05\x80\x25\x4d\x3a\x37\x06\x24\x14\x01\x18\x24\x07\x01\x24\x08\x01\x30\x09\x41\x04\xf4\x75\xec\x51\x47\xf3\x1a\xe1\x53\x88\x68\x3a\x42\xbf\x75\x2f\x3d\xe4\x30\x1f\xc2\xb7\xa5\xc4\x10\x26\x7e\x2e\x22\x19\xe2\x7b\xb0\xb2\x8d\x69\x44\x7a\x2b\x0b\x39\xf7\xa6\x04\xd1\x52\x23\xb4\x90\x1c\xa4\xb8\x41\xdf\xe0\x40\x81\xc1\x82\x5b\x9d\x13\xf3\xe2\x37\x0a\x35\x01\x29\x01\x18\x24\x02\x60\x30\x04\x14\x72\x39\x2e\x78\x40\x14\x1f\x6c\x35\x58\x7b\x4a\x98\x97\x1d\x1a\x6d\x1d\x2e\x21\x30\x05\x14\x72\x39\x2e\x78\x40\x14\x1f\x6c\x35\x58\x7b\x4a\x98\x97\x1d\x1a\x6d\x1d\x2e\x21\x18\x30\x0b\x40\x4a\x8f\x90\x3c\x34\x69\xcd\xb3\x75\x1a\x30\xf2\x88\x8a\x6a\x42\xa8\xe6\xeb\x5f\xae\xc5\xe0\x18\xf4\xa6\x0a\x65\x7b\x3a\x48\xb0\x7d\x0a\x1e\xfa\xf5\x06\x9c\x69\xde\x46\xee\x56\x85\xca\x17\xcd\x04\xa6\x9a\x34\x32\x20\x06\xfd\xad\xdf\xa9\x69\x4e\xf2\x2c\x93\x18";

    const uint8_t chip_kvs_fidx[] = "\x15\x24\x00\x02\x36\x01\x04\x01\x18\x18";

    const uint8_t chip_kvs_rID[] = "\x15\x24\x01\x01\x26\x02\x69\xb6\x01\x00\x18";

    const char *ct_conf_data =
        "[Default]\n"
        "ExampleCAIntermediateCert0=MIIBljCCATygAwIBAgIBATAKBggqhkjOPQQDAjAiMSAwHgYKKwYBBAGConwBBAwQMDAwMDAwMDAwMDAwMDAwMTAeFw0yMTAxMDEwMDAwMDBaFw0zMDEyMzAwMDAwMDBaMCIxIDAeBgorBgEEAYKifAEDDBAwMDAwMDAwMDAwMDAwMDAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUkqkQwry0UE7XsJ/eQim/NYXHmJ4w/c/DQ4kAQ7N0Q3DysV5dsYMZvharAR6rIxhWpnf4ALnDhQIyBJx+I9h4KNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFCXeKv+cX86W8HGBZ1brCsoo1ux5MB8GA1UdIwQYMBaAFHI5LnhAFB9sNVh7SpiXHRptHS4hMAoGCCqGSM49BAMCA0gAMEUCICQ27rdH8ggpmVHIbhh5GEGHKUo6BF3lQ0cny+H+b+3HAiEAiKUPhUrgV+98Euesp7D7U5OM3aayO/HLCmGD5HguTU0=\n"
        "ExampleCARootCert0=MIIBlTCCATygAwIBAgIBATAKBggqhkjOPQQDAjAiMSAwHgYKKwYBBAGConwBBAwQMDAwMDAwMDAwMDAwMDAwMTAeFw0yMTAxMDEwMDAwMDBaFw0zMDEyMzAwMDAwMDBaMCIxIDAeBgorBgEEAYKifAEEDBAwMDAwMDAwMDAwMDAwMDAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9HXsUUfzGuFTiGg6Qr91Lz3kMB/Ct6XEECZ+LiIZ4nuwso1pRHorCzn3pgTRUiO0kBykuEHf4ECBwYJbnRPz4qNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFHI5LnhAFB9sNVh7SpiXHRptHS4hMB8GA1UdIwQYMBaAFHI5LnhAFB9sNVh7SpiXHRptHS4hMAoGCCqGSM49BAMCA0cAMEQCIEqPkDw0ac2zdRow8oiKakKo5utfrsXgGPSmCmV7OkiwAiB9Ch769Qacad5G7laFyhfNBKaaNDIgBv2t36lpTvIskw==\n"
        "ExampleOpCredsCAKey0=BPR17FFH8xrhU4hoOkK/dS895DAfwrelxBAmfi4iGeJ7sLKNaUR6Kws596YE0VIjtJAcpLhB3+BAgcGCW50T8+JsI15jdzAZjYkIYerQh9da2IFfJ+FHGmN3XSi+FDnZyw==\n"
        "ExampleOpCredsICAKey0=BFJKpEMK8tFBO17Cf3kIpvzWFx5ieMP3Pw0OJAEOzdENw8rFeXbGDGb4WqwEeqyMYVqZ3+AC5w4UCMgScfiPYeANeOo58nDggDWIE7jrI80ycd4tO8QEn8ChY/yMnjKSUQ==\n";

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