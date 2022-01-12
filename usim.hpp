#ifndef _USIM_H
#define _USIM_H

#include <stdint.h>
#include <stdio.h>
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#define true 1
#define false 0
#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#define AKA_RAND_LEN 16
#define AKA_AUTN_LEN 16
#define AKA_AUTS_LEN 14
#define RES_MAX_LEN 16
#define MAC_LEN 8
#define IK_LEN 16
#define CK_LEN 16
#define AK_LEN 6
#define SQN_LEN 6
#define KEY_LEN 32

typedef enum
{
    AUTH_OK,
    AUTH_FAILED,
    AUTH_SYNCH_FAILURE
} auth_result_t;

typedef enum
{
    auth_algo_milenage = 0,
    auth_algo_xor,
} auth_algo_t;

typedef mbedtls_aes_context aes_context;

// Security variables
uint8_t ck[CK_LEN] = {};
uint8_t ik[IK_LEN] = {};
uint8_t ak[AK_LEN] = {};
uint8_t k_asme[KEY_LEN] = {};
uint8_t k_enb_star[KEY_LEN] = {};
uint8_t k_enb_initial[KEY_LEN] = {};
uint8_t auts[AKA_AUTS_LEN] = {};
uint8_t mac[8] = {};
uint8_t autn[16] = {};

// User data
auth_algo_t auth_algo = auth_algo_milenage;
uint8_t amf[2] = {};
uint8_t op[16] = {};
uint8_t opc[16] = {};
uint8_t k[16] = {};

void set_k(uint8_t *k_)
{
    for (uint8_t i = 0; i < 16; i++)
    {
        k[i] = *(k_ + i);
    }
}
void set_op(uint8_t *op_)
{
    for (uint8_t i = 0; i < 16; i++)
    {
        op[i] = *(op_ + i);
    }
}
void set_opc(uint8_t *opc_)
{
    for (uint8_t i = 0; i < 16; i++)
    {
        opc[i] = *(opc_ + i);
    }
}
void set_amf(uint8_t *amf_)
{
    for (uint8_t i = 0; i < 2; i++)
    {
        amf[i] = *(amf_ + i);
    }
}

// milenage
int compute_opc(uint8_t *k, uint8_t *op, uint8_t *op_c);
int security_xor_f2345(uint8_t *k, uint8_t *rand, uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak);
int security_milenage_f2345(uint8_t *k, uint8_t *op_c, uint8_t *rand, uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak);
// xor
int security_xor_f1(uint8_t *k, uint8_t *rand, uint8_t *sqn, uint8_t *amf, uint8_t *mac_a);
int security_milenage_f1(uint8_t *k, uint8_t *op_c, uint8_t *rand, uint8_t *sqn, uint8_t *amf, uint8_t *mac_a);

auth_result_t gen_auth_res_xor(uint8_t *rand, uint8_t *autn_enb, uint8_t *res, int *res_len, uint8_t *ak_xor_sqn);
auth_result_t gen_auth_res_milenage(uint8_t *rand, uint8_t *autn_enb, uint8_t *res, int *res_len, uint8_t *ak_xor_sqn);

// implement
int compute_opc(uint8_t *k, uint8_t *op, uint8_t *op_c)
{
    uint32_t i;
    aes_context ctx;
    int err = 1;

    if (k != NULL && op != NULL && op_c != NULL)
    {
        mbedtls_aes_setkey_enc(&ctx, k, 128);
        mbedtls_aes_crypt_ecb(&ctx, AES_ENCRYPT, op, op_c);
        for (i = 0; i < 16; i++)
        {
            op_c[i] ^= op[i];
        }
        err = 0;
    }
    return err;
}

int security_xor_f2345(uint8_t *k, uint8_t *rand, uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak)
{
    uint8_t xdout[16];
    uint8_t cdout[8];
    // Use RAND and K to compute RES, CK, IK and AK
    for (uint32_t i = 0; i < 16; i++)
    {
        xdout[i] = k[i] ^ rand[i];
    }
    for (uint32_t i = 0; i < 16; i++)
    {
        res[i] = xdout[i];
        ck[i] = xdout[(i + 1) % 16];
        ik[i] = xdout[(i + 2) % 16];
    }
    for (uint32_t i = 0; i < 6; i++)
    {
        ak[i] = xdout[i + 3];
    }
    return 0;
}

int security_xor_f1(uint8_t *k, uint8_t *rand, uint8_t *sqn, uint8_t *amf, uint8_t *mac_a)
{
    uint8_t xdout[16];
    uint8_t cdout[8];
    // Use RAND and K to compute RES, CK, IK and AK
    for (uint32_t i = 0; i < 16; i++)
    {
        xdout[i] = k[i] ^ rand[i];
    }
    // Generate cdout
    for (uint32_t i = 0; i < 6; i++)
    {
        cdout[i] = sqn[i];
    }
    for (uint32_t i = 0; i < 2; i++)
    {
        cdout[6 + i] = amf[i];
    }

    // Generate MAC
    for (uint32_t i = 0; i < 8; i++)
    {
        mac_a[i] = xdout[i] ^ cdout[i];
    }
    return 0;
}

int security_milenage_f2345(uint8_t *k, uint8_t *op_c, uint8_t *rand, uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak)
{
    int err = false;
    uint32_t i;
    uint8_t temp[16];
    uint8_t out[16];
    uint8_t input[16];
    aes_context ctx;

    if (k != NULL && op_c != NULL && rand != NULL && res != NULL && ck != NULL && ik != NULL && ak != NULL)
    {
        // Initialize the round keys
        mbedtls_aes_setkey_enc(&ctx, k, 128);
        // Compute temp
        for (i = 0; i < 16; i++)
        {
            input[i] = rand[i] ^ op_c[i];
        }
        mbedtls_aes_crypt_ecb(&ctx, AES_ENCRYPT, input, temp);
        // Compute out for RES and AK
        for (i = 0; i < 16; i++)
        {
            input[i] = temp[i] ^ op_c[i];
        }
        input[15] ^= 1;
        mbedtls_aes_crypt_ecb(&ctx, AES_ENCRYPT, input, out);
        for (i = 0; i < 16; i++)
        {
            out[i] ^= op_c[i];
        }

        // Return RES
        for (i = 0; i < 8; i++)
        {
            res[i] = out[i + 8];
        }

        // Return AK
        for (i = 0; i < 6; i++)
        {
            ak[i] = out[i];
        }

        // Compute out for CK
        for (i = 0; i < 16; i++)
        {
            input[(i + 12) % 16] = temp[i] ^ op_c[i];
        }
        input[15] ^= 2;
        mbedtls_aes_crypt_ecb(&ctx, AES_ENCRYPT, input, out);
        for (i = 0; i < 16; i++)
        {
            out[i] ^= op_c[i];
        }

        // Return CK
        for (i = 0; i < 16; i++)
        {
            ck[i] = out[i];
        }

        // Compute out for IK
        for (i = 0; i < 16; i++)
        {
            input[(i + 8) % 16] = temp[i] ^ op_c[i];
        }
        input[15] ^= 4;
        mbedtls_aes_crypt_ecb(&ctx, AES_ENCRYPT, input, out);
        for (i = 0; i < 16; i++)
        {
            out[i] ^= op_c[i];
        }

        // Return IK
        for (i = 0; i < 16; i++)
        {
            ik[i] = out[i];
        }

        err = true;
    }

    return (err);
}

auth_result_t gen_auth_res_xor(uint8_t *rand, uint8_t *autn_enb, uint8_t *res, int *res_len, uint8_t *ak_xor_sqn)
{
    auth_result_t result = AUTH_OK;
    uint8_t sqn[6];
    uint8_t res_[16];

    // Use RAND and K to compute RES, CK, IK and AK
    security_xor_f2345(k, rand, res_, ck, ik, ak);

    for (uint32_t i = 0; i < 8; i++)
    {
        res[i] = res_[i];
    }

    *res_len = 8;

    // Extract sqn from autn
    for (uint32_t i = 0; i < 6; i++)
    {
        sqn[i] = autn_enb[i] ^ ak[i];
    }
    // Extract AMF from autn
    for (uint32_t i = 0; i < 2; i++)
    {
        amf[i] = autn_enb[6 + i];
    }

    // Generate MAC
    security_xor_f1(k, rand, sqn, amf, mac);

    // Construct AUTN
    for (uint32_t i = 0; i < 6; i++)
    {
        autn[i] = sqn[i] ^ ak[i];
    }
    for (uint32_t i = 0; i < 2; i++)
    {
        autn[6 + i] = amf[i];
    }
    for (uint32_t i = 0; i < 8; i++)
    {
        autn[8 + i] = mac[i];
    }

    // Compare AUTNs
    for (uint32_t i = 0; i < 16; i++)
    {
        // printf("%02x %02x\n", autn[i], autn_enb[i]);
        if (autn[i] != autn_enb[i])
        {
            result = AUTH_FAILED;
        }
    }

    for (uint32_t i = 0; i < 6; i++)
    {
        ak_xor_sqn[i] = sqn[i] ^ ak[i];
    }

    return result;
}

int security_milenage_f1(uint8_t *k, uint8_t *op_c, uint8_t *rand, uint8_t *sqn, uint8_t *amf, uint8_t *mac_a)
{
    int err = false;
    uint32_t i;
    aes_context ctx;
    uint8_t temp[16];
    uint8_t in1[16];
    uint8_t out1[16];
    uint8_t input[16];

    if (k != NULL && op_c != NULL && rand != NULL && sqn != NULL && amf != NULL && mac_a != NULL)
    {
        // Initialize the round keys
        mbedtls_aes_setkey_enc(&ctx, k, 128);

        // Compute temp
        for (i = 0; i < 16; i++)
        {
            input[i] = rand[i] ^ op_c[i];
        }
        mbedtls_aes_crypt_ecb(&ctx, AES_ENCRYPT, input, temp);

        // Construct in1
        for (i = 0; i < 6; i++)
        {
            in1[i] = sqn[i];
            in1[i + 8] = sqn[i];
        }
        for (i = 0; i < 2; i++)
        {
            in1[i + 6] = amf[i];
            in1[i + 14] = amf[i];
        }

        // Compute out1
        for (i = 0; i < 16; i++)
        {
            input[(i + 8) % 16] = in1[i] ^ op_c[i];
        }
        for (i = 0; i < 16; i++)
        {
            input[i] ^= temp[i];
        }
        mbedtls_aes_crypt_ecb(&ctx, AES_ENCRYPT, input, out1);
        for (i = 0; i < 16; i++)
        {
            out1[i] ^= op_c[i];
        }

        // Return MAC-A
        for (i = 0; i < 8; i++)
        {
            mac_a[i] = out1[i];
        }

        err = true;
    }

    return err;
}

auth_result_t gen_auth_res_milenage(uint8_t *rand, uint8_t *autn_enb, uint8_t *res, int *res_len, uint8_t *ak_xor_sqn)
{
    auth_result_t result = AUTH_OK;
    uint32_t i;
    uint8_t sqn[6];

    // Use RAND and K to compute RES, CK, IK and AK
    security_milenage_f2345(k, opc, rand, res, ck, ik, ak);

    *res_len = 8;

    // Extract sqn from autn
    for (i = 0; i < 6; i++)
    {
        sqn[i] = autn_enb[i] ^ ak[i];
    }

    // Extract AMF from autn
    for (int i = 0; i < 2; i++)
    {
        amf[i] = autn_enb[6 + i];
    }

    // Generate MAC
    security_milenage_f1(k, opc, rand, sqn, amf, mac);

    // Construct AUTN
    for (i = 0; i < 6; i++)
    {
        autn[i] = sqn[i] ^ ak[i];
    }
    for (i = 0; i < 2; i++)
    {
        autn[6 + i] = amf[i];
    }
    for (i = 0; i < 8; i++)
    {
        autn[8 + i] = mac[i];
    }

    // Compare AUTNs
    for (i = 0; i < 16; i++)
    {
        if (autn[i] != autn_enb[i])
        {
            result = AUTH_FAILED;
        }
    }

    for (i = 0; i < 6; i++)
    {
        ak_xor_sqn[i] = sqn[i] ^ ak[i];
    }
    return result;
}
#endif