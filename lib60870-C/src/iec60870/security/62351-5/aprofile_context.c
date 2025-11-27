/*
 * Copyright 2024
 *
 * This file is part of lib60870-C
 *
 * lib60870-C is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * lib60870-C is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lib60870-C.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "../../inc/internal/aprofile_internal.h"
#include "lib60870_internal.h"
#include "cs104_frame.h"
#include "hal_time.h"
#include "lib_memory.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"

#define APROFILE_TAG_SECURE_DATA 0xF1
#define APROFILE_TAG_ASSOCIATION_REQUEST 0xE1
#define APROFILE_TAG_ASSOCIATION_RESPONSE 0xE2
#define APROFILE_TAG_SESSION_KEY_CHANGE_REQUEST 0xE3
#define APROFILE_TAG_SESSION_KEY_CHANGE_RESPONSE 0xE4

#define APROFILE_ASSOC_VERSION 0x01
#define APROFILE_ASSOC_NONCE_SIZE 16
#define APROFILE_CONTROL_MAC_SIZE 16
#define APROFILE_HEADER_SIZE 11 /* tag (1) + DSQ (4) + AIM (2) + AIS (2) + ASDU length (2) */
#define APROFILE_MAC_SIZE 16 /* Integrity tag size for GCM or truncated MAC */

#define APROFILE_MAX_CONTROL_PDU 512

/*
 * This implementation provides a hardened, self-contained version of the
 * IEC 62351-5 A-profile data processing logic. It focuses on deterministic
 * replay protection (DSQ handling) and integrity tagging using the mandatory
 * HMAC-SHA-256 (truncated to 16 octets for 104 over TCP). The code maintains
 * distinct inbound/outbound session keys, enforces DSQ progression, and
 * exposes helper functions to reset counters or inject externally derived
 * session keys from a Station Association / Session Key Change workflow.
 */

struct sAProfileContext
{
    bool startDtSeen;
    bool sessionKeysSet;
    bool rekeyRequested;
    bool associationInProgress;
    bool awaitingAssociationResponse;
    bool awaitingKeyChangeResponse;
    bool associationEstablished;
    bool certificatesVerified;
    bool rolesAuthorized;
    bool updateKeysSet;
    bool ecdhInitialized;
    bool hasPendingSessionKeys;
    uint8_t pendingSessionKeyOutbound[APROFILE_SESSION_KEY_LENGTH];
    uint8_t pendingSessionKeyInbound[APROFILE_SESSION_KEY_LENGTH];
    uint16_t aim;
    uint16_t ais;
    uint32_t dsqOut;
    uint32_t dsqInExpected;
    uint32_t sentMessages;
    uint64_t sessionKeyBirthMs;
    AProfileDpaAlgorithm algorithm;
    AProfileTelemetry telemetry;
    uint8_t authUpdateKey[APROFILE_SESSION_KEY_LENGTH];
    uint8_t encUpdateKey[APROFILE_SESSION_KEY_LENGTH];
    uint8_t sessionKeyOutbound[APROFILE_SESSION_KEY_LENGTH];
    uint8_t sessionKeyInbound[APROFILE_SESSION_KEY_LENGTH];
    uint8_t assocNonceLocal[APROFILE_ASSOC_NONCE_SIZE];
    uint8_t assocNoncePeer[APROFILE_ASSOC_NONCE_SIZE];
    uint8_t pendingControl[APROFILE_MAX_CONTROL_PDU];
    size_t pendingControlLen;
    mbedtls_ecdh_context ecdhCtx;
    uint8_t inboundBuffer[IEC60870_5_104_MAX_ASDU_LENGTH];
};

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context drbg_ctx;
static bool rng_initialized = false;

static const uint8_t defaultAesKwIv[8] = {0xa6u, 0xa6u, 0xa6u, 0xa6u, 0xa6u, 0xa6u, 0xa6u, 0xa6u};

static void
updateAssociationState(AProfileContext ctx)
{
    if (ctx == NULL)
        return;

    ctx->associationEstablished = ctx->sessionKeysSet && ctx->certificatesVerified && ctx->rolesAuthorized;
}

static bool
queueControlPdu(AProfileContext ctx, const uint8_t* data, size_t len)
{
    if ((ctx == NULL) || (data == NULL) || (len == 0) || (len > APROFILE_MAX_CONTROL_PDU))
        return false;

    memcpy(ctx->pendingControl, data, len);
    ctx->pendingControlLen = len;
    return true;
}

static bool
aesKwWrap(const uint8_t* kek, const uint8_t* plaintext, size_t plaintextLen, uint8_t* wrapped, size_t wrappedLen)
{
    const size_t n = plaintextLen / 8;

    if ((plaintextLen % 8 != 0) || (n < 2) || (wrappedLen < plaintextLen + 8))
        return false;

    uint8_t a[8];
    memcpy(a, defaultAesKwIv, sizeof(a));

    uint8_t r[6][8];
    if (n > 6)
        return false;

    for (size_t i = 0; i < n; i++)
        memcpy(r[i], plaintext + (8 * i), 8);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, kek, 256) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    for (size_t j = 0; j <= 5; j++)
    {
        for (size_t i = 0; i < n; i++)
        {
            uint8_t block[16];
            memcpy(block, a, 8);
            memcpy(block + 8, r[i], 8);

            mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, block, block);

            uint64_t t = (uint64_t)(n * j + (i + 1));

            for (int k = 0; k < 8; k++)
                a[k] = block[k] ^ ((t >> (56 - (8 * k))) & 0xffu);

            memcpy(r[i], block + 8, 8);
        }
    }

    mbedtls_aes_free(&aes);

    memcpy(wrapped, a, 8);
    for (size_t i = 0; i < n; i++)
        memcpy(wrapped + 8 + (8 * i), r[i], 8);

    return true;
}

static bool
aesKwUnwrap(const uint8_t* kek, const uint8_t* wrapped, size_t wrappedLen, uint8_t* plaintext, size_t plaintextLen)
{
    const size_t n = plaintextLen / 8;

    if ((plaintextLen % 8 != 0) || (wrappedLen != plaintextLen + 8) || (n < 2) || (n > 6))
        return false;

    uint8_t a[8];
    memcpy(a, wrapped, 8);

    uint8_t r[6][8];
    for (size_t i = 0; i < n; i++)
        memcpy(r[i], wrapped + 8 + (8 * i), 8);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_dec(&aes, kek, 256) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    for (int j = 5; j >= 0; j--)
    {
        for (int i = (int)n - 1; i >= 0; i--)
        {
            uint64_t t = (uint64_t)(n * j + (i + 1));
            uint8_t block[16];

            for (int k = 0; k < 8; k++)
                block[k] = (uint8_t)(a[k] ^ ((t >> (56 - (8 * k))) & 0xffu));

            memcpy(block + 8, r[i], 8);

            mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, block, block);

            memcpy(a, block, 8);
            memcpy(r[i], block + 8, 8);
        }
    }

    mbedtls_aes_free(&aes);

    if (memcmp(a, defaultAesKwIv, sizeof(a)) != 0)
        return false;

    for (size_t i = 0; i < n; i++)
        memcpy(plaintext + (8 * i), r[i], 8);

    return true;
}

static bool
generateRandomBytes(uint8_t* out, size_t length)
{
    if (!rng_initialized)
    {
        mbedtls_entropy_init(&entropy_ctx);
        mbedtls_ctr_drbg_init(&drbg_ctx);

        const char* pers = "aprofile";
        if (mbedtls_ctr_drbg_seed(&drbg_ctx, mbedtls_entropy_func, &entropy_ctx,
                                  (const unsigned char*)pers, strlen(pers)) != 0)
        {
            mbedtls_ctr_drbg_free(&drbg_ctx);
            mbedtls_entropy_free(&entropy_ctx);
            return false;
        }

        rng_initialized = true;
    }

    return (mbedtls_ctr_drbg_random(&drbg_ctx, out, length) == 0);
}

static int
generateRandomBytesMbedtls(void* randomCtx, unsigned char* out, size_t length)
{
    (void)randomCtx;

    return generateRandomBytes(out, length) ? 0 : MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
}

static void
fallbackDeterministicKey(uint8_t* keyBuf, size_t length)
{
    uint64_t seed = Hal_getMonotonicTimeInMs();

    for (size_t i = 0; i < length; i++)
    {
        seed ^= (seed << 13);
        seed ^= (seed >> 7);
        seed ^= (seed << 17);
        keyBuf[i] = (uint8_t)(seed & 0xffu);
    }
}

static bool
ensureEcdhInitialized(AProfileContext ctx)
{
    if (ctx->ecdhInitialized)
        return true;

    mbedtls_ecdh_init(&ctx->ecdhCtx);

    if (mbedtls_ecdh_setup(&ctx->ecdhCtx, MBEDTLS_ECP_DP_SECP256R1) != 0)
    {
        mbedtls_ecdh_free(&ctx->ecdhCtx);
        return false;
    }

    ctx->ecdhInitialized = true;
    return true;
}

static bool
deriveUpdateKeysFromSecret(const uint8_t* secret, size_t secretLen, const uint8_t* salt, size_t saltLen, uint16_t aim,
                           uint16_t ais, uint8_t* authOut, uint8_t* encOut)
{
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL)
        return false;

    uint8_t info[6];
    info[0] = (uint8_t)((aim >> 8) & 0xffu);
    info[1] = (uint8_t)(aim & 0xffu);
    info[2] = (uint8_t)((ais >> 8) & 0xffu);
    info[3] = (uint8_t)(ais & 0xffu);
    info[4] = 'A';
    info[5] = 'P';

    uint8_t derived[APROFILE_SESSION_KEY_LENGTH * 2];
    if (mbedtls_hkdf(md, salt, saltLen, secret, secretLen, info, sizeof(info), derived, sizeof(derived)) != 0)
        return false;

    memcpy(authOut, derived, APROFILE_SESSION_KEY_LENGTH);
    memcpy(encOut, derived + APROFILE_SESSION_KEY_LENGTH, APROFILE_SESSION_KEY_LENGTH);

    return true;
}

static void
initializeSessionKeys(AProfileContext ctx)
{
    if (!generateRandomBytes(ctx->sessionKeyOutbound, APROFILE_SESSION_KEY_LENGTH))
        fallbackDeterministicKey(ctx->sessionKeyOutbound, APROFILE_SESSION_KEY_LENGTH);

    if (!generateRandomBytes(ctx->sessionKeyInbound, APROFILE_SESSION_KEY_LENGTH))
        fallbackDeterministicKey(ctx->sessionKeyInbound, APROFILE_SESSION_KEY_LENGTH);

    ctx->sessionKeysSet = true;
    ctx->sessionKeyBirthMs = Hal_getMonotonicTimeInMs();
    ctx->rekeyRequested = false;
    ctx->sentMessages = 0;
    updateAssociationState(ctx);
}

static bool
shouldRequestRekey(AProfileContext ctx)
{
    const uint64_t now = Hal_getMonotonicTimeInMs();

    if ((CONFIG_CS104_APROFILE_MAX_SESSION_AGE_MS > 0) &&
        ((now - ctx->sessionKeyBirthMs) > (uint64_t)CONFIG_CS104_APROFILE_MAX_SESSION_AGE_MS))
        return true;

    if ((CONFIG_CS104_APROFILE_MAX_MESSAGES_PER_SESSION > 0) &&
        (ctx->sentMessages >= CONFIG_CS104_APROFILE_MAX_MESSAGES_PER_SESSION))
        return true;

    if (ctx->dsqOut >= (UINT32_MAX - CONFIG_CS104_APROFILE_DSQ_REKEY_MARGIN))
        return true;

    return false;
}

static bool
localSessionKeyChange(AProfileContext ctx)
{
    if ((ctx == NULL) || (ctx->updateKeysSet == false))
        return false;

    uint8_t newOutbound[APROFILE_SESSION_KEY_LENGTH];
    uint8_t newInbound[APROFILE_SESSION_KEY_LENGTH];
    uint8_t wrappedOutbound[APROFILE_SESSION_KEY_WRAP_LENGTH];
    uint8_t wrappedInbound[APROFILE_SESSION_KEY_WRAP_LENGTH];

    if (!generateRandomBytes(newOutbound, sizeof(newOutbound)))
        fallbackDeterministicKey(newOutbound, sizeof(newOutbound));

    if (!generateRandomBytes(newInbound, sizeof(newInbound)))
        fallbackDeterministicKey(newInbound, sizeof(newInbound));

    if (!aesKwWrap(ctx->encUpdateKey, newOutbound, sizeof(newOutbound), wrappedOutbound, sizeof(wrappedOutbound)))
        return false;

    if (!aesKwWrap(ctx->encUpdateKey, newInbound, sizeof(newInbound), wrappedInbound, sizeof(wrappedInbound)))
        return false;

    if (!AProfile_unwrapAndInstallSessionKeys(ctx, wrappedOutbound, sizeof(wrappedOutbound), wrappedInbound,
                                             sizeof(wrappedInbound)))
        return false;

    ctx->telemetry.controlFrames++;
    return true;
}

static const mbedtls_md_info_t*
selectMac(AProfileDpaAlgorithm algorithm)
{
    switch (algorithm)
    {
    case APROFILE_DPA_HMAC_SHA256:
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
#ifdef MBEDTLS_MD_SHA3_256
    case APROFILE_DPA_HMAC_SHA3_256:
        return mbedtls_md_info_from_type(MBEDTLS_MD_SHA3_256);
#endif
#ifdef MBEDTLS_MD_BLAKE2S_256
    case APROFILE_DPA_HMAC_BLAKE2S_256:
        return mbedtls_md_info_from_type(MBEDTLS_MD_BLAKE2S_256);
#endif
    default:
        return NULL;
    }
}

static bool
hmacTruncated(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen, uint8_t* macOut)
{
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL)
        return false;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, md, 1) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    bool ok = false;

    if ((mbedtls_md_hmac_starts(&ctx, key, keyLen) == 0) && (mbedtls_md_hmac_update(&ctx, data, dataLen) == 0))
    {
        uint8_t full[MBEDTLS_MD_MAX_SIZE];
        if (mbedtls_md_hmac_finish(&ctx, full) == 0)
        {
            memcpy(macOut, full, APROFILE_CONTROL_MAC_SIZE);
            ok = true;
        }
    }

    mbedtls_md_free(&ctx);
    return ok;
}

static void
deriveNonceFromDsq(uint32_t dsq, uint8_t nonce[12])
{
    memset(nonce, 0, 12);

    /* Place the 32-bit DSQ in network byte order at the tail of the nonce */
    nonce[8] = (uint8_t)((dsq >> 24) & 0xffu);
    nonce[9] = (uint8_t)((dsq >> 16) & 0xffu);
    nonce[10] = (uint8_t)((dsq >> 8) & 0xffu);
    nonce[11] = (uint8_t)(dsq & 0xffu);
}

static void
buildAssociationIdAd(uint16_t aim, uint16_t ais, uint8_t* aadBuf, size_t* aadLen)
{
    if ((aadBuf == NULL) || (aadLen == NULL))
        return;

    aadBuf[0] = (uint8_t)((aim >> 8) & 0xffu);
    aadBuf[1] = (uint8_t)(aim & 0xffu);
    aadBuf[2] = (uint8_t)((ais >> 8) & 0xffu);
    aadBuf[3] = (uint8_t)(ais & 0xffu);
    *aadLen = 4;
}

static bool
protectPayload(AProfileContext ctx, const uint8_t* key, const uint8_t* header, size_t headerLen,
               const uint8_t* plaintext, size_t plaintextLen, uint8_t* outPayload, uint8_t outMac[APROFILE_MAC_SIZE])
{
    if (ctx->algorithm == APROFILE_DPA_AES256_GCM)
    {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);

        uint8_t nonce[12];
        uint32_t dsq = ((uint32_t)header[1] << 24) | ((uint32_t)header[2] << 16) |
                       ((uint32_t)header[3] << 8) | (uint32_t)header[4];
        deriveNonceFromDsq(dsq, nonce);

        uint8_t aad[4];
        size_t aadLen = 0;
        buildAssociationIdAd(ctx->aim, ctx->ais, aad, &aadLen);

        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0)
        {
            ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintextLen, nonce, sizeof(nonce), aad, aadLen,
                                            plaintext, outPayload, APROFILE_MAC_SIZE, outMac);
        }

        mbedtls_gcm_free(&gcm);

        return (ret == 0);
    }

    const mbedtls_md_info_t* md_info = selectMac(ctx->algorithm);
    if (md_info == NULL)
        return false;

    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    if (mbedtls_md_setup(&md_ctx, md_info, 1) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    if (mbedtls_md_hmac_starts(&md_ctx, key, APROFILE_SESSION_KEY_LENGTH) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    if (mbedtls_md_hmac_update(&md_ctx, header, headerLen) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    if (mbedtls_md_hmac_update(&md_ctx, plaintext, plaintextLen) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    uint8_t fullMac[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_md_hmac_finish(&md_ctx, fullMac) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    mbedtls_md_free(&md_ctx);

    memcpy(outPayload, plaintext, plaintextLen);
    memcpy(outMac, fullMac, APROFILE_MAC_SIZE);
    return true;
}

static bool
validateAndDecryptPayload(AProfileContext ctx, const uint8_t* key, const uint8_t* header, size_t headerLen,
                          const uint8_t* cipherPayload, size_t payloadLen, const uint8_t* mac,
                          uint8_t* outPlaintext)
{
    if (ctx->algorithm == APROFILE_DPA_AES256_GCM)
    {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);

        uint8_t nonce[12];
        uint32_t dsq = ((uint32_t)header[1] << 24) | ((uint32_t)header[2] << 16) |
                       ((uint32_t)header[3] << 8) | (uint32_t)header[4];
        deriveNonceFromDsq(dsq, nonce);

        uint8_t aad[4];
        size_t aadLen = 0;
        buildAssociationIdAd(ctx->aim, ctx->ais, aad, &aadLen);

        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0)
        {
            ret = mbedtls_gcm_auth_decrypt(&gcm, payloadLen, nonce, sizeof(nonce), aad, aadLen, mac, APROFILE_MAC_SIZE,
                                           cipherPayload, outPlaintext);
        }

        mbedtls_gcm_free(&gcm);
        return (ret == 0);
    }

    const mbedtls_md_info_t* md_info = selectMac(ctx->algorithm);
    if (md_info == NULL)
        return false;

    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    if (mbedtls_md_setup(&md_ctx, md_info, 1) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    if (mbedtls_md_hmac_starts(&md_ctx, key, APROFILE_SESSION_KEY_LENGTH) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    if (mbedtls_md_hmac_update(&md_ctx, header, headerLen) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    if (mbedtls_md_hmac_update(&md_ctx, cipherPayload, payloadLen) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    uint8_t fullMac[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_md_hmac_finish(&md_ctx, fullMac) != 0)
    {
        mbedtls_md_free(&md_ctx);
        return false;
    }

    mbedtls_md_free(&md_ctx);

    if (memcmp(fullMac, mac, APROFILE_MAC_SIZE) != 0)
        return false;

    memcpy(outPlaintext, cipherPayload, payloadLen);
    return true;
}

static int
wrapPayload(AProfileContext ctx, T104Frame frame)
{
    int msgSize = T104Frame_getMsgSize((Frame)frame);
    if (msgSize <= IEC60870_5_104_APCI_LENGTH)
        return -1;

    if (ctx->dsqOut == 0 || ctx->dsqOut == UINT32_MAX)
        return -1;

    int asduLength = msgSize - IEC60870_5_104_APCI_LENGTH;

    uint8_t securePayload[IEC60870_5_104_MAX_ASDU_LENGTH + APROFILE_HEADER_SIZE + APROFILE_MAC_SIZE];

    uint8_t* frameBuffer = T104Frame_getBuffer((Frame)frame);
    const uint8_t* asduStart = frameBuffer + IEC60870_5_104_APCI_LENGTH;

    securePayload[0] = APROFILE_TAG_SECURE_DATA;
    securePayload[1] = (uint8_t)((ctx->dsqOut >> 24) & 0xffu);
    securePayload[2] = (uint8_t)((ctx->dsqOut >> 16) & 0xffu);
    securePayload[3] = (uint8_t)((ctx->dsqOut >> 8) & 0xffu);
    securePayload[4] = (uint8_t)(ctx->dsqOut & 0xffu);

    securePayload[5] = (uint8_t)((ctx->aim >> 8) & 0xffu);
    securePayload[6] = (uint8_t)(ctx->aim & 0xffu);
    securePayload[7] = (uint8_t)((ctx->ais >> 8) & 0xffu);
    securePayload[8] = (uint8_t)(ctx->ais & 0xffu);

    securePayload[9] = (uint8_t)((asduLength >> 8) & 0xffu);
    securePayload[10] = (uint8_t)(asduLength & 0xffu);

    memcpy(securePayload + APROFILE_HEADER_SIZE, asduStart, (size_t)asduLength);

    uint8_t mac[APROFILE_MAC_SIZE];
    if (!protectPayload(ctx, ctx->sessionKeyOutbound, securePayload, APROFILE_HEADER_SIZE,
                       securePayload + APROFILE_HEADER_SIZE, (size_t)asduLength,
                       securePayload + APROFILE_HEADER_SIZE, mac))
        return -1;

    memcpy(securePayload + APROFILE_HEADER_SIZE + asduLength, mac, APROFILE_MAC_SIZE);

    int secureLength = APROFILE_HEADER_SIZE + asduLength + APROFILE_MAC_SIZE;

    /* ensure the target frame has enough capacity */
    T104Frame_resetFrame((Frame)frame);
    if (T104Frame_getSpaceLeft((Frame)frame) < secureLength)
        return -1;

    T104Frame_appendBytes((Frame)frame, securePayload, secureLength);

    return secureLength;
}

static bool
encodeAssociationRequest(AProfileContext ctx)
{
    if (!ensureEcdhInitialized(ctx))
        return false;

    if (!generateRandomBytes(ctx->assocNonceLocal, APROFILE_ASSOC_NONCE_SIZE))
        fallbackDeterministicKey(ctx->assocNonceLocal, APROFILE_ASSOC_NONCE_SIZE);

    uint8_t pub[MBEDTLS_ECP_MAX_PT_LEN];
    size_t pubLen = 0;
    if (mbedtls_ecdh_make_public(&ctx->ecdhCtx, &pubLen, pub, sizeof(pub), generateRandomBytesMbedtls, NULL) != 0)
        return false;

    uint8_t buf[APROFILE_MAX_CONTROL_PDU];
    size_t offset = 0;
    buf[offset++] = APROFILE_TAG_ASSOCIATION_REQUEST;
    buf[offset++] = APROFILE_ASSOC_VERSION;
    buf[offset++] = (uint8_t)((ctx->aim >> 8) & 0xffu);
    buf[offset++] = (uint8_t)(ctx->aim & 0xffu);
    buf[offset++] = (uint8_t)((ctx->ais >> 8) & 0xffu);
    buf[offset++] = (uint8_t)(ctx->ais & 0xffu);
    buf[offset++] = (uint8_t)ctx->algorithm;
    buf[offset++] = (uint8_t)pubLen;
    memcpy(buf + offset, pub, pubLen);
    offset += pubLen;
    buf[offset++] = APROFILE_ASSOC_NONCE_SIZE;
    memcpy(buf + offset, ctx->assocNonceLocal, APROFILE_ASSOC_NONCE_SIZE);
    offset += APROFILE_ASSOC_NONCE_SIZE;

    ctx->associationInProgress = true;
    ctx->awaitingAssociationResponse = true;
    return queueControlPdu(ctx, buf, offset);
}

static bool
encodeAssociationResponse(AProfileContext ctx, const uint8_t* peerPub, size_t peerPubLen, const uint8_t* peerNonce,
                          size_t peerNonceLen)
{
    if ((peerPub == NULL) || (peerNonce == NULL) || (peerNonceLen != APROFILE_ASSOC_NONCE_SIZE))
        return false;

    if (!ensureEcdhInitialized(ctx))
        return false;

    if (!generateRandomBytes(ctx->assocNonceLocal, APROFILE_ASSOC_NONCE_SIZE))
        fallbackDeterministicKey(ctx->assocNonceLocal, APROFILE_ASSOC_NONCE_SIZE);

    uint8_t responderPub[MBEDTLS_ECP_MAX_PT_LEN];
    size_t responderPubLen = 0;
    if (mbedtls_ecdh_make_public(&ctx->ecdhCtx, &responderPubLen, responderPub, sizeof(responderPub),
                                 generateRandomBytesMbedtls, NULL) != 0)
        return false;

    if (mbedtls_ecdh_read_public(&ctx->ecdhCtx, peerPub, peerPubLen) != 0)
        return false;

    uint8_t shared[64];
    size_t sharedLen = 0;
    if (mbedtls_ecdh_calc_secret(&ctx->ecdhCtx, &sharedLen, shared, sizeof(shared), generateRandomBytesMbedtls, NULL) != 0)
        return false;

    uint8_t salt[APROFILE_ASSOC_NONCE_SIZE * 2];
    memcpy(salt, peerNonce, APROFILE_ASSOC_NONCE_SIZE);
    memcpy(salt + APROFILE_ASSOC_NONCE_SIZE, ctx->assocNonceLocal, APROFILE_ASSOC_NONCE_SIZE);

    if (!deriveUpdateKeysFromSecret(shared, sharedLen, salt, sizeof(salt), ctx->aim, ctx->ais, ctx->authUpdateKey,
                                    ctx->encUpdateKey))
        return false;

    ctx->updateKeysSet = true;

    uint8_t buf[APROFILE_MAX_CONTROL_PDU];
    size_t offset = 0;
    buf[offset++] = APROFILE_TAG_ASSOCIATION_RESPONSE;
    buf[offset++] = APROFILE_ASSOC_VERSION;
    buf[offset++] = (uint8_t)((ctx->aim >> 8) & 0xffu);
    buf[offset++] = (uint8_t)(ctx->aim & 0xffu);
    buf[offset++] = (uint8_t)((ctx->ais >> 8) & 0xffu);
    buf[offset++] = (uint8_t)(ctx->ais & 0xffu);
    buf[offset++] = (uint8_t)ctx->algorithm;
    buf[offset++] = (uint8_t)responderPubLen;
    memcpy(buf + offset, responderPub, responderPubLen);
    offset += responderPubLen;
    buf[offset++] = APROFILE_ASSOC_NONCE_SIZE;
    memcpy(buf + offset, ctx->assocNonceLocal, APROFILE_ASSOC_NONCE_SIZE);
    offset += APROFILE_ASSOC_NONCE_SIZE;
    buf[offset++] = APROFILE_ASSOC_NONCE_SIZE;
    memcpy(buf + offset, peerNonce, APROFILE_ASSOC_NONCE_SIZE);
    offset += APROFILE_ASSOC_NONCE_SIZE;

    uint8_t mac[APROFILE_CONTROL_MAC_SIZE];
    if (!hmacTruncated(ctx->authUpdateKey, APROFILE_SESSION_KEY_LENGTH, buf + 1, offset - 1, mac))
        return false;

    buf[offset++] = APROFILE_CONTROL_MAC_SIZE;
    memcpy(buf + offset, mac, APROFILE_CONTROL_MAC_SIZE);
    offset += APROFILE_CONTROL_MAC_SIZE;

    return queueControlPdu(ctx, buf, offset);
}

static bool
processAssociationResponse(AProfileContext ctx, const uint8_t* buf, size_t len)
{
    if ((ctx == NULL) || (buf == NULL) || (len < 7))
        return false;

    size_t offset = 1; /* skip tag */
    if (buf[offset++] != APROFILE_ASSOC_VERSION)
        return false;

    ctx->aim = ((uint16_t)buf[offset] << 8) | (uint16_t)buf[offset + 1];
    offset += 2;
    ctx->ais = ((uint16_t)buf[offset] << 8) | (uint16_t)buf[offset + 1];
    offset += 2;
    ctx->algorithm = (AProfileDpaAlgorithm)buf[offset++];

    uint8_t peerPubLen = buf[offset++];
    if (len < offset + peerPubLen + 1)
        return false;

    const uint8_t* peerPub = buf + offset;
    offset += peerPubLen;

    uint8_t nonceLen = buf[offset++];
    if ((nonceLen != APROFILE_ASSOC_NONCE_SIZE) || (len < offset + nonceLen))
        return false;
    memcpy(ctx->assocNoncePeer, buf + offset, nonceLen);
    offset += nonceLen;

    if (len < offset + APROFILE_ASSOC_NONCE_SIZE + 1 + APROFILE_CONTROL_MAC_SIZE)
        return false;

    uint8_t initiatorNonceLen = buf[offset++];
    if ((initiatorNonceLen != APROFILE_ASSOC_NONCE_SIZE) || (len < offset + initiatorNonceLen + 1))
        return false;
    memcpy(ctx->assocNonceLocal, buf + offset, initiatorNonceLen);
    offset += initiatorNonceLen;

    uint8_t macLen = buf[offset++];
    if ((macLen != APROFILE_CONTROL_MAC_SIZE) || (len < offset + macLen))
        return false;

    const uint8_t* mac = buf + offset;

    if (!ensureEcdhInitialized(ctx))
        return false;

    if (mbedtls_ecdh_read_public(&ctx->ecdhCtx, peerPub, peerPubLen) != 0)
        return false;

    uint8_t shared[64];
    size_t sharedLen = 0;
    if (mbedtls_ecdh_calc_secret(&ctx->ecdhCtx, &sharedLen, shared, sizeof(shared), generateRandomBytesMbedtls, NULL) != 0)
        return false;

    uint8_t salt[APROFILE_ASSOC_NONCE_SIZE * 2];
    memcpy(salt, ctx->assocNonceLocal, APROFILE_ASSOC_NONCE_SIZE);
    memcpy(salt + APROFILE_ASSOC_NONCE_SIZE, ctx->assocNoncePeer, APROFILE_ASSOC_NONCE_SIZE);

    if (!deriveUpdateKeysFromSecret(shared, sharedLen, salt, sizeof(salt), ctx->aim, ctx->ais, ctx->authUpdateKey,
                                    ctx->encUpdateKey))
        return false;

    if (!hmacTruncated(ctx->authUpdateKey, APROFILE_SESSION_KEY_LENGTH, buf + 1, len - 1 - macLen, ctx->inboundBuffer))
        return false;

    if (memcmp(ctx->inboundBuffer, mac, macLen) != 0)
        return false;

    ctx->updateKeysSet = true;
    ctx->associationInProgress = false;
    ctx->awaitingAssociationResponse = false;
    ctx->rekeyRequested = true; /* trigger session key change */
    return true;
}

static bool
encodeSessionKeyChangeRequest(AProfileContext ctx)
{
    if (ctx->updateKeysSet == false)
        return false;

    uint8_t newOutbound[APROFILE_SESSION_KEY_LENGTH];
    uint8_t newInbound[APROFILE_SESSION_KEY_LENGTH];

    if (!generateRandomBytes(newOutbound, sizeof(newOutbound)))
        fallbackDeterministicKey(newOutbound, sizeof(newOutbound));

    if (!generateRandomBytes(newInbound, sizeof(newInbound)))
        fallbackDeterministicKey(newInbound, sizeof(newInbound));

    uint8_t wrappedOutbound[APROFILE_SESSION_KEY_WRAP_LENGTH];
    uint8_t wrappedInbound[APROFILE_SESSION_KEY_WRAP_LENGTH];

    if (!aesKwWrap(ctx->encUpdateKey, newOutbound, sizeof(newOutbound), wrappedOutbound, sizeof(wrappedOutbound)))
        return false;
    if (!aesKwWrap(ctx->encUpdateKey, newInbound, sizeof(newInbound), wrappedInbound, sizeof(wrappedInbound)))
        return false;

    uint8_t buf[APROFILE_MAX_CONTROL_PDU];
    size_t offset = 0;
    buf[offset++] = APROFILE_TAG_SESSION_KEY_CHANGE_REQUEST;
    buf[offset++] = APROFILE_ASSOC_VERSION;
    buf[offset++] = sizeof(wrappedOutbound);
    memcpy(buf + offset, wrappedOutbound, sizeof(wrappedOutbound));
    offset += sizeof(wrappedOutbound);
    buf[offset++] = sizeof(wrappedInbound);
    memcpy(buf + offset, wrappedInbound, sizeof(wrappedInbound));
    offset += sizeof(wrappedInbound);

    if (!hmacTruncated(ctx->authUpdateKey, APROFILE_SESSION_KEY_LENGTH, buf + 1, offset - 1, buf + offset))
        return false;

    offset += APROFILE_CONTROL_MAC_SIZE;

    memcpy(ctx->pendingSessionKeyOutbound, newOutbound, sizeof(newOutbound));
    memcpy(ctx->pendingSessionKeyInbound, newInbound, sizeof(newInbound));
    ctx->hasPendingSessionKeys = true;
    ctx->awaitingKeyChangeResponse = true;

    return queueControlPdu(ctx, buf, offset);
}

static bool
encodeSessionKeyChangeResponse(AProfileContext ctx, bool success)
{
    uint8_t buf[32];
    size_t offset = 0;
    buf[offset++] = APROFILE_TAG_SESSION_KEY_CHANGE_RESPONSE;
    buf[offset++] = APROFILE_ASSOC_VERSION;
    buf[offset++] = success ? 0x00 : 0x01;

    if (!hmacTruncated(ctx->authUpdateKey, APROFILE_SESSION_KEY_LENGTH, buf + 1, offset - 1, buf + offset))
        return false;

    offset += APROFILE_CONTROL_MAC_SIZE;

    return queueControlPdu(ctx, buf, offset);
}

static bool
processSessionKeyChangeResponse(AProfileContext ctx, const uint8_t* buf, size_t len)
{
    if ((len < 1 + 1 + 1 + APROFILE_CONTROL_MAC_SIZE) || (buf[1] != APROFILE_ASSOC_VERSION))
        return false;

    uint8_t status = buf[2];
    const uint8_t* mac = buf + 3;

    uint8_t computed[APROFILE_CONTROL_MAC_SIZE];
    if (!hmacTruncated(ctx->authUpdateKey, APROFILE_SESSION_KEY_LENGTH, buf + 1, 2, computed))
        return false;

    if (memcmp(mac, computed, APROFILE_CONTROL_MAC_SIZE) != 0)
        return false;

    if (status == 0x00 && ctx->hasPendingSessionKeys)
    {
        AProfile_setSessionKeys(ctx, ctx->pendingSessionKeyOutbound, ctx->pendingSessionKeyInbound);
        ctx->hasPendingSessionKeys = false;
    }

    ctx->awaitingKeyChangeResponse = false;
    return (status == 0x00);
}

AProfileContext
AProfile_create(void)
{
#if (CONFIG_CS104_APROFILE == 1)
    AProfileContext ctx = (AProfileContext)GLOBAL_CALLOC(1, sizeof(struct sAProfileContext));

    if (ctx)
    {
        ctx->dsqOut = 1;
        ctx->dsqInExpected = 1;
        ctx->aim = 0;
        ctx->ais = 0;
        ctx->algorithm = APROFILE_DPA_HMAC_SHA256;
        memset(&ctx->telemetry, 0, sizeof(ctx->telemetry));
        ctx->associationEstablished = false;
        ctx->certificatesVerified = false;
        ctx->rolesAuthorized = false;
        ctx->updateKeysSet = false;
        ctx->associationInProgress = false;
        ctx->awaitingAssociationResponse = false;
        ctx->awaitingKeyChangeResponse = false;
        ctx->ecdhInitialized = false;
        ctx->hasPendingSessionKeys = false;
        ctx->pendingControlLen = 0;
        mbedtls_ecdh_init(&ctx->ecdhCtx);
    }

    return ctx;
#else
    return NULL;
#endif
}

void
AProfile_destroy(AProfileContext ctx)
{
    if (ctx)
    {
        if (ctx->ecdhInitialized)
            mbedtls_ecdh_free(&ctx->ecdhCtx);
        GLOBAL_FREEMEM(ctx);
    }
}

bool
AProfile_setAssociationIds(AProfileContext ctx, uint16_t aim, uint16_t ais)
{
    if (ctx == NULL)
        return false;

    ctx->aim = aim;
    ctx->ais = ais;
    return true;
}

bool
AProfile_getAssociationIds(AProfileContext ctx, uint16_t* aim, uint16_t* ais)
{
    if (ctx == NULL)
        return false;

    if (aim)
        *aim = ctx->aim;
    if (ais)
        *ais = ctx->ais;

    return true;
}

bool
AProfile_setDpaAlgorithm(AProfileContext ctx, AProfileDpaAlgorithm algorithm)
{
    if (ctx == NULL)
        return false;

    if ((algorithm == APROFILE_DPA_AES256_GCM) || (selectMac(algorithm) != NULL))
    {
        ctx->algorithm = algorithm;
        return true;
    }

    return false;
}

AProfileDpaAlgorithm
AProfile_getDpaAlgorithm(AProfileContext ctx)
{
    if (ctx == NULL)
        return APROFILE_DPA_HMAC_SHA256;

    return ctx->algorithm;
}

void
AProfile_getTelemetry(AProfileContext ctx, AProfileTelemetry* telemetryOut)
{
    if ((ctx == NULL) || (telemetryOut == NULL))
        return;

    *telemetryOut = ctx->telemetry;
}

void
AProfile_clearTelemetry(AProfileContext ctx)
{
    if (ctx == NULL)
        return;

    memset(&ctx->telemetry, 0, sizeof(ctx->telemetry));
}

bool
AProfile_setSessionKeys(AProfileContext ctx, const uint8_t* outboundKey, const uint8_t* inboundKey)
{
    if ((ctx == NULL) || (outboundKey == NULL) || (inboundKey == NULL))
        return false;

    memcpy(ctx->sessionKeyOutbound, outboundKey, APROFILE_SESSION_KEY_LENGTH);
    memcpy(ctx->sessionKeyInbound, inboundKey, APROFILE_SESSION_KEY_LENGTH);
    ctx->sessionKeysSet = true;
    ctx->sessionKeyBirthMs = Hal_getMonotonicTimeInMs();
    ctx->rekeyRequested = false;
    ctx->sentMessages = 0;
    AProfile_resetCounters(ctx);
    updateAssociationState(ctx);

    return true;
}

bool
AProfile_setUpdateKeys(AProfileContext ctx, const uint8_t* authKey, const uint8_t* encKey)
{
    if ((ctx == NULL) || (authKey == NULL) || (encKey == NULL))
        return false;

    memcpy(ctx->authUpdateKey, authKey, APROFILE_SESSION_KEY_LENGTH);
    memcpy(ctx->encUpdateKey, encKey, APROFILE_SESSION_KEY_LENGTH);
    ctx->updateKeysSet = true;

    return true;
}

bool
AProfile_unwrapAndInstallSessionKeys(AProfileContext ctx, const uint8_t* wrappedOutbound,
                                     size_t wrappedOutboundLen, const uint8_t* wrappedInbound,
                                     size_t wrappedInboundLen)
{
    if ((ctx == NULL) || (wrappedOutbound == NULL) || (wrappedInbound == NULL))
        return false;

    if ((wrappedOutboundLen != APROFILE_SESSION_KEY_WRAP_LENGTH) ||
        (wrappedInboundLen != APROFILE_SESSION_KEY_WRAP_LENGTH) || (ctx->updateKeysSet == false))
        return false;

    uint8_t outboundKey[APROFILE_SESSION_KEY_LENGTH];
    uint8_t inboundKey[APROFILE_SESSION_KEY_LENGTH];

    if (!aesKwUnwrap(ctx->encUpdateKey, wrappedOutbound, wrappedOutboundLen, outboundKey, sizeof(outboundKey)))
        return false;

    if (!aesKwUnwrap(ctx->encUpdateKey, wrappedInbound, wrappedInboundLen, inboundKey, sizeof(inboundKey)))
        return false;

    return AProfile_setSessionKeys(ctx, outboundKey, inboundKey);
}

bool
AProfile_markCertificatesVerified(AProfileContext ctx, bool localCertificateOk, bool peerCertificateOk)
{
    if (ctx == NULL)
        return false;

    ctx->certificatesVerified = localCertificateOk && peerCertificateOk;
    updateAssociationState(ctx);
    return ctx->certificatesVerified;
}

bool
AProfile_markRolesAuthorized(AProfileContext ctx, bool rolesAuthorized)
{
    if (ctx == NULL)
        return false;

    ctx->rolesAuthorized = rolesAuthorized;
    updateAssociationState(ctx);

    return ctx->rolesAuthorized;
}

bool
AProfile_forceLocalKeyRotation(AProfileContext ctx)
{
    return localSessionKeyChange(ctx);
}

void
AProfile_resetCounters(AProfileContext ctx)
{
    if (ctx == NULL)
        return;

    ctx->dsqOut = 1;
    ctx->dsqInExpected = 1;
    ctx->sentMessages = 0;
    ctx->rekeyRequested = false;
    ctx->awaitingKeyChangeResponse = false;
}

bool
AProfile_requiresRekey(AProfileContext ctx)
{
#if (CONFIG_CS104_APROFILE == 1)
    if ((ctx == NULL) || (ctx->sessionKeysSet == false))
        return false;

    if (ctx->rekeyRequested)
        return true;

    ctx->rekeyRequested = shouldRequestRekey(ctx);
    return ctx->rekeyRequested;
#else
    (void)ctx;
    return false;
#endif
}

bool
AProfile_onStartDT(AProfileContext ctx)
{
    if (ctx == NULL)
        return false;

    ctx->startDtSeen = true;
    AProfile_resetCounters(ctx);

    return true;
}

bool
AProfile_ready(AProfileContext ctx)
{
#if (CONFIG_CS104_APROFILE == 1)
    return (ctx != NULL) && ctx->startDtSeen && ctx->sessionKeysSet && ctx->associationEstablished;
#else
    return false;
#endif
}

bool
AProfile_wrapOutAsdu(AProfileContext ctx, T104Frame frame)
{
    if ((ctx == NULL) || (frame == NULL))
        return false;

#if (CONFIG_CS104_APROFILE == 1)
    if (ctx->pendingControlLen > 0)
        return AProfile_emitPendingControl(ctx, frame);

    if ((ctx->startDtSeen == false))
        return false;

    if (ctx->associationEstablished == false)
    {
        if (ctx->associationInProgress == false)
            encodeAssociationRequest(ctx);

        if (ctx->pendingControlLen > 0)
            return AProfile_emitPendingControl(ctx, frame);

        return false;
    }

    if (ctx->sessionKeysSet == false)
        return false;

    if (AProfile_requiresRekey(ctx))
    {
        if ((ctx->awaitingKeyChangeResponse == false) && !encodeSessionKeyChangeRequest(ctx))
            return false;

        if (ctx->pendingControlLen > 0)
            return AProfile_emitPendingControl(ctx, frame);

        return false;
    }

    int result = wrapPayload(ctx, frame);
    if (result > 0)
    {
        ctx->dsqOut++;
        ctx->sentMessages++;
        return true;
    }
#endif

    return false;
}

AProfileKind
AProfile_handleInPdu(AProfileContext ctx, const uint8_t* in, int inSize,
                     const uint8_t** out, int* outSize)
{
    if ((ctx == NULL) || (in == NULL) || (out == NULL) || (outSize == NULL))
    {
        *out = NULL;
        *outSize = 0;
        return APROFILE_CTRL_MSG;
    }

    if (inSize > 1)
    {
        if (in[0] == APROFILE_TAG_ASSOCIATION_REQUEST)
        {
            size_t offset = 1;
            if (inSize >= 8)
            {
                uint8_t version = in[offset++];
                uint16_t aim = ((uint16_t)in[offset] << 8) | (uint16_t)in[offset + 1];
                offset += 2;
                uint16_t ais = ((uint16_t)in[offset] << 8) | (uint16_t)in[offset + 1];
                offset += 2;
                AProfile_setAssociationIds(ctx, aim, ais);
                ctx->algorithm = (AProfileDpaAlgorithm)in[offset++];
                uint8_t peerPubLen = in[offset++];
                if ((version == APROFILE_ASSOC_VERSION) && (inSize >= (int)(offset + peerPubLen + 1)))
                {
                    const uint8_t* peerPub = in + offset;
                    offset += peerPubLen;
                    uint8_t nonceLen = in[offset++];
                    if ((nonceLen == APROFILE_ASSOC_NONCE_SIZE) && (inSize >= (int)(offset + nonceLen)))
                    {
                        memcpy(ctx->assocNoncePeer, in + offset, nonceLen);
                        encodeAssociationResponse(ctx, peerPub, peerPubLen, ctx->assocNoncePeer, nonceLen);
                    }
                }
            }

            ctx->telemetry.controlFrames++;
            return APROFILE_CTRL_MSG;
        }

        if ((in[0] == APROFILE_TAG_ASSOCIATION_RESPONSE) && (ctx->awaitingAssociationResponse))
        {
            processAssociationResponse(ctx, in, (size_t)inSize);
            ctx->telemetry.controlFrames++;
            return APROFILE_CTRL_MSG;
        }

        if (in[0] == APROFILE_TAG_SESSION_KEY_CHANGE_RESPONSE)
        {
            processSessionKeyChangeResponse(ctx, in, (size_t)inSize);
            ctx->telemetry.controlFrames++;
            return APROFILE_CTRL_MSG;
        }
    }

    if (inSize < (APROFILE_HEADER_SIZE + APROFILE_MAC_SIZE))
    {
        *out = in;
        *outSize = inSize;
        ctx->telemetry.controlFrames++;
        return APROFILE_PLAINTEXT;
    }

    if (in[0] != APROFILE_TAG_SECURE_DATA)
    {
#if (CONFIG_CS104_APROFILE == 1)
        if ((in[0] == APROFILE_TAG_SESSION_KEY_CHANGE_REQUEST) && ctx->updateKeysSet)
        {
            size_t offset = 2; /* tag + version */
            if ((inSize > (int)offset) && (in[1] == APROFILE_ASSOC_VERSION))
            {
                uint8_t wrapOutLen = in[offset++];
                if (inSize >= (int)(offset + wrapOutLen + 1))
                {
                    const uint8_t* wrappedOutbound = in + offset;
                    offset += wrapOutLen;
                    uint8_t wrapInLen = in[offset++];
                    if (inSize >= (int)(offset + wrapInLen + APROFILE_CONTROL_MAC_SIZE))
                    {
                        const uint8_t* wrappedInbound = in + offset;
                        offset += wrapInLen;
                        const uint8_t* mac = in + offset;

                        uint8_t calc[APROFILE_CONTROL_MAC_SIZE];
                        if (hmacTruncated(ctx->authUpdateKey, APROFILE_SESSION_KEY_LENGTH, in + 1, offset - 1, calc) &&
                            (memcmp(calc, mac, APROFILE_CONTROL_MAC_SIZE) == 0))
                        {
                            uint8_t newOut[APROFILE_SESSION_KEY_LENGTH];
                            uint8_t newIn[APROFILE_SESSION_KEY_LENGTH];

                            bool ok = aesKwUnwrap(ctx->encUpdateKey, wrappedOutbound, wrapOutLen, newOut,
                                                  sizeof(newOut));
                            ok = ok && aesKwUnwrap(ctx->encUpdateKey, wrappedInbound, wrapInLen, newIn, sizeof(newIn));

                            if (ok)
                                ok = AProfile_setSessionKeys(ctx, newOut, newIn);

                            encodeSessionKeyChangeResponse(ctx, ok);
                        }
                    }
                }
            }

            ctx->telemetry.controlFrames++;
            return APROFILE_CTRL_MSG;
        }

        if (ctx->sessionKeysSet && ctx->associationEstablished)
        {
            *out = NULL;
            *outSize = 0;
            ctx->telemetry.plaintextRejected++;
            ctx->telemetry.controlFrames++;
            return APROFILE_CTRL_MSG;
        }
#endif

        *out = in;
        *outSize = inSize;
        ctx->telemetry.controlFrames++;
        return APROFILE_PLAINTEXT;
    }

#if (CONFIG_CS104_APROFILE == 1)
    if (ctx->sessionKeysSet == false)
    {
        *out = NULL;
        *outSize = 0;
        return APROFILE_CTRL_MSG;
    }

    uint32_t receivedDsq = ((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) |
                           ((uint32_t)in[3] << 8) | (uint32_t)in[4];
    uint16_t receivedAim = ((uint16_t)in[5] << 8) | (uint16_t)in[6];
    uint16_t receivedAis = ((uint16_t)in[7] << 8) | (uint16_t)in[8];
    int encodedAsduLen = ((int)in[9] << 8) | (int)in[10];

    if ((encodedAsduLen < 0) || (APROFILE_HEADER_SIZE + encodedAsduLen + APROFILE_MAC_SIZE > inSize))
    {
        *out = NULL;
        *outSize = 0;
        ctx->telemetry.secureRejected++;
        ctx->telemetry.controlFrames++;
        return APROFILE_CTRL_MSG;
    }

    if (encodedAsduLen > IEC60870_5_104_MAX_ASDU_LENGTH)
    {
        *out = NULL;
        *outSize = 0;
        ctx->telemetry.secureRejected++;
        ctx->telemetry.controlFrames++;
        return APROFILE_CTRL_MSG;
    }

    if ((ctx->aim != 0) && (receivedAim != ctx->aim))
    {
        *out = NULL;
        *outSize = 0;
        ctx->telemetry.secureRejected++;
        ctx->telemetry.controlFrames++;
        return APROFILE_CTRL_MSG;
    }

    if ((ctx->ais != 0) && (receivedAis != ctx->ais))
    {
        *out = NULL;
        *outSize = 0;
        ctx->telemetry.secureRejected++;
        ctx->telemetry.controlFrames++;
        return APROFILE_CTRL_MSG;
    }

    if ((receivedDsq != ctx->dsqInExpected) || (ctx->dsqInExpected == UINT32_MAX))
    {
        *out = NULL;
        *outSize = 0;
        ctx->telemetry.replayRejected++;
        ctx->telemetry.controlFrames++;
        return APROFILE_CTRL_MSG;
    }

    const int macOffset = APROFILE_HEADER_SIZE + encodedAsduLen;
    uint8_t* decrypted = ctx->inboundBuffer;
    if (!validateAndDecryptPayload(ctx, ctx->sessionKeyInbound, in, APROFILE_HEADER_SIZE, in + APROFILE_HEADER_SIZE,
                                   (size_t)encodedAsduLen, in + macOffset, decrypted))
    {
        *out = NULL;
        *outSize = 0;
        ctx->telemetry.secureRejected++;
        ctx->telemetry.controlFrames++;
        return APROFILE_CTRL_MSG;
    }

    ctx->dsqInExpected++;

    *out = decrypted;
    *outSize = encodedAsduLen;
    ctx->telemetry.secureAccepted++;

    return APROFILE_SECURE_DATA;
#else
    *out = in;
    *outSize = inSize;
    return APROFILE_PLAINTEXT;
#endif
}

bool
AProfile_hasPendingControl(AProfileContext ctx)
{
    return (ctx != NULL) && (ctx->pendingControlLen > 0);
}

bool
AProfile_emitPendingControl(AProfileContext ctx, T104Frame frame)
{
    if ((ctx == NULL) || (frame == NULL) || (ctx->pendingControlLen == 0))
        return false;

    T104Frame_resetFrame((Frame)frame);
    if (T104Frame_getSpaceLeft((Frame)frame) < (int)ctx->pendingControlLen)
        return false;

    T104Frame_appendBytes((Frame)frame, ctx->pendingControl, (int)ctx->pendingControlLen);
    ctx->pendingControlLen = 0;
    return true;
}
