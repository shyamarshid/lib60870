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
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"

#define APROFILE_TAG_SECURE_DATA 0xF1
#define APROFILE_HEADER_SIZE 11 /* tag (1) + DSQ (4) + AIM (2) + AIS (2) + ASDU length (2) */
#define APROFILE_MAC_SIZE 16 /* Integrity tag size for GCM or truncated MAC */

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
    bool associationEstablished;
    bool certificatesVerified;
    bool rolesAuthorized;
    bool updateKeysSet;
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

static void
deriveNonceFromHeader(const uint8_t* header, size_t headerLen, uint8_t nonce[12])
{
    memset(nonce, 0, 12);

    /* Use DSQ||AIM||AIS as nonce input to guarantee monotonicity */
    size_t usable = (headerLen > 1) ? (headerLen - 1) : 0;
    if (usable > 12)
        usable = 12;

    memcpy(nonce, header + 1, usable);
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
        deriveNonceFromHeader(header, headerLen, nonce);

        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0)
        {
            ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintextLen, nonce, sizeof(nonce), header,
                                            headerLen, plaintext, outPayload, APROFILE_MAC_SIZE, outMac);
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
        deriveNonceFromHeader(header, headerLen, nonce);

        int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0)
        {
            ret = mbedtls_gcm_auth_decrypt(&gcm, payloadLen, nonce, sizeof(nonce), header, headerLen, mac,
                                           APROFILE_MAC_SIZE, cipherPayload, outPlaintext);
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
        GLOBAL_FREEMEM(ctx);
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
    if ((ctx->startDtSeen == false) || (ctx->sessionKeysSet == false) || (ctx->associationEstablished == false))
        return false;

    if (AProfile_requiresRekey(ctx))
    {
        if (!localSessionKeyChange(ctx))
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

    if (inSize < (APROFILE_HEADER_SIZE + APROFILE_MAC_SIZE))
    {
        *out = in;
        *outSize = inSize;
        ctx->telemetry.controlFrames++;
        return APROFILE_PLAINTEXT;
    }

    if (in[0] != APROFILE_TAG_SECURE_DATA)
    {
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
