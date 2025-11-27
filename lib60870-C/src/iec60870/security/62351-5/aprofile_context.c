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

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"

#define APROFILE_TAG_SECURE_DATA 0xF1
#define APROFILE_HEADER_SIZE 7 /* tag (1) + DSQ (4) + ASDU length (2) */
#define APROFILE_MAC_SIZE 16 /* HMAC-SHA-256 truncated for 104/TCP */

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
    uint32_t dsqOut;
    uint32_t dsqInExpected;
    uint8_t sessionKeyOutbound[APROFILE_SESSION_KEY_LENGTH];
    uint8_t sessionKeyInbound[APROFILE_SESSION_KEY_LENGTH];
};

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context drbg_ctx;
static bool rng_initialized = false;

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
}

static bool
calculateMac(const uint8_t* key, const uint8_t* data, size_t dataLen, uint8_t outMac[APROFILE_MAC_SIZE])
{
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL)
        return false;

    uint8_t fullMac[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_md_hmac(md_info, key, APROFILE_SESSION_KEY_LENGTH, data, dataLen, fullMac) != 0)
        return false;

    memcpy(outMac, fullMac, APROFILE_MAC_SIZE);
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

    memcpy(securePayload + APROFILE_HEADER_SIZE, asduStart, (size_t)asduLength);

    securePayload[0] = APROFILE_TAG_SECURE_DATA;
    securePayload[1] = (uint8_t)((ctx->dsqOut >> 24) & 0xffu);
    securePayload[2] = (uint8_t)((ctx->dsqOut >> 16) & 0xffu);
    securePayload[3] = (uint8_t)((ctx->dsqOut >> 8) & 0xffu);
    securePayload[4] = (uint8_t)(ctx->dsqOut & 0xffu);

    securePayload[5] = (uint8_t)((asduLength >> 8) & 0xffu);
    securePayload[6] = (uint8_t)(asduLength & 0xffu);

    uint8_t mac[APROFILE_MAC_SIZE];
    if (!calculateMac(ctx->sessionKeyOutbound, securePayload, (size_t)(APROFILE_HEADER_SIZE + asduLength), mac))
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
        initializeSessionKeys(ctx);
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
AProfile_setSessionKeys(AProfileContext ctx, const uint8_t* outboundKey, const uint8_t* inboundKey)
{
    if ((ctx == NULL) || (outboundKey == NULL) || (inboundKey == NULL))
        return false;

    memcpy(ctx->sessionKeyOutbound, outboundKey, APROFILE_SESSION_KEY_LENGTH);
    memcpy(ctx->sessionKeyInbound, inboundKey, APROFILE_SESSION_KEY_LENGTH);
    ctx->sessionKeysSet = true;

    return true;
}

void
AProfile_resetCounters(AProfileContext ctx)
{
    if (ctx == NULL)
        return;

    ctx->dsqOut = 1;
    ctx->dsqInExpected = 1;
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
    return (ctx != NULL) && ctx->startDtSeen && ctx->sessionKeysSet;
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
    if ((ctx->startDtSeen == false) || (ctx->sessionKeysSet == false))
        return false;

    int result = wrapPayload(ctx, frame);
    if (result > 0)
    {
        ctx->dsqOut++;
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
        return APROFILE_PLAINTEXT;
    }

    if (in[0] != APROFILE_TAG_SECURE_DATA)
    {
        *out = in;
        *outSize = inSize;
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
    int encodedAsduLen = ((int)in[5] << 8) | (int)in[6];

    if ((encodedAsduLen < 0) || (APROFILE_HEADER_SIZE + encodedAsduLen + APROFILE_MAC_SIZE > inSize))
    {
        *out = NULL;
        *outSize = 0;
        return APROFILE_CTRL_MSG;
    }

    if ((receivedDsq != ctx->dsqInExpected) || (ctx->dsqInExpected == UINT32_MAX))
    {
        *out = NULL;
        *outSize = 0;
        return APROFILE_CTRL_MSG;
    }

    const int macOffset = APROFILE_HEADER_SIZE + encodedAsduLen;
    uint8_t expectedMac[APROFILE_MAC_SIZE];
    if (!calculateMac(ctx->sessionKeyInbound, in, (size_t)macOffset, expectedMac))
    {
        *out = NULL;
        *outSize = 0;
        return APROFILE_CTRL_MSG;
    }

    if (memcmp(expectedMac, in + macOffset, APROFILE_MAC_SIZE) != 0)
    {
        *out = NULL;
        *outSize = 0;
        return APROFILE_CTRL_MSG;
    }

    ctx->dsqInExpected++;

    *out = in + APROFILE_HEADER_SIZE;
    *outSize = encodedAsduLen;

    return APROFILE_SECURE_DATA;
#else
    *out = in;
    *outSize = inSize;
    return APROFILE_PLAINTEXT;
#endif
}
