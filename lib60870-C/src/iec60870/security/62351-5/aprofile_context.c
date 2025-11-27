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

#include <stddef.h>
#include <string.h>

#define APROFILE_TAG_SECURE_DATA 0xF1
#define APROFILE_HEADER_SIZE 7 /* tag (1) + DSQ (4) + ASDU length (2) */
#define APROFILE_MAC_SIZE 8

/*
 * This implementation provides a lightweight, self-contained version of the
 * IEC 62351-5 A-profile data processing logic. It focuses on deterministic
 * replay protection (DSQ handling) and integrity tagging using an internal
 * keyed checksum. The checksum is intentionally simple to avoid new
 * dependencies while keeping the code functional and compile-ready. The
 * structure mirrors the standard message flow: the outgoing ASDU is wrapped
 * with a header and authentication tag, and the incoming PDU is validated and
 * unwrapped before the ASDU parser consumes it.
 */

struct sAProfileContext
{
    bool startDtSeen;
    uint32_t dsqOut;
    uint32_t dsqInExpected;
    uint8_t sessionKey[32];
};

static void
generateSessionKey(AProfileContext ctx)
{
    /*
     * A simple deterministic key schedule derived from the monotonic clock.
     * The goal is to avoid external dependencies while still producing a
     * non-zero key stream for the internal checksum. This is not intended to
     * be cryptographically strong; the TLS layer (IEC 62351-3) must be used to
     * provide confidentiality when required.
     */
    uint64_t seed = Hal_getMonotonicTimeInMs();

    for (size_t i = 0; i < sizeof(ctx->sessionKey); i++)
    {
        seed ^= (seed << 13);
        seed ^= (seed >> 7);
        seed ^= (seed << 17);
        ctx->sessionKey[i] = (uint8_t)(seed & 0xffu);
    }
}

static void
calculateMac(const AProfileContext ctx, const uint8_t* data, size_t dataLen, uint8_t outMac[APROFILE_MAC_SIZE])
{
    /*
     * Fowler–Noll–Vo style keyed checksum. The function folds the session key
     * into the accumulator before processing the payload. The resulting
     * 64‑bit tag is exported in big-endian layout.
     */
    uint64_t acc = 1469598103934665603ULL; /* FNV offset basis */
    const uint64_t prime = 1099511628211ULL;

    for (size_t i = 0; i < sizeof(ctx->sessionKey); i++)
    {
        acc ^= ctx->sessionKey[i];
        acc *= prime;
    }

    for (size_t i = 0; i < dataLen; i++)
    {
        acc ^= data[i];
        acc *= prime;
    }

    for (int i = APROFILE_MAC_SIZE - 1; i >= 0; i--)
    {
        outMac[i] = (uint8_t)(acc & 0xffu);
        acc >>= 8;
    }
}

static int
wrapPayload(AProfileContext ctx, T104Frame frame)
{
    int msgSize = T104Frame_getMsgSize((Frame)frame);
    if (msgSize <= IEC60870_5_104_APCI_LENGTH)
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
    calculateMac(ctx, securePayload, (size_t)(APROFILE_HEADER_SIZE + asduLength), mac);
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
        generateSessionKey(ctx);
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
AProfile_onStartDT(AProfileContext ctx)
{
    if (ctx == NULL)
        return false;

    ctx->startDtSeen = true;
    ctx->dsqOut = 1;
    ctx->dsqInExpected = 1;

    return true;
}

bool
AProfile_ready(AProfileContext ctx)
{
#if (CONFIG_CS104_APROFILE == 1)
    return (ctx != NULL) && ctx->startDtSeen;
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
    if (ctx->startDtSeen == false)
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
    uint32_t receivedDsq = ((uint32_t)in[1] << 24) | ((uint32_t)in[2] << 16) |
                           ((uint32_t)in[3] << 8) | (uint32_t)in[4];
    int encodedAsduLen = ((int)in[5] << 8) | (int)in[6];

    if ((encodedAsduLen < 0) || (APROFILE_HEADER_SIZE + encodedAsduLen + APROFILE_MAC_SIZE > inSize))
    {
        *out = NULL;
        *outSize = 0;
        return APROFILE_CTRL_MSG;
    }

    if (receivedDsq != ctx->dsqInExpected)
    {
        *out = NULL;
        *outSize = 0;
        return APROFILE_CTRL_MSG;
    }

    const int macOffset = APROFILE_HEADER_SIZE + encodedAsduLen;
    uint8_t expectedMac[APROFILE_MAC_SIZE];
    calculateMac(ctx, in, (size_t)macOffset, expectedMac);

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

