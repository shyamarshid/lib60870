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

#ifndef APROFILE_CONTEXT_H_
#define APROFILE_CONTEXT_H_

#include <stdbool.h>
#include <stdint.h>

typedef struct sAProfileContext* AProfileContext;

#define APROFILE_SESSION_KEY_LENGTH 32
#define APROFILE_SESSION_KEY_WRAP_LENGTH (APROFILE_SESSION_KEY_LENGTH + 8)

typedef enum
{
    APROFILE_PLAINTEXT = 0,
    APROFILE_SECURE_DATA,
    APROFILE_CTRL_MSG
} AProfileKind;

typedef enum
{
    APROFILE_DPA_HMAC_SHA256 = 0,
    APROFILE_DPA_HMAC_SHA3_256,
    APROFILE_DPA_HMAC_BLAKE2S_256,
    APROFILE_DPA_AES256_GCM
} AProfileDpaAlgorithm;

typedef struct
{
    uint32_t secureAccepted;
    uint32_t secureRejected;
    uint32_t replayRejected;
    uint32_t controlFrames;
} AProfileTelemetry;

typedef struct sT104Frame* T104Frame;

AProfileContext AProfile_create(void);
void AProfile_destroy(AProfileContext ctx);

bool AProfile_onStartDT(AProfileContext ctx);
bool AProfile_ready(AProfileContext ctx);

bool AProfile_setAssociationIds(AProfileContext ctx, uint16_t aim, uint16_t ais);
bool AProfile_getAssociationIds(AProfileContext ctx, uint16_t* aim, uint16_t* ais);

bool AProfile_setDpaAlgorithm(AProfileContext ctx, AProfileDpaAlgorithm algorithm);
AProfileDpaAlgorithm AProfile_getDpaAlgorithm(AProfileContext ctx);

void AProfile_getTelemetry(AProfileContext ctx, AProfileTelemetry* telemetryOut);
void AProfile_clearTelemetry(AProfileContext ctx);

bool AProfile_setSessionKeys(AProfileContext ctx, const uint8_t* outboundKey, const uint8_t* inboundKey);
bool AProfile_setUpdateKeys(AProfileContext ctx, const uint8_t* authKey, const uint8_t* encKey);
bool AProfile_unwrapAndInstallSessionKeys(AProfileContext ctx, const uint8_t* wrappedOutbound,
                                         size_t wrappedOutboundLen, const uint8_t* wrappedInbound,
                                         size_t wrappedInboundLen);
bool AProfile_markCertificatesVerified(AProfileContext ctx, bool localCertificateOk, bool peerCertificateOk);
bool AProfile_markRolesAuthorized(AProfileContext ctx, bool rolesAuthorized);
bool AProfile_forceLocalKeyRotation(AProfileContext ctx);
void AProfile_resetCounters(AProfileContext ctx);

/*
 * Return true when a new session key set should be negotiated. This is
 * driven by configurable limits for DSQ wraparound, message volume, and
 * maximum key age.
 */
bool AProfile_requiresRekey(AProfileContext ctx);

bool AProfile_wrapOutAsdu(AProfileContext ctx, T104Frame frame);
AProfileKind AProfile_handleInPdu(AProfileContext ctx, const uint8_t* in, int inSize,
                                  const uint8_t** out, int* outSize);

#endif /* APROFILE_CONTEXT_H_ */
