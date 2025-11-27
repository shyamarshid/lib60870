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

#ifndef CS104_SECURITY_H_
#define CS104_SECURITY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include "aprofile_context.h"

#if (CONFIG_CS104_APROFILE == 1)
struct mbedtls_x509_crt;
struct mbedtls_pk_context;
#endif

typedef struct sCS104_Connection* CS104_Connection;
typedef struct sCS104_Slave* CS104_Slave;

typedef struct
{
    uint16_t aim;
    uint16_t ais;
    AProfileDpaAlgorithm dpaAlgorithm;
    bool hasStaticSessionKeys;
    uint8_t outboundSessionKey[APROFILE_SESSION_KEY_LENGTH];
    uint8_t inboundSessionKey[APROFILE_SESSION_KEY_LENGTH];
    bool hasWrappedSessionKeys;
    uint8_t wrappedOutboundSessionKey[APROFILE_SESSION_KEY_WRAP_LENGTH];
    uint8_t wrappedInboundSessionKey[APROFILE_SESSION_KEY_WRAP_LENGTH];
    bool hasUpdateKeys;
    uint8_t authenticationUpdateKey[APROFILE_SESSION_KEY_LENGTH];
    uint8_t encryptionUpdateKey[APROFILE_SESSION_KEY_LENGTH];
} CS104_SecurityConfig;

typedef struct
{
    bool localCertificateVerified;
    bool peerCertificateVerified;
#if (CONFIG_CS104_APROFILE == 1)
    /* Optional mbedTLS credentials already parsed in memory */
    const struct mbedtls_x509_crt* localCertificate;
    const struct mbedtls_pk_context* localPrivateKey;
    const struct mbedtls_x509_crt* peerCertificate;
#endif
} CS104_CertConfig;

typedef struct
{
    bool rolesAvailable;
} CS104_RoleConfig;

typedef enum
{
    CS104_SECURITY_EVENT_NONE = 0
} CS104_SecurityEvent;

typedef struct
{
    int dummy;
} CS104_SecurityStats;

typedef void (*CS104_SecurityEventHandler)(void* parameter, CS104_SecurityEvent event,
                                           const CS104_SecurityStats* stats);

void CS104_Connection_setSecurityConfig(CS104_Connection connection,
                                        const CS104_SecurityConfig* sec,
                                        const CS104_CertConfig* cert,
                                        const CS104_RoleConfig* role);

void CS104_Connection_setSecurityEventHandler(CS104_Connection connection,
                                              CS104_SecurityEventHandler handler,
                                              void* parameter);

void CS104_Slave_setSecurityConfig(CS104_Slave slave,
                                   const CS104_SecurityConfig* sec,
                                   const CS104_CertConfig* cert,
                                   const CS104_RoleConfig* role);

#ifdef __cplusplus
}
#endif

#endif /* CS104_SECURITY_H_ */
