#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cs101_information_objects.h"
#include "cs104_security.h"
#include "cs104_slave.h"
#include "hal_thread.h"
#include "hal_time.h"
#include "lib60870_config.h"

static volatile bool running = true;

static void
sigint_handler(int sig)
{
    (void) sig;
    running = false;
}

static void
printCP56Time2a(CP56Time2a time)
{
    printf("%02i:%02i:%02i %02i/%02i/%04i", CP56Time2a_getHour(time), CP56Time2a_getMinute(time),
           CP56Time2a_getSecond(time), CP56Time2a_getDayOfMonth(time), CP56Time2a_getMonth(time),
           CP56Time2a_getYear(time) + 2000);
}

static const char*
getDpaName(AProfileDpaAlgorithm algo)
{
    switch (algo) {
    case APROFILE_DPA_HMAC_SHA256:
        return "HMAC-SHA256";
#ifdef APROFILE_DPA_HMAC_SHA256_TCP
    case APROFILE_DPA_HMAC_SHA256_TCP:
        return "HMAC-SHA256 (TCP 16-byte tag)";
#endif
    case APROFILE_DPA_HMAC_SHA3_256:
        return "HMAC-SHA3-256";
    case APROFILE_DPA_HMAC_BLAKE2S_256:
        return "HMAC-BLAKE2s-256";
    case APROFILE_DPA_AES256_GCM:
        return "AES-256-GCM";
    default:
        return "Unknown";
    }
}

static void
print_hex(const uint8_t* b, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02X ", b[i]);
}

static const uint8_t SERVER_OUTBOUND_SESSION_KEY[APROFILE_SESSION_KEY_LENGTH] = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40
};

static const uint8_t SERVER_INBOUND_SESSION_KEY[APROFILE_SESSION_KEY_LENGTH] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};

static const uint8_t UPDATE_AUTH_KEY[APROFILE_SESSION_KEY_LENGTH] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
};

static const uint8_t UPDATE_ENC_KEY[APROFILE_SESSION_KEY_LENGTH] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF
};

static void
configureSecurity(CS104_SecurityConfig* sec)
{
    memset(sec, 0, sizeof(*sec));

    sec->aim = 0x1001;
    sec->ais = 0x2001;
#ifdef APROFILE_DPA_HMAC_SHA256_TCP
    sec->dpaAlgorithm = APROFILE_DPA_HMAC_SHA256_TCP;
#else
    sec->dpaAlgorithm = APROFILE_DPA_HMAC_SHA256;
#endif

    sec->hasStaticSessionKeys = true;
    memcpy(sec->outboundSessionKey, SERVER_OUTBOUND_SESSION_KEY, sizeof(sec->outboundSessionKey));
    memcpy(sec->inboundSessionKey, SERVER_INBOUND_SESSION_KEY, sizeof(sec->inboundSessionKey));

    sec->hasUpdateKeys = true;
    memcpy(sec->authenticationUpdateKey, UPDATE_AUTH_KEY, sizeof(sec->authenticationUpdateKey));
    memcpy(sec->encryptionUpdateKey, UPDATE_ENC_KEY, sizeof(sec->encryptionUpdateKey));
}

static void
printSecurityConfig(const CS104_SecurityConfig* sec)
{
    printf("[SERVER] ALS config: AIM=0x%04X AIS=0x%04X DPA=%s\n", sec->aim, sec->ais, getDpaName(sec->dpaAlgorithm));
}

static void
handleControlTag(uint8_t tag, const CS104_SecurityConfig* sec)
{
    if (tag == 0xE1) {
        printf("[ALS] Association 0x%04X/0x%04X started, DPA=%s\n", sec->aim, sec->ais, getDpaName(sec->dpaAlgorithm));
    }
    else if (tag == 0xE2) {
        printf("[ALS] Association 0x%04X/0x%04X completed, DPA=%s\n", sec->aim, sec->ais, getDpaName(sec->dpaAlgorithm));
    }
    else if (tag == 0xE3) {
        printf("[ALS] Session Key Change started\n");
    }
    else if (tag == 0xE4) {
        printf("[ALS] Session Key Change completed\n");
    }
}

static void
classifyApdu(const uint8_t* payload, int payloadLen, const CS104_SecurityConfig* sec)
{
    if (payloadLen <= 0)
        return;

    uint8_t tag = payload[0];

    if ((tag >= 0xE1) && (tag <= 0xE4)) {
        handleControlTag(tag, sec);
        printf("APROFILE CTRL %02X\n", tag);
    }
    else if (tag == 0xF1) {
        if (payloadLen >= 11) {
            uint32_t dsq = ((uint32_t)payload[1] << 24) | ((uint32_t)payload[2] << 16)
                         | ((uint32_t)payload[3] << 8) | payload[4];
            uint16_t aim = ((uint16_t)payload[5] << 8) | payload[6];
            uint16_t ais = ((uint16_t)payload[7] << 8) | payload[8];
            uint16_t adl = ((uint16_t)payload[9] << 8) | payload[10];
            printf("SECURE DATA: DSQ=%u AIM=0x%04X AIS=0x%04X ADL=%u\n", dsq, aim, ais, adl);
            if (aim != sec->aim || ais != sec->ais)
                printf("  (AIM/AIS mismatch with local config)\n");
        }
        else {
            printf("SECURE DATA: len=%d (too short for header)\n", payloadLen);
        }
    }
    else {
        printf("PLAINTEXT ASDU len=%d\n", payloadLen);
    }
}

static void
rawMessageHandler(void* parameter, IMasterConnection connection, uint8_t* msg, int msgSize, bool sent)
{
    CS104_SecurityConfig* sec = (CS104_SecurityConfig*) parameter;

    (void) connection;

    printf(sent ? "SERVER SEND: " : "SERVER RECV: ");
    print_hex(msg, msgSize);
    printf("\n");

    if (msgSize > 6 && msg[0] == 0x68) {
        int payloadLen = msgSize - 6;
        classifyApdu(msg + 6, payloadLen, sec);
    }
}

static bool
clockSyncHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, CP56Time2a newTime)
{
    (void) parameter;

    printf("Process time sync command with time ");
    printCP56Time2a(newTime);
    printf("\n");

    uint64_t newSystemTimeInMs = CP56Time2a_toMsTimestamp(newTime);

    (void) newSystemTimeInMs;

    /* Set time for ACT_CON message */
    CP56Time2a_setFromMsTimestamp(newTime, Hal_getTimeInMs());

    /* update system time here */

    return true;
}

static bool
interrogationHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, uint8_t qoi)
{
    (void) parameter;

    printf("Received interrogation for group %i\n", qoi);

    if (qoi == 20) {
        CS101_AppLayerParameters alParams = IMasterConnection_getApplicationLayerParameters(connection);

        IMasterConnection_sendACT_CON(connection, asdu, false);

        /* The CS101 specification only allows information objects without timestamp in GI responses */

        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION, 0, 1, false, false);

        InformationObject io = (InformationObject) MeasuredValueScaled_create(NULL, 100, -1, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(newAsdu, io);

        CS101_ASDU_addInformationObject(newAsdu, (InformationObject)
            MeasuredValueScaled_create((MeasuredValueScaled) io, 101, 23, IEC60870_QUALITY_GOOD));

        CS101_ASDU_addInformationObject(newAsdu, (InformationObject)
            MeasuredValueScaled_create((MeasuredValueScaled) io, 102, 2300, IEC60870_QUALITY_GOOD));

        InformationObject_destroy(io);

        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);

        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION, 0, 1, false, false);

        io = (InformationObject) SinglePointInformation_create(NULL, 104, true, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(newAsdu, io);

        CS101_ASDU_addInformationObject(newAsdu, (InformationObject)
            SinglePointInformation_create((SinglePointInformation) io, 105, false, IEC60870_QUALITY_GOOD));

        InformationObject_destroy(io);

        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);

        newAsdu = CS101_ASDU_create(alParams, true, CS101_COT_INTERROGATED_BY_STATION, 0, 1, false, false);

        CS101_ASDU_addInformationObject(newAsdu, io = (InformationObject) SinglePointInformation_create(NULL, 300, true, IEC60870_QUALITY_GOOD));
        CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 301, false, IEC60870_QUALITY_GOOD));
        CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 302, true, IEC60870_QUALITY_GOOD));
        CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 303, false, IEC60870_QUALITY_GOOD));
        CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 304, true, IEC60870_QUALITY_GOOD));
        CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 305, false, IEC60870_QUALITY_GOOD));
        CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 306, true, IEC60870_QUALITY_GOOD));
        CS101_ASDU_addInformationObject(newAsdu, (InformationObject) SinglePointInformation_create((SinglePointInformation) io, 307, false, IEC60870_QUALITY_GOOD));

        InformationObject_destroy(io);

        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);

        newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_INTERROGATED_BY_STATION, 0, 1, false, false);

        io = (InformationObject) BitString32_create(NULL, 500, 0xaaaa);
        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);

        IMasterConnection_sendASDU(connection, newAsdu);
        CS101_ASDU_destroy(newAsdu);

        IMasterConnection_sendACT_TERM(connection, asdu);
    }
    else {
        IMasterConnection_sendACT_CON(connection, asdu, true);
    }

    return true;
}

static bool
asduHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu)
{
    (void) parameter;

    printf("[SERVER] ASDU type=%i COT=%i CA=%i\n", (int) CS101_ASDU_getTypeID(asdu), CS101_ASDU_getCOT(asdu), CS101_ASDU_getCA(asdu));

    if (CS101_ASDU_getTypeID(asdu) == C_SC_NA_1) {
        if (CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION) {
            InformationObject io = CS101_ASDU_getElement(asdu, 0);

            if (io) {
                if (InformationObject_getObjectAddress(io) == 5000) {
                    SingleCommand sc = (SingleCommand) io;

                    printf("IOA: %i switch to %i\n", InformationObject_getObjectAddress(io), SingleCommand_getState(sc));

                    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
                }
                else {
                    CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
                }

                InformationObject_destroy(io);
            }
            else {
                printf("ERROR: message has no valid information object\n");
                return true;
            }
        }
        else {
            CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_COT);
        }

        IMasterConnection_sendASDU(connection, asdu);
        return true;
    }

    return false;
}

static bool
connectionRequestHandler(void* parameter, const char* ipAddress)
{
    (void) parameter;

    printf("New connection request from %s\n", ipAddress);

    return true;
}

static bool connected = false;

static void
connectionEventHandler(void* parameter, IMasterConnection con, CS104_PeerConnectionEvent event)
{
    (void) parameter;

    if (event == CS104_CON_EVENT_CONNECTION_OPENED) {
        printf("Connection opened (%p)\n", con);
        connected = true;
    }
    else if (event == CS104_CON_EVENT_CONNECTION_CLOSED) {
        printf("Connection closed (%p)\n", con);
    }
    else if (event == CS104_CON_EVENT_ACTIVATED) {
        printf("Connection activated (%p)\n", con);
    }
    else if (event == CS104_CON_EVENT_DEACTIVATED) {
        printf("Connection deactivated (%p)\n", con);
    }
}

int
main(int argc, char** argv)
{
    (void) argc;
    (void) argv;

#if (CONFIG_CS104_APROFILE != 1)
    printf("This example requires CONFIG_CS104_APROFILE=1 to be enabled in lib60870_config.h\n");
    return -1;
#endif

    printf("=== CS104 IEC 62351-5 A-profile debug server ===\n");
#if CONFIG_CS104_APROFILE_AEAD
    printf("AEAD support: enabled (GCM available)\n");
#else
    printf("AEAD support: disabled\n");
#endif

    signal(SIGINT, sigint_handler);

    CS104_Slave slave = CS104_Slave_create(10, 10);

    /* Set security options for ALS */
    CS104_SecurityConfig sec;
    configureSecurity(&sec);
    printSecurityConfig(&sec);

    CS104_CertConfig cert = { .localCertificateVerified = true, .peerCertificateVerified = true };
    CS104_RoleConfig role = { .rolesAvailable = true };

    CS104_Slave_setSecurityConfig(slave, &sec, &cert, &role);

    CS104_Slave_setServerMode(slave, CS104_MODE_SINGLE_REDUNDANCY_GROUP);

    CS101_AppLayerParameters alParams = CS104_Slave_getAppLayerParameters(slave);
    CS104_APCIParameters apciParams = CS104_Slave_getConnectionParameters(slave);

    printf("APCI parameters:\n");
    printf("  t0: %i\n", apciParams->t0);
    printf("  t1: %i\n", apciParams->t1);
    printf("  t2: %i\n", apciParams->t2);
    printf("  t3: %i\n", apciParams->t3);
    printf("  k: %i\n", apciParams->k);
    printf("  w: %i\n", apciParams->w);

    CS104_Slave_setClockSyncHandler(slave, clockSyncHandler, NULL);
    CS104_Slave_setInterrogationHandler(slave, interrogationHandler, NULL);
    CS104_Slave_setASDUHandler(slave, asduHandler, NULL);
    CS104_Slave_setConnectionRequestHandler(slave, connectionRequestHandler, NULL);
    CS104_Slave_setConnectionEventHandler(slave, connectionEventHandler, NULL);
    CS104_Slave_setRawMessageHandler(slave, rawMessageHandler, &sec);

    CS104_Slave_start(slave);

    if (CS104_Slave_isRunning(slave) == false) {
        printf("Starting server failed!\n");
        CS104_Slave_destroy(slave);
        return -1;
    }

    int16_t scaledValue = 0;

    while (running) {
        Thread_sleep(1000);

        CS101_ASDU newAsdu = CS101_ASDU_create(alParams, false, CS101_COT_PERIODIC, 0, 1, false, false);
        InformationObject io = (InformationObject) MeasuredValueScaled_create(NULL, 110, scaledValue, IEC60870_QUALITY_GOOD);
        scaledValue++;

        CS101_ASDU_addInformationObject(newAsdu, io);
        InformationObject_destroy(io);

        /* Add ASDU to slave event queue */
        CS104_Slave_enqueueASDU(slave, newAsdu);
        CS101_ASDU_destroy(newAsdu);
    }

    Thread_sleep(1000);
    printf("Stopping server\n");
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);

    Thread_sleep(500);

    return 0;
}
