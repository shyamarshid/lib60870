#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cs101_information_objects.h"
#include "cs104_security.h"
#include "cs104_slave.h"
#include "hal_thread.h"
#include "lib60870_config.h"

static volatile bool running = true;

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
rawMessageHandler(void* parameter, uint8_t* msg, int msgSize, bool sent)
{
    CS104_SecurityConfig* sec = (CS104_SecurityConfig*) parameter;

    printf(sent ? "SERVER SEND: " : "SERVER RECV: ");
    print_hex(msg, msgSize);
    printf("\n");

    if (msgSize > 6 && msg[0] == 0x68) {
        int payloadLen = msgSize - 6;
        classifyApdu(msg + 6, payloadLen, sec);
    }
}

static bool
asduHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu)
{
    (void) parameter;

    printf("[SERVER] ASDU type=%i COT=%i CA=%i\n", (int) CS101_ASDU_getTypeID(asdu), CS101_ASDU_getCOT(asdu), CS101_ASDU_getCA(asdu));

    if (CS101_ASDU_getTypeID(asdu) == C_SC_NA_1 && CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION) {
        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
        IMasterConnection_sendASDU(connection, asdu);
        return true;
    }

    return false;
}

static void
sigintHandler(int sig)
{
    (void) sig;
    running = false;
}

int
main(int argc, char** argv)
{
    (void) argc;
    (void) argv;

    printf("=== CS104 IEC 62351-5 A-profile debug server ===\n");
#if CONFIG_CS104_APROFILE_AEAD
    printf("AEAD support: enabled (GCM available)\n");
#else
    printf("AEAD support: disabled\n");
#endif

    signal(SIGINT, sigintHandler);

    CS104_Slave slave = CS104_Slave_create(1, 1);

    CS104_SecurityConfig sec = {0};
    sec.aim = 0x1001;
    sec.ais = 0x2001;
#ifdef APROFILE_DPA_HMAC_SHA256_TCP
    sec.dpaAlgorithm = APROFILE_DPA_HMAC_SHA256_TCP;
#else
    sec.dpaAlgorithm = APROFILE_DPA_HMAC_SHA256;
#endif

    CS104_CertConfig cert = { .localCertificateVerified = true, .peerCertificateVerified = true };
    CS104_RoleConfig role = { .rolesAvailable = false };

    CS104_Slave_setSecurityConfig(slave, &sec, &cert, &role);
    CS104_Slave_setRawMessageHandler(slave, rawMessageHandler, &sec);
    CS104_Slave_setASDUHandler(slave, asduHandler, NULL);

    CS101_AppLayerParameters alParams = CS104_Slave_getAppLayerParameters(slave);

    CS104_Slave_start(slave);

    int counter = 0;

    while (running) {
        HalThread_sleep(1000);

        CS101_ASDU asdu = CS101_ASDU_create(alParams, false, CS101_COT_PERIODIC, 0, 1, false, false);
        InformationObject io = (InformationObject) MeasuredValueScaled_create(NULL, 110, counter++, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(asdu, io);
        InformationObject_destroy(io);

        CS104_Slave_enqueueASDU(slave, asdu);
        CS101_ASDU_destroy(asdu);
    }

    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);

    return 0;
}
