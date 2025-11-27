#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cs101_information_objects.h"
#include "cs104_connection.h"
#include "cs104_security.h"
#include "hal_thread.h"

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

    printf(sent ? "CLIENT SEND: " : "CLIENT RECV: ");
    print_hex(msg, msgSize);
    printf("\n");

    if (msgSize > 6 && msg[0] == 0x68) {
        int payloadLen = msgSize - 6;
        classifyApdu(msg + 6, payloadLen, sec);
    }
}

static void
connectionHandler(void* parameter, CS104_Connection connection, CS104_ConnectionEvent event)
{
    (void) parameter;
    (void) connection;

    switch (event) {
    case CS104_CONNECTION_OPENED:
        printf("[CLIENT] Connection opened\n");
        break;
    case CS104_CONNECTION_CLOSED:
        printf("[CLIENT] Connection closed\n");
        break;
    case CS104_CONNECTION_STARTDT_CON_RECEIVED:
        printf("[CLIENT] STARTDT_CON received\n");
        break;
    case CS104_CONNECTION_STOPDT_CON_RECEIVED:
        printf("[CLIENT] STOPDT_CON received\n");
        break;
    case CS104_CONNECTION_FAILED:
        printf("[CLIENT] Connection failed\n");
        break;
    default:
        break;
    }
}

static bool
asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    (void) parameter;
    (void) address;

    printf("[CLIENT] RX ASDU type=%i COT=%i CA=%i elements=%i\n", (int) CS101_ASDU_getTypeID(asdu), CS101_ASDU_getCOT(asdu),
           CS101_ASDU_getCA(asdu), CS101_ASDU_getNumberOfElements(asdu));
    return true;
}

int
main(int argc, char** argv)
{
    (void) argc;
    (void) argv;

    printf("=== CS104 IEC 62351-5 A-profile debug client ===\n");

    CS104_Connection conn = CS104_Connection_create("127.0.0.1", 2404);

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

    CS104_Connection_setSecurityConfig(conn, &sec, &cert, &role);

    CS104_Connection_setConnectionHandler(conn, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(conn, asduReceivedHandler, NULL);
    CS104_Connection_setRawMessageHandler(conn, rawMessageHandler, &sec);

    if (!CS104_Connection_connect(conn)) {
        printf("Failed to connect to server\n");
        CS104_Connection_destroy(conn);
        return -1;
    }

    CS101_AppLayerParameters alParams = CS104_Connection_getAppLayerParameters(conn);

    HalThread_sleep(500);

    CS101_ASDU gi = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION, 0, 1, false, false);
    CS101_ASDU_setTypeID(gi, C_IC_NA_1);
    InformationObject qoi = (InformationObject) InterrogationCommand_create(NULL, 0, IEC60870_QOI_STATION);
    CS101_ASDU_addInformationObject(gi, qoi);
    InformationObject_destroy(qoi);
    CS104_Connection_sendASDU(conn, gi);
    CS101_ASDU_destroy(gi);

    CS101_ASDU cmd = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION, 0, 1, false, false);
    CS101_ASDU_setTypeID(cmd, C_SC_NA_1);
    InformationObject sc = (InformationObject) SingleCommand_create(NULL, 5000, true, IEC60870_QUALITY_GOOD);
    CS101_ASDU_addInformationObject(cmd, sc);
    InformationObject_destroy(sc);
    CS104_Connection_sendASDU(conn, cmd);
    CS101_ASDU_destroy(cmd);

    for (int i = 0; i < 10; i++) {
        HalThread_sleep(1000);
    }

    CS104_Connection_close(conn);
    CS104_Connection_destroy(conn);

    return 0;
}
