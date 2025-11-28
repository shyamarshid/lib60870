#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib60870_config.h"
#include "cs101_information_objects.h"
#include "cs104_connection.h"
#include "cs104_security.h"
#include "hal_thread.h"
#include "hal_time.h"

#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

typedef struct {
    mbedtls_x509_crt local_crt;
    mbedtls_pk_context local_key;
    mbedtls_x509_crt peer_crt;
    bool have_local;
    bool have_peer;
} MbedCreds;

static MbedCreds creds;

static void
init_creds(void)
{
    mbedtls_x509_crt_init(&creds.local_crt);
    mbedtls_x509_crt_init(&creds.peer_crt);
    mbedtls_pk_init(&creds.local_key);
}

static bool
load_local_pair(const char* crt, const char* key)
{
    if ((crt == NULL) || (key == NULL))
        return false;

    int rc1 = mbedtls_x509_crt_parse_file(&creds.local_crt, crt);
    int rc2 = mbedtls_pk_parse_keyfile(&creds.local_key, key, NULL);

    creds.have_local = (rc1 == 0) && (rc2 == 0);
    return creds.have_local;
}

static bool
load_peer_crt(const char* crt)
{
    if (crt == NULL)
        return false;

    int rc = mbedtls_x509_crt_parse_file(&creds.peer_crt, crt);
    creds.have_peer = (rc == 0);
    return creds.have_peer;
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

static volatile bool startDtConfirmed = false;
static volatile bool associationEstablished = false;

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
configureSecurity(CS104_SecurityConfig* sec, uint16_t aim, uint16_t ais)
{
    memset(sec, 0, sizeof(*sec));

    sec->aim = aim;
    sec->ais = ais;
#ifdef APROFILE_DPA_HMAC_SHA256_TCP
    sec->dpaAlgorithm = APROFILE_DPA_HMAC_SHA256_TCP;
#else
    sec->dpaAlgorithm = APROFILE_DPA_HMAC_SHA256;
#endif

    sec->hasUpdateKeys = true;
    memcpy(sec->authenticationUpdateKey, UPDATE_AUTH_KEY, sizeof(sec->authenticationUpdateKey));
    memcpy(sec->encryptionUpdateKey, UPDATE_ENC_KEY, sizeof(sec->encryptionUpdateKey));
}

static void
printSecurityConfig(const CS104_SecurityConfig* sec)
{
    printf("[CLIENT] ALS config: AIM=0x%04X AIS=0x%04X DPA=%s (keys: %s)\n", sec->aim, sec->ais,
           getDpaName(sec->dpaAlgorithm), "handshake/ECDH");
}

static CS104_CertConfig
buildCertConfig(const char* localCertPath, const char* localKeyPath, const char* peerCertPath)
{
    CS104_CertConfig cert = {0};

    if (localCertPath && localKeyPath) {
        bool loaded = load_local_pair(localCertPath, localKeyPath);
        cert.localCertificateVerified = loaded;
        cert.localCertificate = loaded ? &creds.local_crt : NULL;
        cert.localPrivateKey = loaded ? &creds.local_key : NULL;

        printf("[CLIENT] Local certificate: %s (%s)\n", localCertPath,
               loaded ? "loaded" : "failed to load - verification skipped");
        printf("[CLIENT] Local private key: %s (%s)\n", localKeyPath,
               loaded ? "loaded" : "failed to load - verification skipped");
    }
    else {
        printf("[CLIENT] Local certificate/key: not fully provided (verification skipped)\n");
    }

    if (peerCertPath) {
        bool loaded = load_peer_crt(peerCertPath);
        cert.peerCertificateVerified = loaded;
        cert.peerCertificate = loaded ? &creds.peer_crt : NULL;

        printf("[CLIENT] Peer certificate: %s (%s)\n", peerCertPath,
               loaded ? "loaded" : "failed to load - verification skipped");
    }
    else {
        printf("[CLIENT] Peer certificate: none provided (verification skipped)\n");
    }

    return cert;
}

static void
printClientUsage(void)
{
    printf("Usage: client_aprofile_debug [ip] [port] [localIp] [localPort] [--aim 0xID] [--ais 0xID] [--local-cert PATH] [--local-key PATH] [--peer-cert PATH]\n");
}

static void
handleControlTag(uint8_t tag, const CS104_SecurityConfig* sec)
{
    if (tag == 0xE1) {
        printf("[ALS] Association 0x%04X/0x%04X started, DPA=%s\n", sec->aim, sec->ais, getDpaName(sec->dpaAlgorithm));
    }
    else if (tag == 0xE2) {
        printf("[ALS] Association 0x%04X/0x%04X completed, DPA=%s\n", sec->aim, sec->ais, getDpaName(sec->dpaAlgorithm));
        associationEstablished = true;
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
rawMessageHandler(void* parameter, uint8_t* msg, int msgSize, bool sent)
{
    CS104_SecurityConfig* sec = (CS104_SecurityConfig*) parameter;

    printf(sent ? "CLIENT SEND: " : "CLIENT RECV: ");
    print_hex(msg, msgSize);
    printf("\n");

    if ((msgSize >= 2) && (msg[0] == 0x68)) {
        int apduLen = msg[1];
        int payloadLen = apduLen - 4; /* length field excludes start byte and length byte */

        /* If reported length does not match observed bytes, flag it for debugging */
        if ((apduLen + 2) != msgSize)
            printf("[CLIENT] Warning: APDU length byte=%d but frame has %d bytes\n", apduLen, msgSize);

        if (payloadLen > 0 && msgSize >= 6)
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
        associationEstablished = false;
        break;
    case CS104_CONNECTION_STARTDT_CON_RECEIVED:
        printf("[CLIENT] STARTDT_CON received\n");
        startDtConfirmed = true;
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
#if (CONFIG_CS104_APROFILE != 1)
    printf("This example requires CONFIG_CS104_APROFILE=1 to be enabled in lib60870_config.h\n");
    return -1;
#endif

    const char* ip = "localhost";
    uint16_t port = IEC_60870_5_104_DEFAULT_PORT;
    const char* localIp = NULL;
    int localPort = -1;
    uint16_t aim = 0x1001;
    uint16_t ais = 0x2001;
    const char* localCertPath = NULL;
    const char* peerCertPath = NULL;
    const char* localKeyPath = NULL;

    bool ipSet = false;
    bool portSet = false;
    bool localIpSet = false;
    bool localPortSet = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            printClientUsage();
            return 0;
        }
        else if (strcmp(argv[i], "--aim") == 0 && (i + 1 < argc)) {
            aim = (uint16_t) strtol(argv[++i], NULL, 0);
        }
        else if (strcmp(argv[i], "--ais") == 0 && (i + 1 < argc)) {
            ais = (uint16_t) strtol(argv[++i], NULL, 0);
        }
        else if (strcmp(argv[i], "--local-cert") == 0 && (i + 1 < argc)) {
            localCertPath = argv[++i];
        }
        else if (strcmp(argv[i], "--local-key") == 0 && (i + 1 < argc)) {
            localKeyPath = argv[++i];
        }
        else if (strcmp(argv[i], "--peer-cert") == 0 && (i + 1 < argc)) {
            peerCertPath = argv[++i];
        }
        else {
            if (ipSet == false) {
                ip = argv[i];
                ipSet = true;
            }
            else if (portSet == false) {
                port = (uint16_t) atoi(argv[i]);
                portSet = true;
            }
            else if (localIpSet == false) {
                localIp = argv[i];
                localIpSet = true;
            }
            else if (localPortSet == false) {
                localPort = atoi(argv[i]);
                localPortSet = true;
            }
        }
    }

    init_creds();

    printf("=== CS104 IEC 62351-5 A-profile debug client ===\n");
    printf("Connecting to: %s:%u\n", ip, port);

    CS104_Connection conn = CS104_Connection_create(ip, port);

    CS104_SecurityConfig sec;
    configureSecurity(&sec, aim, ais);
    printSecurityConfig(&sec);
    printf("[CLIENT] ALS handshake enabled; expect E1-E4 control frames\n");

    CS104_CertConfig cert = buildCertConfig(localCertPath, localKeyPath, peerCertPath);
    CS104_RoleConfig role = { .rolesAvailable = true };

    CS104_Connection_setSecurityConfig(conn, &sec, &cert, &role);

    CS104_Connection_setConnectionHandler(conn, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(conn, asduReceivedHandler, NULL);
    CS104_Connection_setRawMessageHandler(conn, rawMessageHandler, &sec);

    /* optional bind to local IP address/interface */
    if (localIp)
        CS104_Connection_setLocalAddress(conn, localIp, localPort);

    if (!CS104_Connection_connect(conn)) {
        printf("Failed to connect to server\n");
        CS104_Connection_destroy(conn);
        return -1;
    }

    CS101_AppLayerParameters alParams = CS104_Connection_getAppLayerParameters(conn);

    startDtConfirmed = false;
    associationEstablished = false;
    CS104_Connection_sendStartDT(conn);

    for (int i = 0; (i < 50) && (startDtConfirmed == false); i++)
        Thread_sleep(100);

    if (startDtConfirmed == false)
        printf("[CLIENT] STARTDT_CON not received within timeout\n");

    for (int i = 0; (i < 200) && (associationEstablished == false); i++)
        Thread_sleep(50);

    if (associationEstablished == false) {
        printf("[CLIENT] ALS association not completed within timeout; skipping application traffic\n");
    }
    else {
        CS101_ASDU gi = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION, 0, 1, false, false);
        CS101_ASDU_setTypeID(gi, C_IC_NA_1);
        InformationObject qoi = (InformationObject) InterrogationCommand_create(NULL, 0, IEC60870_QOI_STATION);
        CS101_ASDU_addInformationObject(gi, qoi);
        InformationObject_destroy(qoi);
        CS104_Connection_sendASDU(conn, gi);
        CS101_ASDU_destroy(gi);

        CS101_ASDU cmd = CS101_ASDU_create(alParams, false, CS101_COT_ACTIVATION, 0, 1, false, false);
        CS101_ASDU_setTypeID(cmd, C_SC_NA_1);
        InformationObject sc = (InformationObject) SingleCommand_create(NULL, 5000, true, false, IEC60870_QUALITY_GOOD);
        CS101_ASDU_addInformationObject(cmd, sc);
        InformationObject_destroy(sc);
        CS104_Connection_sendASDU(conn, cmd);
        CS101_ASDU_destroy(cmd);

        struct sCP56Time2a testTimestamp;
        CP56Time2a_createFromMsTimestamp(&testTimestamp, Hal_getTimeInMs());
        CS104_Connection_sendTestCommandWithTimestamp(conn, 1, 0x4938, &testTimestamp);
    }

    for (int i = 0; i < 20; i++) {
        Thread_sleep(1000);
    }

    CS104_Connection_close(conn);
    CS104_Connection_destroy(conn);

    return 0;
}
