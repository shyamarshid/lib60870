# IEC 62351-5 A-Profile PICS

This document captures the current implementation coverage for the IEC 62351-5 A-profile features provided by `lib60870-C`.

## Station association and keys
- Station Association IDs (AIM/AIS) are configurable through the `AProfile_setAssociationIds` API and are carried in every secure data PDU.
- Distinct inbound/outbound 256-bit session keys are maintained; callers can inject externally derived keys via `AProfile_setSessionKeys`.
- AEAD (AES-256-GCM) can be selected at runtime through `AProfile_setDpaAlgorithm`; the default remains HMAC-SHA-256 to preserve backward compatibility.

## Session key rotation
- Rekey requests are triggered when any of the configured caps are hit: DSQ wrap margin (`CONFIG_CS104_APROFILE_DSQ_REKEY_MARGIN`), maximum session age (`CONFIG_CS104_APROFILE_MAX_SESSION_AGE_MS`), or maximum transmitted messages (`CONFIG_CS104_APROFILE_MAX_MESSAGES_PER_SESSION`).

## Data protection algorithms
- Supported: HMAC-SHA-256 (truncated to 16 bytes), AES-256-GCM with 16-byte authentication tag.
- Conditional: SHA3-256 and BLAKE2s-256 are selectable when the underlying mbedtls build exposes the respective digests (`MBEDTLS_MD_SHA3_256` / `MBEDTLS_MD_BLAKE2S_256`).

## Secure data fields and associated data
- Secure PDUs encode DSQ, AIM, AIS, and ASDU length ahead of the ciphertext/plaintext payload. These header bytes are always included as AEAD associated data or HMAC input.

## Identity and RBAC inputs
- The A-profile APIs expose AIM/AIS and key injection hooks; enabling security now requires the embedding application to assert successful certificate validation and role availability when calling `CS104_Connection_setSecurityConfig`, otherwise secure wrapping remains disabled.

## Security telemetry (IEC 62351-14)
- Telemetry counters track accepted secure frames, MAC/AEAD validation failures, replay rejections, and control frames exposed to the application. See `AProfile_getTelemetry` and `AProfile_clearTelemetry`.

## Configuration defaults
- A-profile code is behind `CONFIG_CS104_APROFILE`. Default DPA algorithm: HMAC-SHA-256. Session key limits follow the existing build-time configuration knobs documented in `aprofile_context.c`.

## Gap analysis vs IEC 62351-5 application-layer security

### Station Association and key hierarchy
- Session keys are generated locally in `AProfile_create` without any Station Association exchange, X.509 validation, or HKDF/ECDH-derived update keys; enabling protection still depends on the caller to inject keys or request local generation before traffic flows.【F:lib60870-C/src/iec60870/security/62351-5/aprofile_context.c†L199-L236】
- There is no support for Authentication/Encryption Update Keys, AES-256 key wrap, curve negotiation, or association identifiers within Additional Data beyond the bare AIM/AIS fields in secure PDUs.【F:lib60870-C/src/iec60870/security/62351-5/aprofile_context.c†L332-L345】
- Implementation guidance: add Station Association PDUs, mutual certificate verification, and ECDH+HKDF derivation of update keys; wrap per-direction session keys with AES-256-KW using the Encryption Update Key and authenticate the key-change messages with the Authentication Update Key before calling `AProfile_setSessionKeys`.

### Session Key Change procedure
- Rekey requests are detected (`AProfile_requiresRekey`) and block outgoing protection, but no Session Key Change control messages or timers exist to perform the rotation; the library simply refuses to wrap ASDUs once limits are hit.【F:lib60870-C/src/iec60870/security/62351-5/aprofile_context.c†L493-L555】
- Implementation guidance: implement the IEC 62351-5 Session Key Change state machines so the controlling station can push new wrapped keys and the controlled side can authenticate and install them, resetting DSQ to 1 on success.

### Identity, trust, and RBAC
- Certificate validation, trust-anchor handling, and role-based access control must still be performed by the embedding application, but enabling security now requires the caller to signal successful certificate checks and available roles before payloads will be wrapped.【F:IEC62351-5-PICS.md†L20-L22】【F:lib60870-C/src/iec60870/cs104/cs104_connection.c†L1227-L1260】
- Implementation guidance: wire the security configuration into the A-profile context, verify peer/device certificates before association, and gate inbound operations on roles per IEC 62351-8 (e.g., deny unauthorised commands and raise security events).

### Security telemetry and event reporting
- Telemetry counters are local to the context and are not exposed over 104 or mapped to IEC 62351-14 events; only simple accept/reject counters exist.【F:lib60870-C/src/iec60870/security/62351-5/aprofile_context.c†L447-L463】
- Implementation guidance: add the mandatory counter set defined in IEC 62351-14, persist them per association, and define an ASDU or information object mapping to export counters/events as required by the 104 profile.

### Data protection algorithm coverage
- The implementation supports HMAC-SHA-256 with optional SHA3-256/BLAKE2s-256 and AES-256-GCM, but lacks the explicit DPA code negotiation, minimum tag length enforcement for serial profiles, and AEAD-associated-data construction that includes the full Association ID per the standard’s tables.【F:lib60870-C/src/iec60870/security/62351-5/aprofile_context.c†L142-L205】【F:lib60870-C/src/iec60870/security/62351-5/aprofile_context.c†L332-L351】
- Implementation guidance: surface DPA code negotiation during Station Association, validate that the selected algorithm matches the transport (e.g., 16-byte tag for 104/TCP), and ensure AEAD uses AIM||AIS as Additional Data and DSQ-derived nonces exactly per Annex B.

### Integration with the 104 state machine
- Secure wrapping is enabled only after STARTDT and when session keys are present, but the library does not mandate running the association/key-change handshake before allowing plaintext ASDUs or enforcing rekey deadlines; STARTDT simply resets DSQ counters.【F:lib60870-C/src/iec60870/security/62351-5/aprofile_context.c†L512-L556】【F:lib60870-C/src/iec60870/cs104/cs104_connection.c†L777-L781】
- Implementation guidance: insert the Station Association and Session Key Change procedures after STARTDT before application traffic flows, and drop/alarms on plaintext ASDUs when the A-profile is required.
