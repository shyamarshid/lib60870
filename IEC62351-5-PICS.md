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
- The A-profile APIs expose AIM/AIS and key injection hooks; certificate validation, trust anchors, and RBAC enforcement remain the responsibility of the embedding application (not implemented in this library revision).

## Security telemetry (IEC 62351-14)
- Telemetry counters track accepted secure frames, MAC/AEAD validation failures, replay rejections, and control frames exposed to the application. See `AProfile_getTelemetry` and `AProfile_clearTelemetry`.

## Configuration defaults
- A-profile code is behind `CONFIG_CS104_APROFILE`. Default DPA algorithm: HMAC-SHA-256. Session key limits follow the existing build-time configuration knobs documented in `aprofile_context.c`.
