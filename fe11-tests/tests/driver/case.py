# SPDX-License-Identifier: Apache-2.0
"""Execute one frozen public API case and independently observe its native calls."""
from pathlib import Path
import argparse
import json
import os
import re
import secrets
import shlex
import shutil
from process import execute, frames, erase
from run import digest, environment, save, read_records, verify_worker, trace_matches
from dependencies import verify as verify_dependencies
from owned_storage import OwnedTokens, identity as storage_identity

HERE = Path(__file__).resolve().parent
DIGEST_FUNCTIONS = ("C_DigestInit", "C_Digest", "C_DigestUpdate", "C_DigestFinal", "C_DigestKey")
VERIFICATION_FUNCTIONS = ("C_VerifyInit", "C_Verify", "C_VerifyUpdate", "C_VerifyFinal", "C_VerifyRecoverInit", "C_VerifyRecover")
MAC_FUNCTIONS = ("C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal") + VERIFICATION_FUNCTIONS
CIPHER_FUNCTIONS = tuple("C_" + direction + suffix for direction in ("Encrypt", "Decrypt")
                         for suffix in ("Init", "", "Update", "Final"))
CANCEL_DIGEST_FUNCTIONS = DIGEST_FUNCTIONS + ("C_SessionCancel", "C_CloseSession", "C_Login", "C_Logout")
TRANSITION_DIGEST_FUNCTIONS = CANCEL_DIGEST_FUNCTIONS + ("C_GetOperationState",)
AUTHENTICATION_FUNCTIONS = CANCEL_DIGEST_FUNCTIONS + ("C_LoginUser",)
MESSAGE_FUNCTIONS = tuple(name for direction in ("Encrypt", "Decrypt", "Sign", "Verify")
                          for name in ("C_Message" + direction + "Init", "C_" + direction + "Message",
                                       "C_" + direction + "MessageBegin", "C_" + direction + "MessageNext",
                                       "C_Message" + direction + "Final"))
TICKET_FAMILY_FUNCTIONS = tuple(dict.fromkeys(DIGEST_FUNCTIONS + CIPHER_FUNCTIONS + MAC_FUNCTIONS + MESSAGE_FUNCTIONS))



def run_case(args):
    """Retain evidence while removing only storage created by this invocation."""
    owners, result = [], None
    try:
        result = _run_case(args, owners)
        return result
    finally:
        # execute() returns only after reaping the worker/debugger process group.
        # No subsequent native call is permitted after storage cleanup begins.
        for owner in owners:
            try:
                outcome = owner.cleanup()
            except Exception:
                # An unknown path must remain untouched, including its receipts.
                if storage_identity(owner.parent) == owner.parent_identity:
                    save(owner.parent / 'token-cleanup.json', {'status': 'FAILED'})
                    if result is not None:
                        result.update(status='INCOMPLETE', attribution='UNKNOWN',
                                      failure_category='OwnedStorageCleanup')
                        # Keep the earlier native result as evidence. The later
                        # supervisor failure is a separate record and nonzero exit.
                        save(owner.parent / 'cleanup-failure.json', result)
                raise ValueError('owned token cleanup failed') from None
            save(owner.parent / 'token-cleanup.json', outcome)


def _run_case(args, owners):
    if os.name != "posix" or "microsoft" in os.uname().release.lower():
        raise ValueError("use the selected Linux execution host")
    root = args.root.resolve()
    if args.root.is_symlink() or any(char in str(root) for char in "\r\n#="):
        raise ValueError("invalid isolated job path")
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    if digest(args.manifest) != args.manifest_sha256 or digest(args.gate) != args.gate_sha256:
        raise ValueError("case manifest or recipe gate identity mismatch")
    cases = json.loads(args.manifest.read_text())
    selected = [row for row in cases if row["id"] == args.case]
    if len(selected) != 1:
        raise ValueError("case must be uniquely specified")
    case = selected[0]
    vector = (args.manifest.parent / case["file"]).resolve(strict=True)
    if not vector.is_relative_to(args.manifest.parent.resolve()) or digest(vector) != case["sha256"]:
        raise ValueError("vector path or identity mismatch")
    recipe = json.loads(args.recipe.read_text())
    recipe_sha = digest(args.recipe)
    gate = json.loads(args.gate.read_text())
    module = Path(recipe["module"]).resolve(strict=True)
    if (gate.get("status") != "RECIPE_READY" or gate.get("module_sha256") != recipe["sha256"]
            or gate.get("recipe_sha256") != recipe_sha or gate.get("backend") != args.backend):
        raise ValueError("recipe prerequisites not established for this module/backend")
    if digest(module) != recipe["sha256"] or digest(args.worker) != args.worker_sha256:
        raise ValueError("worker or module identity mismatch")
    for value in (args.source_sha256, args.worker_sha256, recipe["sha256"]):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid provenance digest")
    mode = case.get("worker_mode", "digest-vector")
    if mode not in ("generated-aes", "digest-vector", "digest-stream", "ecdsa-encoding", "ecdsa-vector", "rsa-vector", "dsa-vector", "oaep-vector", "oaep-encrypt", "key-wrap-vector", "key-wrap-controlled", "ticket-family", "mac-vector", "mac-equivalence", "digest-cancel", "cipher-vector", "digest-transition", "authentication-admission", "pin-admission", "rsa-domain", "rsa-known", "generation-vector", "ticket-identity", "pqc-vector", "authentication-state", "pqc-random", "classical-sign", "dsa-import-identity", "dh-import-identity", "dh-public-import", "gcm-vector", "gcm-parameters", "edwards-vector", "edwards-negative", "ecdh-vector", "encrypt-data-vector", "search-transition", "search-population", "context-login", "context-wrong-pin", "context-local-guards", "context-missing-login", "context-pss-login", "random-contract", "object-contract", "interface-contract", "initialization-contract", "session-contract", "pin-contract", "legacy-contract", "token-label-contract", "discovery-contract", "cipher-transition", "digest-capacity", "cipher-batch-transition", "digest-refused", "gcm-transition", "kem-vector", "mac-transition", "kem-import", "import-encoding", "ticket-boundary", "absent-mechanism", "rsa-transition", "aead-preinit", "pqc-transition", "single-signature-transition", "gcm-withholding", "edwards-transition", "ecdsa-transition", "rsa-usage", "rsa-changed-signature", "rsa-negative", "generation-transition", "direct-generation", "ticket-state-guard", "object-transition", "public-guard", "generation-negative", "cipher-usage", "des-parity", "ticket-owner-identity", "record-parser", "classical-sign-denied", "classical-verify-denied", "trusted-wrap-session", "trusted-wrap-advanced", "kem-wrong-key", "signature-extension-stream-route", "signature-extension-single-route", "extension-cipher", "extension-gcm", "extension-oaep", "extension-oaep-null", "extension-signature", "extension-generation", "extension-pair", "extension-objects", "digest-ticket-cipher", "input-guard", "direct-material", "admission-scope", "module-lifecycle", "module-controls", "active-pair", "shared-module", "verification-guards", "unsupported-lifecycle", "symmetric-guards", "dual-cbc", "single-part-guard-0", "single-part-guard-1", "single-part-guard-2", "single-part-guard-3", "single-part-guard-4", "single-part-guard-5", "dh-vector", "pqc-import-guard", "batch-state", "attribute-guard", "typed-selection", "module-accessor", "advanced-setting", "admission-family", "authenticated-transport-guard", "oaep-reference-guard", "oaep-destination-guard", "foreign-info", "digest-live-alias", "retained-digest", "module-boundary", "derive-usage-negative", "derive-template-negative", "foreign-session", "retained-cipher", "retained-signature", "oaep-encrypt-denied", "oaep-decrypt-denied", "dh-usage-denied", "dh-template-denied", "ecdh-usage-denied", "ecdh-template-denied", "recovery-record", "ecdh-invalid", "builder-observation", "digest-family-view", "gcm-usage", "classical-changed", "concatenation-negative", "concatenation-values", "transport-negative", "aes-entry-guard", "binary-generation", "foreign-callback", "rsa-unwrap-negative", "extension-rsa-aes-session", "extension-rsa-aes-advanced", "signing-guards", "pqc-verification-guards", "rsa-wrap-negative", "rsa-aes-private-unwrap", "rsa-aes-private-wrap", "gcm-result-metadata", "hkdf-hash-widths", "session-abi-widths", "attribute-value-partitions", "attribute-mixed-values", "attribute-creation-change", "optional-rsa-crt-import", "absent-object-attributes", "aes-transport-class", "signature-result-metadata", "foreign-event-guard", "session-conversion", "builder-choices", "borrowed-client", "runtime-successor", "cross-runtime-guard", "engine-choices", "builder-runtime-choices", "pqc-signing-guard", "aead-input-guards", "digest-key-identity", "mechanism-request-guard", "agreement-input-guards", "drain-ticket-identity", "token-drain-session", "foreign-slot-guard", "kem-lifecycle"):
        raise ValueError("unexpected worker mode")
    observed_functions = (("C_Login", "C_GenerateRandom", "C_SeedRandom", "C_Logout", "C_CloseSession") if mode == "random-contract" else ("C_Login", "C_SignInit", "C_SignUpdate", "C_SignFinal", "C_VerifyInit", "C_VerifyUpdate", "C_VerifyFinal", "C_GetOperationState", "C_SessionCancel", "C_CloseSession", "C_Logout") if mode in ("mac-transition", "rsa-transition") else ("C_Login", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_GetOperationState", "C_SessionCancel", "C_CloseSession", "C_Logout") if mode == "digest-capacity" else ("C_Login", "C_EncryptInit", "C_EncryptUpdate", "C_EncryptFinal", "C_DecryptInit", "C_DecryptUpdate", "C_DecryptFinal", "C_GetOperationState", "C_SessionCancel", "C_CloseSession", "C_Logout") if mode in ("cipher-transition", "gcm-transition") else ("C_Login", "C_SignInit", "C_Sign", "C_GetSessionInfo", "C_CreateObject", "C_DestroyObject", "C_Logout", "C_CloseSession") if mode in ("context-login", "context-wrong-pin", "context-local-guards", "context-missing-login", "context-pss-login") else ("C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_Logout", "C_CloseSession") if mode in ("search-transition", "search-population") else ("C_DeriveKey", "C_GetAttributeValue", "C_DestroyObject") if mode in ("ecdh-vector", "encrypt-data-vector") else ("C_OpenSession", "C_CloseSession", "C_GetSessionInfo", "C_Login", "C_LoginUser", "C_Logout", "C_CreateObject", "C_DestroyObject", "C_InitPIN", "C_SetPIN") if mode == "authentication-state" else MAC_FUNCTIONS if mode in ("pqc-vector", "pqc-random", "classical-sign", "dsa-import-identity", "edwards-vector") else ("C_GenerateKey", "C_GenerateKeyPair", "C_GetAttributeValue", "C_DestroyObject") if mode == "generation-vector" else MAC_FUNCTIONS + CIPHER_FUNCTIONS if mode == "rsa-known" else ("C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal", "C_EncryptInit", "C_Encrypt") if mode == "rsa-domain" else
                          ("C_WrapKey", "C_UnwrapKey") if mode in ("key-wrap-vector", "key-wrap-controlled") else
                          TICKET_FAMILY_FUNCTIONS + ("C_Login", "C_Logout", "C_GetOperationState", "C_SessionCancel") if mode == "ticket-identity" else
                          TICKET_FAMILY_FUNCTIONS if mode == "ticket-family" else
                          ("C_Login", "C_Logout", "C_InitPIN", "C_SetPIN", "C_CloseSession") if mode == "pin-admission" else
                          AUTHENTICATION_FUNCTIONS if mode == "authentication-admission" else
                          VERIFICATION_FUNCTIONS if mode in ("ecdsa-encoding", "ecdsa-vector", "rsa-vector", "dsa-vector") else
                          TRANSITION_DIGEST_FUNCTIONS if mode == "digest-transition" else
                          CIPHER_FUNCTIONS if mode in ("cipher-vector", "oaep-vector", "oaep-encrypt", "gcm-vector") else
                          CANCEL_DIGEST_FUNCTIONS if mode == "digest-cancel" else
                          MAC_FUNCTIONS if mode == "mac-vector" else DIGEST_FUNCTIONS)
    if mode == "hkdf-hash-widths":
        observed_functions = ("C_DeriveKey",)
    if mode == "session-abi-widths":
        observed_functions = ("C_CreateObject", "C_GetSessionValidationFlags", "C_EncryptInit", "C_DecryptInit", "C_DestroyObject")
    if mode in ("attribute-value-partitions", "attribute-mixed-values", "absent-object-attributes"):
        observed_functions = ("C_GetAttributeValue",)
    if mode == "optional-rsa-crt-import":
        observed_functions = ("C_CreateObject", "C_SignInit", "C_Sign")
    if mode == "attribute-creation-change":
        observed_functions = ("C_CreateObject",)
    if mode == "aes-transport-class":
        observed_functions = ("C_WrapKey", "C_UnwrapKey", "C_SignInit", "C_Sign")
    if mode == "gcm-result-metadata":
        observed_functions = ("C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt")
    if mode == "signature-result-metadata":
        observed_functions = ("C_SignInit", "C_Sign")
    if mode in ("dh-import-identity", "dh-public-import"):
        observed_functions = ("C_CreateObject", "C_GetAttributeValue", "C_DeriveKey", "C_DestroyObject", "C_CloseSession")
    if mode == "dsa-import-identity":
        observed_functions = ("C_CreateObject", "C_GetAttributeValue", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_DestroyObject", "C_CloseSession")
    if mode == "pqc-vector" and "pqc_value_export" in case:
        observed_functions = ("C_CreateObject", "C_GetAttributeValue", "C_DestroyObject")
    if mode == "generation-vector" and "generated_lifetime" in case:
        observed_functions = ("C_OpenSession", "C_CloseSession", "C_GenerateKey", "C_GenerateKeyPair",
            "C_GetAttributeValue", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_DestroyObject")
    if mode == "generation-vector" and "disabled_usage" in case:
        observed_functions += ("C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify",
                               "C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt")
    if mode == "generation-vector" and "disabled_usage" in case and case["disabled_usage"] in ("WRAP", "UNWRAP", "DERIVE"):
        observed_functions += ("C_CreateObject", "C_WrapKey", "C_UnwrapKey", "C_DeriveKey")
    if mode == "generation-vector" and "secret_witness" in case:
        observed_functions = ("C_GenerateKey", "C_GetAttributeValue", "C_DestroyObject",
            "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify",
            "C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt")
    if mode == "generation-vector" and "domain_witness" in case:
        observed_functions = observed_functions + ("C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_DeriveKey")
    if mode == "generation-vector" and "rsa_witness_bits" in case:
        observed_functions = observed_functions + ("C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify")
    if mode == "generation-vector" and "pqc_witness" in case:
        observed_functions = observed_functions + ("C_OpenSession", "C_Login", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_Logout", "C_CloseSession", "C_Finalize")
    if mode == "legacy-contract":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_GetFunctionStatus", "C_CancelFunction", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_CloseSession", "C_Finalize")
    if mode == "cipher-vector" and ("counter_boundary" in case or "block_boundary" in case):
        observed_functions = CIPHER_FUNCTIONS + ("C_Login", "C_CreateObject", "C_DestroyObject", "C_CloseSession")
    if mode == "token-label-contract":
        observed_functions = ("C_Initialize", "C_InitToken", "C_OpenSession", "C_Login", "C_Logout", "C_CreateObject", "C_GetAttributeValue", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_CloseSession", "C_Finalize")
    if mode == "pin-contract":
        observed_functions = ("C_InitToken", "C_OpenSession", "C_Login", "C_Logout", "C_InitPIN", "C_SetPIN", "C_CloseSession", "C_Finalize")
    if mode == "session-contract":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_GetSessionInfo", "C_Login", "C_Logout", "C_CloseSession", "C_CloseAllSessions", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_Finalize")
    if mode == "initialization-contract":
        observed_functions = ("C_Initialize", "C_Finalize", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal")
    if mode == "discovery-contract":
        observed_functions = ("C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList", "C_GetMechanismInfo", "C_WaitForSlotEvent", "C_Finalize")
    if mode == "discovery-contract" and "identifier_widths" in case:
        # Mechanism enumeration uses one or two calls depending on actual slot
        # membership. The worker checks its returned set or exact native refusal.
        observed_functions = ("C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismInfo", "C_Finalize")
    if mode == "key-wrap-vector" and "unwrap_attributes" in case:
        observed_functions = ("C_UnwrapKey", "C_GetAttributeValue")
    if mode in ("trusted-wrap-session", "trusted-wrap-advanced"):
        observed_functions = ("C_Login", "C_CreateObject", "C_WrapKey", "C_SetAttributeValue", "C_GetAttributeValue", "C_DestroyObject", "C_Logout", "C_CloseSession")
    if mode == "kem-wrong-key":
        observed_functions = ("C_CreateObject", "C_EncapsulateKey", "C_DecapsulateKey", "C_DestroyObject", "C_CloseSession")
    if mode == "interface-contract":
        observed_functions = ("C_GetInterfaceList", "C_GetInterface", "C_GetFunctionList", "C_Initialize", "C_Finalize")
    if mode in ("pqc-transition", "single-signature-transition", "gcm-withholding", "edwards-transition", "ecdsa-transition"):
        observed_functions = ("C_Login", "C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal", "C_VerifyInit", "C_Verify", "C_VerifyUpdate", "C_VerifyFinal", "C_GetOperationState", "C_SessionCancel", "C_CloseSession", "C_Logout")
    if mode in ("module-lifecycle", "module-controls", "shared-module", "builder-runtime-choices"):
        observed_functions = ("C_Initialize", "C_OpenSession", "C_GetSessionInfo", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_CloseSession", "C_Finalize")
    if mode == "builder-runtime-choices" and "imported_private_protection" in case:
        observed_functions += ("C_CreateObject", "C_DestroyObject", "C_GetAttributeValue")
    if mode == "builder-runtime-choices" and "absent_agreement_selector" in case:
        observed_functions += ("C_CreateObject", "C_DestroyObject", "C_DeriveKey", "C_WrapKey")
    if mode == "builder-runtime-choices" and "gost_destination_class" in case:
        observed_functions += ("C_CreateObject", "C_DestroyObject", "C_FindObjectsInit",
                               "C_FindObjects", "C_FindObjectsFinal", "C_DeriveKey")
    if mode == "builder-runtime-choices" and "absent_legacy_key_selector" in case:
        observed_functions += ("C_CreateObject", "C_DestroyObject", "C_EncryptInit", "C_Encrypt",
                               "C_SignInit", "C_Sign", "C_WrapKey")
    if mode == "builder-runtime-choices" and "absent_rsa_selector" in case:
        observed_functions += ("C_CreateObject", "C_DestroyObject", "C_EncryptInit", "C_Encrypt",
                               "C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal")
    if mode == "builder-runtime-choices" and "absent_cipher_selector" in case:
        observed_functions += ("C_CreateObject", "C_DestroyObject", "C_EncryptInit", "C_Encrypt", "C_EncryptUpdate", "C_EncryptFinal")
    if mode == "builder-runtime-choices" and "absent_hash_selector" in case:
        observed_functions += ("C_CreateObject", "C_DestroyObject", "C_Digest", "C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal")
    if mode == "builder-runtime-choices" and "protocol_absence" in case:
        observed_functions = observed_functions + ("C_CreateObject", "C_DeriveKey", "C_DestroyObject")
        if case["protocol_absence"] in ("tls-finished", "tls12-finished"):
            observed_functions += ("C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal")
        if case["protocol_absence"] in ("kip-mac-sign", "kip-mac-verify", "kip-wrap", "kip-unwrap"):
            observed_functions += ("C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_WrapKey", "C_UnwrapKey")
    if mode == "builder-runtime-choices" and "output_credit" in case:
        observed_functions = observed_functions + ("C_GenerateRandom",)
        if case["output_credit"] == "capture-release":
            observed_functions += ("C_GetOperationState",)
    if mode == "builder-runtime-choices" and "owner_progress" in case:
        observed_functions += ("C_SessionCancel", "C_CancelFunction")
    if mode == "builder-runtime-choices" and "reference_credit" in case:
        observed_functions = observed_functions + ("C_CreateObject", "C_FindObjectsInit",
            "C_FindObjects", "C_FindObjectsFinal", "C_GetAttributeValue", "C_DestroyObject")
    if mode == "builder-runtime-choices" and "public_point_form" in case:
        # Attribute contents are asserted by the worker; trace the exact native
        # creation, lookup, verification and destruction lifecycle independently.
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CreateObject",
            "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal",
            "C_VerifyInit", "C_Verify", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "builder-runtime-choices" and "notification_owner" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_DigestInit",
            "C_DigestUpdate", "C_DigestFinal", "C_CloseSession", "C_Finalize")
    if mode == "unsupported-lifecycle":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_SignRecoverInit", "C_SignRecover", "C_DestroyObject", "C_CloseSession", "C_Finalize")
        if "message_initialization" in case:
            observed_functions = MESSAGE_FUNCTIONS + VERIFICATION_FUNCTIONS + ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_VerifySignatureInit", "C_VerifySignature", "C_VerifySignatureUpdate", "C_VerifySignatureFinal", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode in ("single-part-guard-0", "single-part-guard-1", "single-part-guard-2", "single-part-guard-3", "single-part-guard-4", "single-part-guard-5"):
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_DestroyObject", "C_CloseSession", "C_Finalize", "C_VerifySignatureInit", "C_VerifySignature", "C_VerifySignatureUpdate", "C_VerifySignatureFinal")
    if mode == "attribute-guard":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_GetAttributeValue", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode in ("digest-live-alias", "retained-digest"):
        observed_functions = ("C_OpenSession", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_CloseSession")
    if mode in ("derive-usage-negative", "derive-template-negative", "dh-usage-denied", "dh-template-denied", "ecdh-usage-denied", "ecdh-template-denied"):
        observed_functions = ("C_CreateObject", "C_DeriveKey", "C_DestroyObject", "C_CloseSession")
    if mode == "builder-choices":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_DigestInit", "C_Digest", "C_CloseSession", "C_Finalize")
    if mode == "builder-observation":
        observed_functions = ('C_Initialize', 'C_Finalize', 'C_InitToken', 'C_InitPIN', 'C_SetPIN', 'C_OpenSession', 'C_CloseSession', 'C_CloseAllSessions', 'C_GetSessionInfo', 'C_GetOperationState', 'C_SetOperationState', 'C_Login', 'C_Logout', 'C_CreateObject', 'C_CopyObject', 'C_DestroyObject', 'C_GetObjectSize', 'C_GetAttributeValue', 'C_SetAttributeValue', 'C_FindObjectsInit', 'C_FindObjects', 'C_FindObjectsFinal', 'C_EncryptInit', 'C_Encrypt', 'C_EncryptUpdate', 'C_EncryptFinal', 'C_DecryptInit', 'C_Decrypt', 'C_DecryptUpdate', 'C_DecryptFinal', 'C_DigestInit', 'C_Digest', 'C_DigestUpdate', 'C_DigestKey', 'C_DigestFinal', 'C_SignInit', 'C_Sign', 'C_SignUpdate', 'C_SignFinal', 'C_SignRecoverInit', 'C_SignRecover', 'C_VerifyInit', 'C_Verify', 'C_VerifyUpdate', 'C_VerifyFinal', 'C_VerifyRecoverInit', 'C_VerifyRecover', 'C_DigestEncryptUpdate', 'C_DecryptDigestUpdate', 'C_SignEncryptUpdate', 'C_DecryptVerifyUpdate', 'C_GenerateKey', 'C_GenerateKeyPair', 'C_WrapKey', 'C_UnwrapKey', 'C_DeriveKey', 'C_SeedRandom', 'C_GenerateRandom', 'C_GetFunctionStatus', 'C_CancelFunction', 'C_WaitForSlotEvent', 'C_LoginUser', 'C_SessionCancel', 'C_MessageEncryptInit', 'C_EncryptMessage', 'C_EncryptMessageBegin', 'C_EncryptMessageNext', 'C_MessageEncryptFinal', 'C_MessageDecryptInit', 'C_DecryptMessage', 'C_DecryptMessageBegin', 'C_DecryptMessageNext', 'C_MessageDecryptFinal', 'C_MessageSignInit', 'C_SignMessage', 'C_SignMessageBegin', 'C_SignMessageNext', 'C_MessageSignFinal', 'C_MessageVerifyInit', 'C_VerifyMessage', 'C_VerifyMessageBegin', 'C_VerifyMessageNext', 'C_MessageVerifyFinal', 'C_EncapsulateKey', 'C_DecapsulateKey', 'C_VerifySignatureInit', 'C_VerifySignature', 'C_VerifySignatureUpdate', 'C_VerifySignatureFinal', 'C_GetSessionValidationFlags', 'C_AsyncComplete', 'C_AsyncGetID', 'C_AsyncJoin', 'C_WrapKeyAuthenticated', 'C_UnwrapKeyAuthenticated')
    if mode == "module-boundary":
        observed_functions = ("C_Initialize", "C_Finalize")
    if mode in ("retained-cipher", "retained-signature"):
        observed_functions = ("C_CreateObject", "C_EncryptInit", "C_Encrypt", "C_SignInit", "C_Sign", "C_Login", "C_Logout", "C_DestroyObject", "C_CloseSession")
    if mode in ("oaep-encrypt-denied", "oaep-decrypt-denied"):
        observed_functions = ("C_CreateObject", "C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt", "C_DestroyObject")
    if mode == "active-pair":
        observed_functions = ("C_OpenSession", "C_CreateObject", "C_DigestInit", "C_EncryptInit",
                              "C_SignInit", "C_VerifyInit", "C_FindObjectsInit", "C_FindObjectsFinal",
                              "C_Encrypt", "C_DigestFinal", "C_Sign", "C_Verify",
                              "C_CloseSession", "C_Finalize")
    if mode == "kem-lifecycle":
        observed_functions = ("C_OpenSession", "C_Login", "C_GenerateKeyPair", "C_EncapsulateKey", "C_DecapsulateKey", "C_CopyObject", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize")
    if mode == "ecdsa-vector" and "wrong_curve" in case and case["wrong_curve"] is True:
        observed_functions = ("C_CreateObject", "C_VerifyInit", "C_Verify", "C_DestroyObject", "C_CloseSession")
    if mode == "kem-lifecycle" and "parameter_identity" in case:
        observed_functions = observed_functions + ("C_GetAttributeValue",)
    if mode == "kem-lifecycle" and "public_import" in case and case["public_import"] is True:
        observed_functions = observed_functions + ("C_CreateObject",)
    if mode == "foreign-slot-guard":
        observed_functions = ('C_Initialize', 'C_GetInfo', 'C_InitToken', 'C_OpenSession', 'C_CloseSession', 'C_Finalize')
    if mode == "foreign-session":
        observed_functions = ("C_Initialize", "C_GetInfo", "C_OpenSession", "C_CloseSession", "C_Finalize")
    if mode == "foreign-session" and "foreign_object" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_CreateObject",
            "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetAttributeValue",
            "C_DestroyObject", "C_CloseSession", "C_Logout", "C_Finalize")
    if mode == "foreign-session" and "foreign_authentication" in case:
        observed_functions = observed_functions + ("C_Login", "C_Logout", "C_GetSessionInfo", "C_CreateObject", "C_GetAttributeValue", "C_DestroyObject", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal")
    if mode == "foreign-event-guard":
        observed_functions = ("C_Initialize", "C_GetInfo", "C_WaitForSlotEvent", "C_Finalize")
    if mode == "foreign-callback":
        observed_functions = ("C_Initialize", "C_GetInfo", "C_Finalize")
    if mode == "cross-runtime-guard":
        observed_functions = ("C_Initialize", "C_GetInfo", "C_OpenSession", "C_GetSessionInfo", "C_CreateObject", "C_GetAttributeValue", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "borrowed-client":
        observed_functions = ("C_Initialize", "C_GetInfo", "C_Finalize")
    if mode == "engine-choices":
        observed_functions = ("C_Initialize", "C_GetInfo", "C_OpenSession", "C_GetSessionInfo", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_CloseSession", "C_Finalize")
    if mode == "foreign-info":
        observed_functions = ("C_Initialize", "C_GetInfo", "C_Finalize")
    if mode in ("admission-family", "authenticated-transport-guard"):
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "authenticated-transport-guard" and "native_function" in case:
        observed_functions = observed_functions + ("C_WrapKeyAuthenticated", "C_UnwrapKeyAuthenticated")
    if mode == "authenticated-transport-guard" and ("standard_wrap" in case or "layout_identity" in case):
        observed_functions = observed_functions + ("C_WrapKey",)
    if mode == "mac-equivalence":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal", "C_VerifyInit", "C_Verify", "C_VerifyUpdate", "C_VerifyFinal", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "edwards-negative":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_GenerateKeyPair", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_CopyObject", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize")
    if mode == "edwards-negative" and "multipart_edwards" in case:
        observed_functions = observed_functions + ("C_SignUpdate", "C_SignFinal", "C_VerifyUpdate", "C_VerifyFinal")
    if mode == "edwards-negative" and "generated_edwards_identity" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_GenerateKeyPair", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_GetAttributeValue", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize")
    if mode == "oaep-destination-guard":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_GenerateKeyPair", "C_UnwrapKey", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize")
    if mode == "oaep-reference-guard":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_GenerateKeyPair", "C_EncryptInit", "C_Encrypt", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize")
    if mode == "advanced-setting":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_GetSessionValidationFlags", "C_CloseSession", "C_Finalize")
    if mode == "module-accessor":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CloseSession", "C_Finalize")
    if mode == "typed-selection":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_CreateObject", "C_GenerateKey", "C_GenerateKeyPair", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_DestroyObject", "C_CloseSession", "C_Logout", "C_Finalize")
    if mode == "batch-state":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_DestroyObject", "C_GetOperationState", "C_SessionCancel", "C_CloseSession", "C_Finalize")
    if mode == "pqc-import-guard":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "pqc-import-guard" and "pqc_private_form" in case:
        observed_functions = observed_functions + ("C_EncapsulateKey", "C_DecapsulateKey")
    if mode == "dh-vector":
        observed_functions = ("C_DeriveKey", "C_GetAttributeValue", "C_DestroyObject")
    if mode == "symmetric-guards":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Initialize", "C_OpenSession", "C_GenerateKey", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "pqc-signing-guard":
        observed_functions = ('C_Login', 'C_GenerateKeyPair', 'C_SignInit', 'C_Sign', 'C_SignUpdate', 'C_SignFinal', 'C_DigestInit', 'C_Digest', 'C_DestroyObject', 'C_CloseSession')
    if mode == "aead-input-guards":
        observed_functions = ('C_GenerateKey', 'C_EncryptInit', 'C_EncryptUpdate', 'C_EncryptFinal', 'C_MessageEncryptInit', 'C_EncryptMessage', 'C_EncryptMessageBegin', 'C_EncryptMessageNext', 'C_MessageEncryptFinal', 'C_DigestInit', 'C_Digest', 'C_DigestUpdate', 'C_DigestFinal', 'C_DestroyObject', 'C_CloseSession')
    if mode == "digest-key-identity":
        observed_functions = ('C_CreateObject', 'C_DigestInit', 'C_DigestKey', 'C_DigestUpdate', 'C_DigestFinal', 'C_DestroyObject', 'C_CloseSession')
    if mode == "object-contract":
        observed_functions = ("C_Login", "C_CreateObject", "C_CopyObject", "C_GetAttributeValue", "C_SetAttributeValue", "C_GetObjectSize", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_SignInit", "C_Sign", "C_DestroyObject", "C_Logout", "C_CloseSession")
    if mode == "object-contract" and "configuration_variant" in case and case["configuration_variant"] == "log-secret-sentinel":
        observed_functions = observed_functions + ("C_VerifyInit", "C_Verify")
    if mode == "object-contract" and "data_lifetime" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_CreateObject", "C_GetAttributeValue", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize")
    if mode == "object-contract" and "store_visibility" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_CreateObject", "C_GetAttributeValue", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_DestroyObject", "C_Logout", "C_CloseSession", "C_Finalize")
    if mode == "unsupported-lifecycle" and "recover_initialization" in case:
        observed_functions = ("C_CreateObject", "C_SignRecoverInit", "C_SignRecover", "C_VerifyRecoverInit", "C_VerifyRecover", "C_DestroyObject")
    if mode == "unsupported-lifecycle" and "cms_initialization" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_SignRecoverInit", "C_SignRecover", "C_VerifyRecoverInit", "C_VerifyRecover", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "unsupported-lifecycle" and "ccm_initialization" in case:
        observed_functions = ("C_CreateObject", "C_EncryptInit", "C_Encrypt", "C_EncryptUpdate", "C_EncryptFinal", "C_DestroyObject")
    if mode == "unsupported-lifecycle" and "hkdf_refusal" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_DeriveKey", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "unsupported-lifecycle" and "ecdh_contract" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_DeriveKey", "C_GetAttributeValue", "C_SignInit", "C_Sign", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "unsupported-lifecycle" and "curve_operations" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_GenerateKeyPair", "C_CreateObject", "C_DeriveKey", "C_GetAttributeValue", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "unsupported-lifecycle" and "rsa_roundtrip" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "mechanism-request-guard":
        observed_functions = ('C_CreateObject', 'C_DigestInit', 'C_Digest', 'C_DestroyObject', 'C_CloseSession')
    if mode == "agreement-input-guards":
        observed_functions = ("C_Login", "C_GenerateKeyPair", "C_DeriveKey", "C_DigestInit", "C_Digest", "C_DestroyObject", "C_CloseSession")
    if mode == "agreement-input-guards" and "typed_ecdh_kdf" in case:
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_GenerateKeyPair", "C_DeriveKey", "C_DigestInit", "C_Digest", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "drain-ticket-identity":
        observed_functions = ("C_OpenSession", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_CloseSession", "C_Finalize")
    if mode == "token-drain-session":
        observed_functions = ("C_InitToken", "C_OpenSession", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_CloseSession", "C_Finalize")
    if mode == "pqc-verification-guards":
        observed_functions = ("C_CreateObject", "C_VerifyInit", "C_Verify", "C_VerifyUpdate", "C_VerifyFinal", "C_DigestInit", "C_Digest", "C_DestroyObject", "C_CloseSession")
    if mode == "session-conversion":
        observed_functions = ("C_OpenSession", "C_Login", "C_GenerateKeyPair", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_DestroyObject", "C_CloseSession")
    if mode == "generated-aes":
        observed_functions = ("C_Login", "C_GenerateKey", "C_DestroyObject", "C_Logout", "C_CloseSession")
        if case["id"] == "aes.generated.gcm-authentication":
            observed_functions += ("C_GenerateRandom", "C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt")
        else:
            observed_functions += ("C_FindObjectsInit", "C_FindObjectsFinal")
    if mode == "signing-guards":
        observed_functions = ("C_Login", "C_GenerateKeyPair", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_DigestInit", "C_Digest", "C_MessageSignInit", "C_MessageVerifyInit", "C_DestroyObject", "C_CloseSession")
    if mode == "verification-guards":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Initialize", "C_CreateObject", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "admission-scope":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Login", "C_Logout", "C_CreateObject", "C_CloseSession", "C_Finalize")
    if mode == "input-guard":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Login", "C_Logout", "C_CreateObject", "C_GenerateKey", "C_GenerateKeyPair", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_CloseSession", "C_Finalize")
    if mode == "digest-family-view":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_CreateObject", "C_DestroyObject", "C_CloseSession")
    if mode == "digest-ticket-cipher":
        observed_functions = TICKET_FAMILY_FUNCTIONS + ("C_Login", "C_Logout", "C_CreateObject", "C_DestroyObject", "C_CloseSession")
    if mode == "ticket-owner-identity":
        observed_functions = ("C_OpenSession", "C_CloseSession", "C_Finalize", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_Login", "C_LoginUser", "C_GetOperationState")
    if mode == "des-parity":
        observed_functions = ("C_CreateObject", "C_DestroyObject", "C_CloseSession")
    if mode == "ecdh-invalid":
        observed_functions = ("C_CreateObject", "C_DeriveKey", "C_DestroyObject", "C_CloseSession")
    if mode == "gcm-usage":
        observed_functions = ("C_CreateObject", "C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt", "C_DestroyObject", "C_CloseSession")
    if mode == "binary-generation":
        observed_functions = ("C_Login", "C_GenerateKeyPair", "C_DeriveKey", "C_DestroyObject", "C_Logout", "C_CloseSession")
    if mode == "aes-entry-guard":
        observed_functions = ("C_GenerateKey", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_DestroyObject", "C_CloseSession")
    if mode in ("rsa-aes-private-unwrap", "rsa-aes-private-wrap"):
        observed_functions = ("C_Login", "C_CreateObject", "C_UnwrapKey", "C_SignInit",
                              "C_Sign", "C_WrapKey", "C_DestroyObject", "C_CloseSession")
    if mode == "rsa-wrap-negative":
        observed_functions = ("C_Login", "C_CreateObject", "C_WrapKey", "C_UnwrapKey", "C_GetAttributeValue", "C_DestroyObject", "C_CloseSession")
    if mode == "rsa-wrap-negative" and "independent_secret_wrap" in case and case["independent_secret_wrap"]:
        observed_functions += ("C_SignInit", "C_Sign")
    if mode in ("rsa-unwrap-negative", "extension-rsa-aes-session", "extension-rsa-aes-advanced"):
        observed_functions = ("C_Login", "C_CreateObject", "C_UnwrapKey", "C_GetAttributeValue", "C_DestroyObject", "C_CloseSession")
    if mode == "transport-negative":
        observed_functions = ("C_CreateObject", "C_WrapKey", "C_UnwrapKey", "C_GetAttributeValue", "C_DestroyObject", "C_CloseSession")
    if mode in ("concatenation-negative", "concatenation-values"):
        observed_functions = ("C_CreateObject", "C_DeriveKey", "C_GetAttributeValue", "C_DestroyObject", "C_CloseSession")
    if mode == "classical-changed":
        observed_functions = MAC_FUNCTIONS + ("C_CreateObject", "C_DestroyObject", "C_CloseSession")
    if mode == "cipher-usage":
        observed_functions = ("C_CreateObject", "C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt", "C_DestroyObject", "C_CloseSession")
    if mode == "generation-negative":
        observed_functions = ("C_Login", "C_Logout", "C_GenerateKey", "C_GenerateKeyPair", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_DestroyObject", "C_CloseSession")
    if mode in ("classical-sign-denied", "classical-verify-denied", "signature-extension-stream-route", "signature-extension-single-route"):
        observed_functions = MAC_FUNCTIONS + ("C_CreateObject", "C_DestroyObject", "C_CloseSession")
    if mode == "extension-objects":
        observed_functions = ("C_CreateObject", "C_WrapKey", "C_UnwrapKey", "C_DeriveKey", "C_GetAttributeValue", "C_DestroyObject", "C_CloseSession")
    if mode == "extension-pair":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_GenerateKeyPair", "C_GetAttributeValue", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "gcm-vector" and "gcm_short_input" in case:
        observed_functions = observed_functions + ("C_CreateObject", "C_DestroyObject")
    if mode == "gcm-parameters":
        observed_functions = ("C_CreateObject", "C_EncryptInit", "C_Encrypt", "C_DestroyObject", "C_CloseSession")
    if mode == "runtime-successor":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_Login", "C_CreateObject", "C_GetAttributeValue", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_CloseSession", "C_Finalize", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetSessionInfo", "C_DestroyObject")
    if mode == "extension-generation":
        observed_functions = ("C_Initialize", "C_OpenSession", "C_GenerateKey", "C_GetAttributeValue", "C_EncryptInit", "C_Encrypt", "C_DecryptInit", "C_Decrypt", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode in ("extension-cipher", "extension-gcm", "extension-oaep", "extension-oaep-null"):
        observed_functions = CIPHER_FUNCTIONS + ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "extension-signature":
        observed_functions = MAC_FUNCTIONS + ("C_Initialize", "C_OpenSession", "C_CreateObject", "C_DestroyObject", "C_CloseSession", "C_Finalize")
    if mode == "recovery-record":
        observed_functions = ("C_OpenSession", "C_CloseSession", "C_Login", "C_Logout", "C_CreateObject", "C_DestroyObject", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_DecryptInit", "C_DecryptDigestUpdate", "C_DecryptFinal", "C_GetOperationState", "C_SetOperationState")
    if mode == "record-parser":
        observed_functions = ("C_GetOperationState", "C_SetOperationState", "C_Finalize")
    if mode == "public-guard":
        observed_functions = ("C_OpenSession", "C_CloseSession", "C_Finalize", "C_CreateObject", "C_GetAttributeValue", "C_DestroyObject", "C_GetSessionValidationFlags", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal")
    if mode == "public-guard" and case["id"] == "accessor.Module::call_counts":
        observed_functions = observed_functions + ("C_GetInfo",)
    if mode == "object-transition":
        observed_functions = ("C_OpenSession", "C_Login", "C_Logout", "C_CreateObject", "C_CopyObject", "C_DestroyObject", "C_SetAttributeValue", "C_GetAttributeValue", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_SignInit", "C_Sign", "C_CloseSession", "C_Finalize")
    if mode == "object-transition" and case["id"] == "authentication.shared-login.private-token-use":
        observed_functions = observed_functions + ("C_GetSessionInfo",)
    if mode == "ticket-state-guard":
        observed_functions = ("C_Login", "C_Logout", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal", "C_GetOperationState", "C_SessionCancel", "C_AsyncComplete", "C_CloseSession")
    if mode == "direct-material":
        observed_functions = ("C_Login", "C_Logout", "C_CreateObject", "C_WrapKey", "C_UnwrapKey", "C_DeriveKey", "C_GetAttributeValue", "C_DestroyObject", "C_CloseSession")
    if mode == "direct-generation":
        observed_functions = ("C_Login", "C_Logout", "C_GenerateKey", "C_GenerateKeyPair", "C_DestroyObject", "C_CloseSession", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify")
    if mode == "generation-transition":
        observed_functions = ("C_Login", "C_Logout", "C_GenerateKey", "C_GenerateKeyPair", "C_GetOperationState", "C_SessionCancel", "C_DestroyObject", "C_CloseSession", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_EncapsulateKey", "C_DecapsulateKey")
    if mode in ("rsa-usage", "rsa-changed-signature", "rsa-negative"):
        observed_functions = MAC_FUNCTIONS + CIPHER_FUNCTIONS + ("C_CreateObject", "C_DestroyObject", "C_CloseSession")
    if mode == "gcm-withholding":
        observed_functions = CIPHER_FUNCTIONS + ("C_CreateObject", "C_DestroyObject", "C_CloseSession")
    if mode == "aead-preinit":
        observed_functions = ("C_Login", "C_CreateObject", "C_MessageEncryptInit", "C_EncryptMessage", "C_EncryptMessageBegin", "C_EncryptMessageNext", "C_MessageEncryptFinal", "C_Logout", "C_CloseSession")
    if mode == "absent-mechanism":
        observed_functions = ("C_Login", "C_CreateObject", "C_DestroyObject", "C_DigestInit", "C_Digest", "C_SignInit", "C_Sign", "C_VerifyInit", "C_Verify", "C_GenerateKeyPair", "C_Logout", "C_CloseSession")
    if mode == "ticket-boundary":
        observed_functions = tuple(dict.fromkeys(TICKET_FAMILY_FUNCTIONS + ("C_SignRecoverInit", "C_SignRecover", "C_VerifyRecoverInit", "C_VerifyRecover", "C_CloseSession")))
    if mode == "import-encoding":
        observed_functions = ("C_Login", "C_CreateObject", "C_DestroyObject", "C_DigestInit", "C_Digest", "C_Logout", "C_CloseSession")
    if mode == "kem-import":
        observed_functions = ("C_Login", "C_CreateObject", "C_GetAttributeValue", "C_DestroyObject", "C_Logout", "C_CloseSession")
    if mode == "kem-vector":
        observed_functions = ("C_CreateObject", "C_DecapsulateKey", "C_GetAttributeValue", "C_DestroyObject")
    if mode == "digest-refused":
        observed_functions = TRANSITION_DIGEST_FUNCTIONS
    if mode == "cipher-batch-transition":
        observed_functions = CIPHER_FUNCTIONS + ("C_GetOperationState", "C_SessionCancel", "C_CloseSession")
    if mode == "dual-cbc":
        observed_functions = ("C_Login", "C_DigestInit", "C_Digest", "C_SignInit", "C_VerifyInit", "C_EncryptInit", "C_DecryptInit", "C_CloseSession", "C_Logout")
    if mode == "digest-stream":
        runs = case["expected_native_call_runs"]
        if (len(runs) != 3 or runs[0] != ["C_DigestInit", 1]
                or runs[-1] != ["C_DigestFinal", 1] or runs[1][0] != "C_DigestUpdate"
                or type(runs[1][1]) is not int or not 1 <= runs[1][1] <= 131072
                or runs[1][1] != case["update_calls"]):
            raise ValueError("invalid streamed digest observation contract")
        expected = [name for name, count in runs for _ in range(count)]
    else:
        expected = case["expected_native_calls"]
    if "expected_native_calls_by_interface" in case:
        selected = case["expected_native_calls_by_interface"]
        if (mode != "advanced-setting" or not isinstance(selected, dict)
                or set(selected) != {"Legacy240", "Standard32"}
                or expected != selected["Standard32"]
                or args.interface not in selected):
            raise ValueError("invalid interface-specific observation contract")
        expected = selected[args.interface]
    no_native_call = mode == "ecdsa-encoding" or (mode == "engine-choices" and case["engine_action"] == "missing")
    if (no_native_call and expected != []) or (not no_native_call and not expected):
        raise ValueError("unexpected observation contract")
    if any(name not in observed_functions for name in expected):
        raise ValueError("unexpected observed function")
    context = f"linux.{args.rust}.{args.recipe_name}.{args.backend}.{args.interface}"
    if context not in case["contexts"]:
        raise ValueError("case does not apply to this explicit context")
    owner = OwnedTokens(root)
    owners.append(owner)
    tokens = owner.path
    config = root / "softhsm.conf"
    config.write_text("directories.tokendir = " + str(tokens) + "\n"
                      "objectstore.backend = " + args.backend + "\nlog.level = ERROR\n")
    env = environment(recipe, config, root)
    peer_module = None
    if mode == "cross-runtime-guard":
        peer_module = root / "peer-module.so"
        with module.open("rb") as source, peer_module.open("xb") as destination:
            shutil.copyfileobj(source, destination, 65536)
        peer_module.chmod(0o500)
        if digest(peer_module) != recipe["sha256"] or peer_module.samefile(module):
            raise ValueError("independent unchanged peer image required")
        env["FE11_PUBLIC_PEER_MODULE"] = str(peer_module)

    if mode == "engine-choices" and case["engine_action"] != "missing":
        if args.verify_engine is None or not args.verify_engine.is_absolute():
            raise ValueError("explicit absolute verification-engine path required")
        engine = args.verify_engine.resolve(strict=True)
        if (not re.fullmatch(r"[0-9a-f]{64}", args.verify_engine_sha256 or "")
                or digest(engine) != args.verify_engine_sha256):
            raise ValueError("verification-engine identity mismatch")
        env.update(FE11_PUBLIC_VERIFY_ENGINE=str(engine),
                   FE11_PUBLIC_VERIFY_ENGINE_SHA256=args.verify_engine_sha256)

    label = "fe11-" + secrets.token_hex(8)
    # PIN mutation cases use UTF-8 ASCII values; a one-bit mutation of the
    # first byte remains valid UTF-8 and cannot change the tested PIN length.
    def fresh_pin():
        return (bytearray(secrets.token_hex(8), "ascii") if mode in ("pin-admission", "authentication-state")
                else bytearray(secrets.token_bytes(16)))
    officer = fresh_pin()
    user = fresh_pin()
    wire = frames(officer, user)
    identities = dict(source_sha256=args.source_sha256, recipe_sha256=recipe_sha,
                      module_sha256=recipe["sha256"])
    result = dict(scope="fe11_case", case=args.case, context=context,
                  worker_sha256=args.worker_sha256, vector_sha256=case["sha256"],
                  manifest_sha256=args.manifest_sha256, gate_sha256=args.gate_sha256,
                  body_started=False, **identities)

    def command(mode, case_id):
        return [str(args.worker.resolve()), mode, case_id, args.source_sha256, recipe_sha,
                str(module), recipe["sha256"], args.interface, label, str(vector)]

    try:
        child_umask = -1
        if case.get("configuration_variant", "").startswith("umask-"):
            from permission_modes import prepare
            prepare(root, config, case, vector)
            child_umask = 0
        provision = execute(command("provision", "case-provision"), dict(env, LD_DEBUG="files"), root / "provision", wire,
                            child_umask=child_umask)
        result["provision_process"] = provision
        verify_worker(root / "provision/stdout.raw", provision, dict(identities, case="case-provision"),
                      "preparation_terminal")
        result["provision_dependencies"] = verify_dependencies(root / "provision/stderr.raw", gate["dependencies"])
        if "store_visibility" in case:
            from store_visibility import execute_composition
            result.update(execute_composition(root, case, vector, env, wire, command,
                                             identities, recipe, gate, observed_functions, owners))
            return result
        if "configuration_variant" in case:
            from configuration_variants import apply as apply_configuration_variant
            apply_configuration_variant(root, config, case, vector)
        observation = root / "observation"
        trace = observation / "trace.jsonl"
        observer_config = root / "observer.json"
        observer_options = dict(module=str(module), module_sha256=recipe["sha256"],
                                functions=list(observed_functions), output=str(trace))
        if mode == "builder-runtime-choices":
            observer_options["initialization_metadata"] = True
        if mode == "generation-transition" and case["fixture"]["route"] in (
                "typed_generate_montgomery_key", "typed_generate_montgomery_key_448"):
            observer_options["generation_returns"] = True
            env["FE11_PUBLIC_KEYPAIR_RETURNS"] = str(observation / "keypair-returns")
        if peer_module is not None:
            observer_options["peer_module"] = str(peer_module)
        save(observer_config, observer_options)
        gdb = shutil.which("gdb", path=env["PATH"])
        if gdb is None:
            raise ValueError("GDB prerequisite missing")
        worker = command(mode, args.case)
        worker_report = observation / "worker.jsonl"
        for value in worker + [str(worker_report)]:
            if "\n" in value or "\r" in value:
                raise ValueError("line delimiter in GDB argument")
        inferior_args = " ".join(shlex.quote(value) for value in worker[1:])
        inferior_args += " > " + shlex.quote(str(worker_report))
        invocation = [gdb, "-nx", "-nh", "-batch", "-iex", "set auto-load no",
                      "-iex", "set debuginfod enabled off", "-iex", "set print frame-arguments none",
                      "-iex", "set confirm off", "-iex", "set disable-randomization off",
                      "-ex", "set environment LD_DEBUG files",
                      "-ex", "set args " + inferior_args,
                      "-ex", "starti", "-x", str(HERE / "native_observer.py"), "-ex", "continue", worker[0]]
        if case.get("configuration_variant") == "directory-inaccessible":
            from denied_directory import constrain
            invocation = constrain(invocation, env, root)
        process = execute(invocation, dict(env, FE11_OBSERVER_CONFIG=str(observer_config)), observation, wire,
                          child_umask=child_umask)
        result["observer_process"] = process
        expected_dependencies = gate["dependencies"]
        if ((mode == "engine-choices" and case["engine_action"] == "missing")
                or (mode == "builder-runtime-choices"
                    and case.get("configuration_variant") in ("log-invalid", "absent-file", "directory-missing", "directory-file", "directory-inaccessible")
                    and expected == ["C_Initialize"])):
            # Missing engine selection and these exact early initialization
            # failures occur before provider loading. ELF dependencies remain
            # mandatory; an unexpected provider image still fails verification.
            expected_dependencies = [item for item in expected_dependencies
                                     if Path(item["path"]).name not in ("legacy.so", "gost.so")]
        result["case_dependencies"] = verify_dependencies(observation / "stderr.raw", expected_dependencies)
        # The large-message fixtures require up to 131072 update entries.
        # Bound the trace by the declared call count, independently of input size.
        # Discovery can load the same image during preparation and in two
        # independent readers. Relocation records are evidence too, even when
        # the body makes no native calls. Bound them from the declared workload.
        image_loads = case.get("observer_image_loads", 1)
        if type(image_loads) is not int or not 1 <= image_loads <= 3:
            raise ValueError("invalid image observation bound")
        trace_bound = 16384 + (len(expected) + image_loads * len(observed_functions)) * 512
        records = read_records(trace, maximum=min(64 * 1024 * 1024, trace_bound))
        if not records or records[-1].get("kind") != "observer_terminal":
            raise ValueError("missing native observer terminal record")
        # GDB's own exit code is not the inferior's exit code. Keep both and
        # validate the worker protocol against the latter, including FAIL reports.
        inferior = dict(process, exit_code=records[-1].get("exit_code"))
        worker_records = verify_worker(worker_report, inferior, dict(identities, case=args.case),
                                       "terminal", require_success=False)
        result["worker_records"] = worker_records
        if observer_options.get("generation_returns"):
            returns = (observation / "keypair-returns").read_text(encoding="ascii").splitlines()
            entries = sum(row.get("kind") == "entry" and row["function"] == "C_GenerateKeyPair"
                          for row in records)
            if (len(returns) != entries or not records[-1].get("complete")
                    or any(not rv.isdecimal() or len(rv) > 20 or int(rv) >= 2**64 for rv in returns)):
                raise ValueError("incomplete key-pair return observation")
            result["generation_returns"] = list(map(int, returns))
        result["body_started"] = worker_records[-1]["body"] != "NOT_EXECUTED"
        if case.get("independent_wrap") and worker_records[-1]["status"] == "PASS":
            from wrap_reference import verify
            result["independent_reference"] = verify(case, vector, observation)
        if mode == "oaep-encrypt" and worker_records[-1]["status"] == "PASS":
            # The worker's PASS covers only native completion and cleanup.
            # This independent reference is mandatory before the case can pass.
            oracle = HERE / "rsa_reference.py"
            if digest(oracle) != case["reference_sha256"]:
                raise ValueError("RSA reference source changed")
            from rsa_reference import decrypt_oaep
            output = observation / "public-rsa-ciphertext.bin"
            if output.is_symlink() or not output.is_file() or output.stat().st_size > 2048:
                raise ValueError("invalid public RSA reference output")
            fields = vector.read_text().splitlines()
            if len(fields) != 15 or fields[1] != "valid":
                raise ValueError("unexpected OAEP encryption fixture")
            try:
                plaintext = decrypt_oaep(output.read_bytes(), int(fields[4], 16), int(fields[6], 16),
                                         fields[2], fields[3], bytes.fromhex(fields[12]))
                reference_valid = plaintext == bytes.fromhex(fields[14])
            except ValueError:
                reference_valid = False
            result["independent_reference"] = dict(status="PASS" if reference_valid else "FAIL", source_sha256=digest(oracle),
                output_sha256=digest(output), output_bytes=output.stat().st_size,
                boundary="Python RSA and RFC8017 decoding; hashlib may share OpenSSL hashes")
        if mode == "digest-stream" and worker_records[-1]["status"] == "PASS":
            for name, value in (("stream_bytes_completed", case["total_bytes"]),
                                ("stream_updates_completed", case["update_calls"])):
                measured = [row for row in worker_records[:-1] if row["assertion"] == name]
                if len(measured) != 1 or measured[0]["value"] != value:
                    raise ValueError("completed stream dimensions differ from the fixture")
        if mode == "generation-vector" and "rsa_witness_bits" in case and worker_records[-1]["status"] == "PASS":
            if (digest(HERE / "rsa_reference.py") != case["reference_sha256"]
                    or digest(HERE / "generated_rsa_reference.py") != case["generated_reference_sha256"]):
                raise ValueError("generated RSA reference source changed")
            from generated_rsa_reference import verify
            result["independent_reference"] = verify(observation, case["rsa_witness_bits"])
        if mode == "rsa-domain" and worker_records[-1]["status"] == "PASS":
            if (digest(HERE / "rsa_reference.py") != case["reference_sha256"]
                    or digest(HERE / "rsa_domain_reference.py") != case["domain_reference_sha256"]):
                raise ValueError("RSA domain reference source changed")
            from rsa_domain_reference import verify
            result["independent_reference"] = verify(vector, observation)
        if mode == "context-pss-login" and worker_records[-1]["status"] == "PASS":
            if (digest(HERE / "rsa_reference.py") != case["reference_sha256"]
                    or digest(HERE / "context_reference.py") != case["context_reference_sha256"]):
                raise ValueError("context reference source changed")
            from context_reference import verify
            result["independent_reference"] = verify(vector, observation)
        if mode == "rsa-negative" and (worker_records[-1]["status"] == "PASS" or any(
                row.get("assertion") == "rsa_positive_controls_complete"
                and row.get("producer") == "test_oracle" and row.get("value") is True
                for row in worker_records)):
            if (digest(HERE / "rsa_reference.py") != case["reference_sha256"]
                    or digest(HERE / "rsa_negative_reference.py") != case["negative_reference_sha256"]):
                raise ValueError("RSA negative reference source changed")
            from rsa_negative_reference import verify
            result["independent_reference"] = verify(vector, observation)
        if mode == "rsa-aes-private-wrap" and worker_records[-1]["status"] == "PASS":
            from rsa_private_wrap_reference import verify
            result["independent_reference"] = verify(case, vector, observation, gate)
        if mode == "rsa-known" and worker_records[-1]["status"] == "PASS":
            if (digest(HERE / "rsa_reference.py") != case["reference_sha256"]
                    or digest(HERE / "rsa_known_reference.py") != case["known_reference_sha256"]):
                raise ValueError("RSA known reference source changed")
            from rsa_known_reference import verify
            result["independent_reference"] = verify(vector, observation)
        if mode == "pqc-random" and worker_records[-1]["status"] == "PASS":
            if (digest(HERE / "pqc_reference.py") != case["reference_sha256"]
                    or digest(HERE / "reference_encoding.py") != case["encoding_sha256"]):
                raise ValueError("PQC reference source changed")
            from pqc_reference import verify
            result["independent_reference"] = verify(vector, observation, gate["pqc_reference"], env)
        if mode in ("classical-sign", "dsa-import-identity") and worker_records[-1]["status"] == "PASS":
            if (digest(HERE / "classical_reference.py") != case["reference_sha256"]
                    or digest(HERE / "reference_encoding.py") != case["encoding_sha256"]):
                raise ValueError("classical reference source changed")
            from classical_reference import verify
            result["independent_reference"] = verify(vector, observation, gate["public_reference"], env)
        if mode == "ecdsa-transition" and worker_records[-1]["status"] == "PASS":
            for name, expected_sha in case["reference_sources"].items():
                if name not in ("signature_transition_reference.py", "classical_reference.py", "reference_encoding.py") or digest(HERE/name) != expected_sha:
                    raise ValueError("signature transition reference changed")
            if set(case["reference_sources"]) != {"signature_transition_reference.py", "classical_reference.py", "reference_encoding.py"}:
                raise ValueError("signature transition reference incomplete")
            from signature_transition_reference import verify
            result["independent_reference"] = verify(vector, observation, gate["public_reference"], env, case["reference_signature_count"])
        observer_sha = digest(HERE / "native_observer.py")
        sequences = case["expected_native_sequences"] if mode == "rsa-domain" else [expected]
        if mode == "optional-rsa-crt-import" and worker_records[-1]["status"] == "PASS":
            refusals = [item for item in worker_records if item.get("assertion") == "creation_return"]
            if refusals:
                if len(refusals) != 1 or refusals[0]["producer"] != "native" or (
                    refusals[0]["value"]["function"], refusals[0]["value"]["code"]
                ) != ("C_CreateObject", 0xD0):
                    raise ValueError("optional RSA import refusal lacks native provenance")
                sequences = [["C_CreateObject", "C_CreateObject"]]
        if mode == "ecdsa-vector" and "wrong_curve" in case and case["wrong_curve"] is True and worker_records[-1]["status"] == "PASS":
            stages = [r for r in worker_records if r.get("assertion") == "wrong_curve_rejection_stage"]
            if (len(stages) != 1 or stages[0].get("producer") != "native"
                    or type(stages[0].get("value")) is not int or stages[0]["value"] not in (1, 2, 3)):
                raise ValueError("missing exact wrong-curve native rejection stage")
            sequences = [case["expected_native_sequences"][stages[0]["value"] - 1]]
        if mode == "unsupported-lifecycle" and "ecdh_contract" in case:
            created = [row for row in worker_records[:-1]
                       if row.get("assertion") == "derivation_object_returned"]
            if (len(created) != 1 or type(created[0]["value"]) is not bool
                    or created[0]["producer"] != "native"):
                raise ValueError("missing ECDH creation outcome")
            sequences = [expected if created[0]["value"] else case["expected_refused_native_calls"]]
            result["derivation_object_returned"] = created[0]["value"]
        if mode == "unsupported-lifecycle" and "curve_operations" in case:
            from curve_observations import sequences as curve_sequences
            actual = [entry["function"] for entry in records if entry.get("kind") == "entry"]
            sequences = curve_sequences(case, worker_records, actual)
            for name in ("curve_created_pairs", "curve_owned_objects"):
                result[name] = next(row["value"] for row in worker_records[:-1]
                                    if row.get("assertion") == name)
        if mode == "object-contract" and "creation_contract" in case:
            created = [row for row in worker_records[:-1]
                       if row.get("assertion") == "creation_object_returned"]
            if (len(created) != 1 or type(created[0]["value"]) is not bool
                    or created[0]["producer"] != "native"):
                raise ValueError("missing object creation outcome")
            sequences = [expected if created[0]["value"] else case["expected_refused_native_calls"]]
            result["creation_object_returned"] = created[0]["value"]
        if mode == "binary-generation" and worker_records[-1]["status"] == "PASS":
            supported = [row for row in worker_records if row.get("assertion") == "binary_curve_supported"]
            if len(supported) != 1 or type(supported[0].get("value")) is not bool:
                raise ValueError("missing binary-curve characterization")
            sequences = [expected if supported[0]["value"] else case["expected_refused_native_calls"]]
            result["curve_characterization"] = {"supported": supported[0]["value"], "scope": "Exact named curve and operation only; a bounded refusal is not successful generation"}
        if mode == "kem-import" and worker_records[-1]["status"] == "PASS":
            accepted = [row for row in worker_records[:-1]
                        if row["assertion"] == "kem_import_accepted"]
            if (len(accepted) != 1 or type(accepted[0]["value"]) is not bool
                    or accepted[0]["producer"] != "native"):
                raise ValueError("missing native import characterization")
            # Import acceptance selects the complete read-and-destroy trace.
            # It must never admit the shorter refusal trace after object creation.
            sequences = [expected if accepted[0]["value"] else case["expected_refused_native_calls"]]
            result["import_characterization"] = {"accepted": accepted[0]["value"],
                "scope": "Object representation only; no FIPS key-validation or KEM operation verdict"}

        sequence_limit = len(expected)
        if mode == "unsupported-lifecycle" and "curve_operations" in case:
            # Unexpected successful generation of the unknown OID still fails,
            # but its two returned objects must be destroyed and observed.
            sequence_limit = max(sequence_limit, 7)
        if (not sequences or len(sequences) > 4 or any((not seq and not no_native_call) or len(seq) > sequence_limit
                or any(name not in observed_functions for name in seq) for seq in sequences)):
            raise ValueError("invalid native sequence alternatives")
        observation_exit = 0
        if mode == "unsupported-lifecycle" and "curve_operations" in case:
            observation_exit = 1 if worker_records[-1]["status"] == "FAIL" else 0
        observed = any(trace_matches(records, seq, recipe["sha256"], observer_sha, observed_functions,
                                     expected_exit_code=observation_exit)
                       for seq in sequences)
        if mode == "builder-runtime-choices":
            actual_initialization = [row.get("initialization") for row in records
                                     if row.get("kind") == "entry" and row.get("function") == "C_Initialize"]
            # Validate every Init named by the exact fixture sequence. A boundary
            # fixture may deliberately reopen independently configured owners.
            expected_initialization = [dict(flags=2, mutexes=[False] * 4, reserved_null=True)
                                       for _ in range(expected.count("C_Initialize"))]
            result["initialization_metadata_matches"] = actual_initialization == expected_initialization
            observed = observed and result["initialization_metadata_matches"]
        if mode == "cross-runtime-guard":
            roles = [row.get("runtime") for row in records if row.get("kind") == "entry"]
            result["native_runtime_sequence"] = roles
            observed = observed and roles == case["expected_native_runtimes"]
        result.update(observer_script_sha256=observer_sha, native_sequence_matches=observed,
                      native_sequence=[row["function"] for row in records if row.get("kind") == "entry"])
        passed = (process["state"] == "EXITED" and process["exit_code"] == 0 and observed
                  and worker_records[-1]["status"] == "PASS"
                  and (mode not in ("oaep-encrypt", "rsa-domain", "rsa-known", "rsa-negative", "context-pss-login", "pqc-random", "classical-sign", "dsa-import-identity", "ecdsa-transition") or result.get("independent_reference", {}).get("status") == "PASS")
                  and (mode != "rsa-aes-private-wrap" or result.get("independent_reference", {}).get("status") == "PASS")
                  and (not case.get("independent_wrap") or result.get("independent_reference", {}).get("status") == "PASS")
                  and ("rsa_witness_bits" not in case or result.get("independent_reference", {}).get("status") == "PASS"))
        result.update(status="PASS" if passed else "FAIL", attribution="NONE" if passed else "UNKNOWN")
        if "configuration_variant" in case and passed:
            from configuration_variants import observe as observe_configuration_variant
            observed_files = observe_configuration_variant(root, case, (officer, user), result)
            result["configuration_files"] = observed_files
            if observed_files["status"] != "PASS":
                result.update(status="FAIL", attribution="UNKNOWN")
    except Exception as error:
        result.update(status="INCOMPLETE", attribution="UNKNOWN", failure_category=type(error).__name__)
        raise
    finally:
        try:
            if case.get("configuration_variant") == "directory-inaccessible":
                if storage_identity(owner.path) != owner.token_identity:
                    raise ValueError("permission restoration target identity changed")
                owner.path.chmod(0o700)
        except Exception:
            result.update(status="INCOMPLETE", attribution="UNKNOWN", failure_category="PermissionRestoration")
            raise
        finally:
            erase(wire)
            erase(officer)
            erase(user)
            save(root / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "recipe", "worker", "manifest", "gate"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("worker-sha256", "source-sha256", "manifest-sha256", "gate-sha256", "case"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--backend", choices=("file", "db"), required=True)
    parser.add_argument("--interface", choices=("Legacy240", "Standard32"), required=True)
    parser.add_argument("--rust", choices=("1.81.0", "1.100.0"), required=True)
    parser.add_argument("--recipe-name", choices=("openssl-full", "openssl-gost"), required=True)
    parser.add_argument("--verify-engine", type=Path)
    parser.add_argument("--verify-engine-sha256")
    result = run_case(parser.parse_args())
    print(json.dumps({key: result[key] for key in ("case", "context", "status", "attribution")}))
    if result["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
