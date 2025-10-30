import { compare } from "uint8array-tools";
import { Envelope } from "../index.js";
import { RatchetError } from "../../Error/index.js";
import { MlKemCipherTextCodec } from "../../RatchetKeysItem/MlKemCodec.js";

// Low-order X25519 points that should be rejected
const LOW_ORDER_POINTS = [
	new Uint8Array(32), // All zeros
	new Uint8Array(32).fill(1), // Point of order 1
	new Uint8Array([
		0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
		0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
		0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
		0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57
	]), // Point of order 2
	new Uint8Array([
		0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
		0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
		0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00
	]), // Point of order 4
	new Uint8Array([
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
	]), // Point of order 8
];

/**
 * Verifies the envelope's protocol version, structure, and signature.
 *
 * Comprehensive validation including:
 * - Protocol version check
 * - Field length validation (keyId, dhPublicKey, messageNumber, etc.)
 * - Low-order point detection for X25519 keys (prevents weak DH attacks)
 * - ML-KEM ciphertext validation if present
 * - Signature verification
 *
 * This should be called BEFORE any database lookups or processing to fail fast
 * on invalid envelopes and prevent database read amplification attacks.
 *
 * @param envelope - The envelope to verify
 * @param remoteNodeId - Expected sender's nodeId (20 bytes)
 * @throws {RatchetError} If any validation fails
 *
 * @example
 * ```typescript
 * envelope.verify(senderNodeId);
 * // Now safe to proceed with database lookups and decryption
 * ```
 */
export const verifyEnvelope = (envelope: Envelope, remoteNodeId: Uint8Array): void => {
	// Validate protocol version
	if (envelope.version !== Envelope.PROTOCOL_VERSION) {
		throw new RatchetError(`Unsupported protocol version: ${envelope.version}, expected ${Envelope.PROTOCOL_VERSION}`);
	}

	// Validate keyId length (8 bytes)
	if (envelope.keyId.byteLength !== 8) {
		throw new RatchetError(`Invalid keyId length: ${envelope.keyId.byteLength}, expected 8`);
	}

	// Validate dhPublicKey length (32 bytes for X25519)
	if (envelope.dhPublicKey.byteLength !== 32) {
		throw new RatchetError(`Invalid dhPublicKey length: ${envelope.dhPublicKey.byteLength}, expected 32`);
	}

	// Check for low-order X25519 points (security vulnerability)
	for (const lowOrderPoint of LOW_ORDER_POINTS) {
		if (compare(envelope.dhPublicKey, lowOrderPoint) === 0) {
			throw new RatchetError("Invalid X25519 public key: low-order point detected");
		}
	}

	// Validate messageNumber (non-negative, safe integer)
	if (envelope.messageNumber < 0 || !Number.isSafeInteger(envelope.messageNumber)) {
		throw new RatchetError(`Invalid messageNumber: ${envelope.messageNumber}`);
	}

	// Validate previousChainLength (non-negative)
	// Note: previousChainLength CAN be greater than messageNumber after a DH ratchet
	// because messageNumber resets to 0 but previousChainLength tracks the old sending chain length
	if (envelope.previousChainLength < 0 || !Number.isSafeInteger(envelope.previousChainLength)) {
		throw new RatchetError(`Invalid previousChainLength: ${envelope.previousChainLength}`);
	}

	// Validate kemCiphertext if present (ML-KEM-1024 ciphertext is 1568 bytes)
	if (envelope.kemCiphertext && envelope.kemCiphertext.byteLength !== MlKemCipherTextCodec.byteLength()) {
		throw new RatchetError(`Invalid kemCiphertext length: ${envelope.kemCiphertext.byteLength}, expected ${MlKemCipherTextCodec.byteLength()}`);
	}

	// Verify signature - ensure sender is who they claim to be
	// This recovers the public key from the signature and compares the derived nodeId
	if (compare(envelope.nodeId, remoteNodeId) !== 0) {
		throw new RatchetError("Signature verification failed: recovered nodeId does not match expected remoteNodeId");
	}
};
