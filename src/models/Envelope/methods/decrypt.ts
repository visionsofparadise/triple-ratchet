import { compare } from "uint8array-tools";
import type { Envelope } from "..";
import { RatchetStateItem } from "../../RatchetStateItem";

/**
 * Decrypts the envelope using ratchet state.
 *
 * NOTE: This assumes envelope.verify() has already been called to validate
 * the protocol version and signature. Call verify() before any database
 * lookups to fail fast on invalid envelopes.
 *
 * @param envelope - The verified envelope to decrypt
 * @param remoteNodeId - Sender's nodeId (20 bytes)
 * @param ratchetState - Current ratchet state for the session
 * @returns Decrypted plaintext data
 */
export const decryptEnvelope = (envelope: Envelope, _remoteNodeId: Uint8Array, ratchetState: RatchetStateItem): Uint8Array => {
	// Perform DH ratchet if remote DH key changed
	if (compare(envelope.dhPublicKey, ratchetState.rootChain.remoteDhPublicKey) !== 0) {
		ratchetState.performDhRatchet(envelope.dhPublicKey);
	}

	// Decrypt message
	return ratchetState.decryptMessage(envelope);
};
