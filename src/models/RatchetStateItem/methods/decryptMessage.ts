import { compare } from "uint8array-tools";
import { RatchetStateItem } from "..";
import type { Envelope } from "../../Envelope";
import { RatchetError } from "../../Error";

export const decryptRatchetStateMessage = (ratchetState: RatchetStateItem, envelope: Envelope): Uint8Array => {
	const skippedData = ratchetState.trySkippedKey(envelope);

	if (skippedData) return skippedData;

	// Check if DH ratchet is needed (remote DH key changed)
	if (compare(envelope.dhPublicKey, ratchetState.rootChain.remoteDhPublicKey) !== 0) {
		ratchetState.performDhRatchet(envelope.dhPublicKey);
	}

	// Validate receivingChain is initialized
	if (!ratchetState.rootChain.receivingChain.chainKey) {
		throw new RatchetError("Receiving chain not initialized");
	}

	// Check for unbounded loop - prevent DoS attack
	const messageDifference = envelope.messageNumber - ratchetState.rootChain.receivingChain.messageNumber;
	if (messageDifference > RatchetStateItem.MAX_MESSAGE_SKIP) {
		throw new RatchetError(`Message skip too large: ${messageDifference} > ${RatchetStateItem.MAX_MESSAGE_SKIP}`);
	}

	while (ratchetState.rootChain.receivingChain.messageNumber < envelope.messageNumber) {
		ratchetState.storeSkippedKeys(ratchetState.rootChain.receivingChain.messageNumber, ratchetState.rootChain.receivingChain.secret);
		ratchetState.rootChain.receivingChain.next();
	}

	const data = envelope.cipherData.decrypt(ratchetState.rootChain.receivingChain.secret);
	ratchetState.rootChain.receivingChain.next();

	return data;
};
