import type { RatchetStateItem } from "..";
import { CipherData } from "../../CipherData";
import { Envelope } from "../../Envelope";
import { RatchetError } from "../../Error";
import type { Keys } from "../../Keys";

export const encryptRatchetStateMessage = (ratchetState: RatchetStateItem, data: Uint8Array, keys: Keys, kemCiphertext?: Uint8Array): Envelope => {
	// Guard: ensure sending chain is initialized (defensive check)
	if (!ratchetState.rootChain.sendingChain.chainKey) {
		throw new RatchetError("Sending chain not initialized");
	}

	// Guard: ensure remoteKeyId is set
	if (!ratchetState.remoteKeyId) {
		throw new RatchetError("Remote keyId not set in ratchet state");
	}

	const cipherData = CipherData.encrypt(ratchetState.rootChain.sendingChain.secret, data);
	const dhPublicKey = ratchetState.rootChain.dhPublicKey;

	const envelope = Envelope.create(
		{
			version: 0x01,
			keyId: ratchetState.remoteKeyId,
			dhPublicKey,
			messageNumber: ratchetState.rootChain.sendingChain.messageNumber,
			previousChainLength: ratchetState.previousChainLength,
			kemCiphertext,
			cipherData,
		},
		keys
	);

	ratchetState.rootChain.sendingChain.next();

	return envelope;
};
