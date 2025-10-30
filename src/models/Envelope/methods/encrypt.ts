import type { Envelope } from "..";
import type { Keys } from "../../Keys";
import { RatchetKeysPublic } from "../../RatchetKeysItem/PublicCodec";
import type { RatchetStateItem } from "../../RatchetStateItem";

export interface EncryptOptions {
	messageBound?: number;
	timeBound?: number;
}

export const encryptEnvelope = (data: Uint8Array, ratchetState: RatchetStateItem, keys: Keys, initiationKeys?: RatchetKeysPublic, options?: EncryptOptions): Envelope => {
	let kemCiphertext: Uint8Array | undefined;

	const shouldRotate = ratchetState.shouldRatchet(options?.messageBound, options?.timeBound);

	if (shouldRotate && initiationKeys) {
		kemCiphertext = ratchetState.performMlKemRatchet(initiationKeys);
	}

	return ratchetState.encryptMessage(data, keys, kemCiphertext);
};
