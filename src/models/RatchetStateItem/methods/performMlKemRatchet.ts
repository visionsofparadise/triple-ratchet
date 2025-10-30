import type { RatchetStateItem } from "..";
import { RatchetKeysPublic } from "../../RatchetKeysItem/PublicCodec";

export const performRatchetStateMlKemRatchet = (ratchetState: RatchetStateItem, initiationKeys: RatchetKeysPublic): Uint8Array => {
	ratchetState.previousChainLength = ratchetState.rootChain.sendingChain.messageNumber;
	ratchetState.ratchetAt = Date.now();

	return ratchetState.rootChain.performMlKemRatchet(initiationKeys);
};
