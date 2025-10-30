import type { RatchetStateItem } from "..";

export const performRatchetStateDhRatchet = (ratchetState: RatchetStateItem, remoteDhPublicKey: Uint8Array): void => {
	ratchetState.previousChainLength = ratchetState.rootChain.sendingChain.messageNumber;
	ratchetState.rootChain.performDhRatchet(remoteDhPublicKey);
	ratchetState.ratchetAt = Date.now();
};
