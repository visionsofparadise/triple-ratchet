import { RatchetStateItem } from "..";

export const storeRatchetStateSkippedKey = (ratchetState: RatchetStateItem, messageNumber: number, secret: Uint8Array): void => {
	ratchetState.skippedKeys.push({
		messageNumber,
		secret,
		createdAt: Date.now(),
	});
};
