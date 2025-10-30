import { RatchetStateItem } from "..";

export const pruneRatchetStateSkippedKeys = (ratchetState: RatchetStateItem): void => {
	const now = Date.now();

	ratchetState.skippedKeys = ratchetState.skippedKeys.filter((skippedKey) => now - skippedKey.createdAt <= RatchetStateItem.SKIPPED_KEY_MAX_AGE_MS);
};
