import type { Envelope } from "../../Envelope";
import type { RatchetStateItem } from "../index";

export const tryRatchetStateSkippedKey = (ratchetState: RatchetStateItem, envelope: Envelope): Uint8Array | undefined => {
	const candidates = ratchetState.skippedKeys.filter((k) => k.messageNumber === envelope.messageNumber);

	if (candidates.length === 0) return undefined;

	// Try all candidates regardless of success to prevent timing attacks
	let successData: Uint8Array | undefined;
	let successCandidate: typeof candidates[0] | undefined;

	for (const candidate of candidates) {
		try {
			const data = envelope.cipherData.decrypt(candidate.secret);
			// Only store first success, but continue trying others for constant timing
			if (!successData) {
				successData = data;
				successCandidate = candidate;
			}
		} catch {
			// Continue to maintain constant timing
		}
	}

	if (successData && successCandidate) {
		ratchetState.skippedKeys = ratchetState.skippedKeys.filter((k) => k !== successCandidate);
		return successData;
	}

	return undefined;
};
