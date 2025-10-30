import { RatchetStateItem } from "../index";

/**
 * Determines if ML-KEM ratchet rotation should occur based on message count and time bounds.
 *
 * **Message Bound:** Mandatory synchronization point. Once the sending chain reaches this
 * message count, rotation MUST occur before the next message. This is cryptographically
 * enforced and not subject to clock drift.
 *
 * **Time Bound:** Advisory limit based on wall-clock time. Subject to clock skew between
 * peers - if clocks drift apart, one peer may rotate while the other hasn't reached the
 * time bound yet. The message bound ensures eventual synchronization even with clock skew.
 *
 * **Clock Skew Implications:**
 * - If peer A's clock is ahead: A rotates before B expects, but B can still decrypt
 * - If peer B's clock is behind: B won't rotate until message bound forces it
 * - Message bound acts as mandatory sync point regardless of time drift
 * - Bounded ratchet design ensures session remains usable despite reasonable clock skew
 *
 * **Security Note:** Both bounds are required for security. Message bound prevents unbounded
 * one-sided messaging (SPQR weakness), time bound ensures forward secrecy even with low
 * message rates.
 *
 * @param ratchetState - Current ratchet state
 * @param messageBound - Maximum messages before rotation (default: 100)
 * @param timeBound - Maximum time in ms before rotation (default: 3600000 = 1 hour)
 * @returns true if rotation should occur, false otherwise
 */
export const shouldRatchetStateRatchet = (ratchetState: RatchetStateItem, messageBound = RatchetStateItem.DEFAULT_MESSAGE_BOUND, timeBound = RatchetStateItem.DEFAULT_TIME_BOUND_MS): boolean => {
	if (ratchetState.rootChain.sendingChain.messageNumber >= messageBound) {
		return true;
	}

	const timeSinceRatchet = Date.now() - ratchetState.ratchetAt;

	if (timeSinceRatchet >= timeBound) {
		return true;
	}

	return false;
};
