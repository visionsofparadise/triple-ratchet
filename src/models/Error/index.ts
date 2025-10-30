/**
 * Ratchet error with support for separate internal/external messages.
 *
 * Public message is shown to users/applications (should be generic for security).
 * Internal details can include sensitive information for debugging/logging.
 *
 * @example
 * ```typescript
 * // Generic public message, detailed internal info
 * throw new RatchetError('Decryption failed', {
 *   internalDetails: `No local ratchet keys found for keyId: ${keyId.toString('hex')}`
 * });
 *
 * // Log internal details for debugging
 * try {
 *   // ...
 * } catch (error) {
 *   if (error instanceof RatchetError) {
 *     logger.error(error.getInternalMessage());
 *   }
 * }
 * ```
 */
export class RatchetError extends Error {
	/**
	 * Internal details that may contain sensitive information.
	 * Only log/display this in secure debugging contexts.
	 */
	private internalDetails?: string;

	/**
	 * Optional error cause
	 */
	cause?: unknown;

	constructor(
		message: string,
		options?: {
			internalDetails?: string;
			cause?: unknown;
		}
	) {
		super(message);
		this.name = 'RatchetError';
		this.cause = options?.cause;
		this.internalDetails = options?.internalDetails;
	}

	/**
	 * Returns the full internal message including sensitive details.
	 * Use this for logging/debugging in secure contexts only.
	 * Never expose to untrusted parties.
	 */
	getInternalMessage(): string {
		return this.internalDetails || this.message;
	}
}
