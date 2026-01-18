import { hex } from "@scure/base";
import { EventEmitter } from "events";
import { ControlMessage } from "../ControlMessage";
import { ControlMessageBodyType } from "../ControlMessage/BodyCodec";
import type { Keys } from "../Keys";
import { Message } from "../Message";
import { RatchetKeys } from "../RatchetKeys";
import type { RatchetPublicKeys } from "../RatchetKeys/Public";
import { createTransactionId } from "../TransactionId/Codec";

export namespace ControlProtocolController {
	export interface EventMap {
		send: [buffer: Uint8Array];
		error: [error: unknown];
	}
}

/**
 * Handles control message protocol (in-band key exchange)
 */
export class ControlProtocolController {
	readonly events: EventEmitter<ControlProtocolController.EventMap>;
	private localKeys: Keys;
	private pendingInitiationRequests = new Map<
		string,
		{
			resolve: (initiationKeys: RatchetPublicKeys) => void;
			reject: (error: Error) => void;
			timeout: NodeJS.Timeout;
		}
	>();

	constructor(localKeys: Keys) {
		this.localKeys = localKeys;
		this.events = new EventEmitter();
	}

	/**
	 * Request initiation keys from remote peer with timeout
	 */
	getInitiationKeys(timeoutMs = 5000): Promise<RatchetPublicKeys> {
		const transactionId = createTransactionId();
		const transactionKey = hex.encode(transactionId);

		return new Promise((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.pendingInitiationRequests.delete(transactionKey);
				reject(new Error("Initiation keys request timed out"));
			}, timeoutMs);

			this.pendingInitiationRequests.set(transactionKey, { resolve, reject, timeout });

			const body = ControlMessage.create(
				{
					body: {
						type: ControlMessageBodyType.GET_INITIATION_KEYS,
						transactionId,
					},
				},
				this.localKeys,
			);

			const message = new Message({ body });
			this.events.emit("send", message.buffer);
		});
	}

	/**
	 * Handle incoming control messages
	 */
	handleControlMessage(controlMessage: ControlMessage): RatchetKeys | undefined {
		switch (controlMessage.body.type) {
			case ControlMessageBodyType.GET_INITIATION_KEYS: {
				const transactionId = controlMessage.body.transactionId;
				const localInitiationKeys = new RatchetKeys();

				const body = ControlMessage.create(
					{
						body: {
							type: ControlMessageBodyType.INITIATION_KEYS,
							transactionId,
							initiationKeys: localInitiationKeys.publicKeys,
						},
					},
					this.localKeys,
				);

				const message = new Message({ body });
				this.events.emit("send", message.buffer);

				return localInitiationKeys;
			}
			case ControlMessageBodyType.INITIATION_KEYS: {
				const transactionKey = hex.encode(controlMessage.body.transactionId);
				const pending = this.pendingInitiationRequests.get(transactionKey);

				if (pending) {
					clearTimeout(pending.timeout);

					this.pendingInitiationRequests.delete(transactionKey);

					pending.resolve(controlMessage.body.initiationKeys);
				}

				return undefined;
			}
		}
	}

	/**
	 * Cleanup all pending requests and timeouts
	 */
	close(): void {
		for (const [_key, pending] of this.pendingInitiationRequests.entries()) {
			clearTimeout(pending.timeout);

			pending.reject(new Error("ControlProtocolController closed"));
		}

		this.pendingInitiationRequests.clear();
	}
}
