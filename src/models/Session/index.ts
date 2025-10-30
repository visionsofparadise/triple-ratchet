import { EventEmitter } from "events";
import { Keys } from "../Keys/index.js";
import { RatchetKeysItem } from "../RatchetKeysItem/index.js";
import { RatchetStateItem } from "../RatchetStateItem/index.js";
// import { Envelope } from "../Envelope/index.js";
import { EnvelopeCodec } from "../Envelope/Codec.js";
import { RatchetError } from "../Error/index.js";
import { createShortHash } from "../../utilities/Hash.js";
import type { RatchetKeysPublic } from "../RatchetKeysItem/PublicCodec.js";

export interface SessionOptions {
	localKeys: Keys;
	localInitiationKeys: RatchetKeysItem;
	remoteNodeId: Uint8Array;
	remoteInitiationKeys?: RatchetKeysPublic;
	state?: RatchetStateItem;
}

export interface SessionEvents {
	/** Emitted when a buffer needs to be sent to the remote peer */
	send: (buffer: Uint8Array) => void;

	/** Emitted when a data message is decrypted */
	message: (data: Uint8Array) => void;

	/** Emitted when session state changes (for persistence) */
	stateChanged: () => void;

	/** Emitted on errors */
	error: (error: Error) => void;
}

export declare interface Session {
	on<K extends keyof SessionEvents>(event: K, listener: SessionEvents[K]): this;
	emit<K extends keyof SessionEvents>(event: K, ...args: Parameters<SessionEvents[K]>): boolean;
}

/**
 * Session manages encrypted communication with a single peer
 */
export class Session extends EventEmitter {
	private localKeys: Keys;
	private localInitiationKeys: RatchetKeysItem;
	private remoteNodeId: Uint8Array;
	private ratchetState?: RatchetStateItem;
	private remoteInitiationKeys?: RatchetKeysPublic;

	constructor(options: SessionOptions) {
		super();

		this.localKeys = options.localKeys;
		this.localInitiationKeys = options.localInitiationKeys;
		this.remoteNodeId = options.remoteNodeId;
		this.ratchetState = options.state;
		this.remoteInitiationKeys = options.remoteInitiationKeys;
	}

	/**
	 * Send encrypted data to the peer
	 */
	async send(data: Uint8Array): Promise<void> {
		try {
			if (!this.remoteInitiationKeys) {
				throw new RatchetError("Remote initiation keys not set - must be provided out of band");
			}

			// Initialize session as initiator if needed
			if (!this.ratchetState) {
				const result = RatchetStateItem.initializeAsInitiator(
					this.localKeys.nodeId,
					this.remoteNodeId,
					this.remoteInitiationKeys,
					data,
					this.localKeys
				);

				this.ratchetState = result.ratchetState;
				this.emit("send", result.envelope.buffer);
				this.emit("stateChanged");
				return;
			}

			// Encrypt and send
			const envelope = this.ratchetState.encryptMessage(data, this.localKeys);

			this.emit("send", envelope.buffer);
			this.emit("stateChanged");
		} catch (error) {
			this.emit("error", error instanceof Error ? error : new Error(String(error)));
		}
	}

	/**
	 * Receive and process envelope from peer
	 */
	receive(buffer: Uint8Array): void {
		try {
			const envelope = EnvelopeCodec.decode(buffer);

			// Verify envelope signature
			const recoveredPublicKey = Keys.recover(envelope.rSignature, envelope.hash);
			const recoveredNodeId = createShortHash(recoveredPublicKey);

			if (!recoveredNodeId.every((byte, i) => byte === this.remoteNodeId[i])) {
				throw new RatchetError("Invalid envelope signature");
			}

			// Initialize session as responder if needed
			if (!this.ratchetState) {
				this.ratchetState = RatchetStateItem.initializeAsResponder(
					envelope,
					this.localKeys.nodeId,
					this.localInitiationKeys,
					this.remoteNodeId
				);
			}

			// Decrypt
			const data = this.ratchetState.decryptMessage(envelope);

			this.emit("message", data);
			this.emit("stateChanged");
		} catch (error) {
			this.emit("error", error instanceof Error ? error : new Error(String(error)));
		}
	}

	/**
	 * Get current ratchet state for persistence
	 */
	getState(): RatchetStateItem | undefined {
		return this.ratchetState;
	}

	/**
	 * Set remote initiation keys (must be exchanged out of band)
	 */
	setRemoteInitiationKeys(keys: RatchetKeysPublic): void {
		this.remoteInitiationKeys = keys;
		this.emit("stateChanged");
	}
}
