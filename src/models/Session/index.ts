import { EventEmitter } from "events";
import { Codec } from "bufferfy";
import { compare } from "uint8array-tools";
import { ControlMessage } from "../ControlMessage";
import { Message, MessageCodec } from "../Message";
import { RatchetState } from "../RatchetState";
import { type SessionProperties, SessionPropertiesCodec } from "./Codec";
import { ControlProtocolController } from "./ControlProtocolController";
import type { Envelope } from "../Envelope";
import type { Keys } from "../Keys";
import type { RatchetKeys } from "../RatchetKeys";

export namespace Session {
	export interface Properties extends SessionProperties {}

	export interface Options extends RatchetState.Options {}

	export interface EventMap {
		send: [buffer: Uint8Array];
		message: [data: Uint8Array];
		stateChanged: [];
		error: [error: unknown];
	}
}

export class Session implements Session.Properties {
	events: EventEmitter<Session.EventMap>;

	localKeys: Keys;
	localInitiationKeys?: RatchetKeys;
	remotePublicKey: Uint8Array;
	ratchetState?: RatchetState;

	private controller: ControlProtocolController;
	private readonly options: Session.Options;

	constructor(properties: Session.Properties, options: Session.Options = {}) {
		this.events = new EventEmitter();
		this.options = options;

		this.localKeys = properties.localKeys;
		this.localInitiationKeys = properties.localInitiationKeys;
		this.remotePublicKey = properties.remotePublicKey;
		this.ratchetState = properties.ratchetState;

		this.controller = new ControlProtocolController(this.localKeys);

		this.controller.events.on("send", (buffer) => this.events.emit("send", buffer));
		this.controller.events.on("error", (error) => this.events.emit("error", error));
	}

	get buffer(): Uint8Array {
		return SessionCodec.encode(this);
	}

	get byteLength(): number {
		return SessionCodec.byteLength(this);
	}

	get properties(): Session.Properties {
		const { localKeys, localInitiationKeys, remotePublicKey, ratchetState } = this;

		return { localKeys, localInitiationKeys, remotePublicKey, ratchetState };
	}

	async send(data: Uint8Array): Promise<void> {
		try {
			if (!this.ratchetState) {
				const remoteInitiationKeys = await this.controller.getInitiationKeys();

				const result = RatchetState.initializeAsInitiator(
					this.localKeys.publicKey,
					this.remotePublicKey,
					remoteInitiationKeys,
					data,
					this.localKeys,
					this.options,
				);

				this.ratchetState = result.ratchetState;

				const message = new Message({ body: result.envelope });

				this.events.emit("send", message.buffer);
				this.events.emit("stateChanged");

				return;
			}

			const envelope = this.ratchetState.encrypt(data, this.localKeys);

			const message = new Message({ body: envelope });

			this.events.emit("send", message.buffer);
			this.events.emit("stateChanged");
		} catch (error) {
			this.events.emit("error", error instanceof Error ? error : new Error(String(error)));
		}
	}

	receive(buffer: Uint8Array): void {
		try {
			const message = MessageCodec.decode(buffer);

			if (compare(message.body.publicKey, this.remotePublicKey) !== 0) {
				throw new Error("Invalid control message signature");
			}

			if (message.body instanceof ControlMessage) {
				const controlMessage = message.body;

				this.handleControlMessage(controlMessage);
			} else {
				const envelope = message.body;

				this.handleEnvelope(envelope);
			}
		} catch (error) {
			this.events.emit("error", error instanceof Error ? error : new Error(String(error)));
		}
	}

	private handleControlMessage(controlMessage: ControlMessage): void {
		const localInitiationKeys = this.controller.handleControlMessage(controlMessage);

		if (localInitiationKeys) {
			this.localInitiationKeys = localInitiationKeys;
		}
	}

	close(): void {
		this.controller.events.removeAllListeners();
		this.controller.close();
		this.events.removeAllListeners();
	}

	private handleEnvelope(envelope: Envelope): void {
		if (!this.ratchetState) {
			if (!this.localInitiationKeys) {
				throw new Error("Cannot initialize ratchet as responder without local initiation keys");
			}

			this.ratchetState = RatchetState.initializeAsResponder(
				envelope,
				this.localKeys.publicKey,
				this.localInitiationKeys,
				this.remotePublicKey,
				this.options,
			);

			delete this.localInitiationKeys;
		}

		const data = this.ratchetState.decrypt(envelope);

		this.events.emit("message", data);
		this.events.emit("stateChanged");
	}
}

export const SessionCodec = Codec.Transform(SessionPropertiesCodec, {
	decode: (properties) => new Session(properties),
	encode: (session) => session.properties,
});
