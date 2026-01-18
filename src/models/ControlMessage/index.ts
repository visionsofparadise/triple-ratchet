import { Codec } from "bufferfy";
import { Keys } from "../Keys";
import type { RSignature } from "../Keys/Codec";
import type { ControlMessageBodyMap, ControlMessageBodyType } from "./BodyCodec";
import { ControlMessageCodec, type ControlMessageProperties, ControlMessagePropertiesCodec, VERSION } from "./Codec";

export namespace ControlMessage {
	export type Properties<T extends ControlMessageBodyType = ControlMessageBodyType> = Omit<ControlMessageProperties, "body"> & {
		body: ControlMessageBodyMap[T] & {
			type: T;
		};
	};

	export interface Cache {
		buffer?: Uint8Array;
		byteLength?: number;
		hash?: Uint8Array;
		publicKey?: Uint8Array;
	}
}

export class ControlMessage<T extends ControlMessageBodyType = ControlMessageBodyType> implements ControlMessage.Properties<T> {
	static create<T extends ControlMessageBodyType>(properties: Pick<ControlMessage.Properties<T>, "body">, keys: Keys): ControlMessage<T> {
		const defaultProperties: Omit<ControlMessage.Properties<T>, "rSignature"> = {
			version: VERSION.V0,
			body: properties.body,
		};

		const hash = ControlMessage.hash(defaultProperties);

		const rSignature = keys.rSign(hash);

		const controlMessage = new ControlMessage<T>(
			{
				...defaultProperties,
				rSignature,
			},
			{
				hash,
				publicKey: keys.publicKey,
			},
		);

		return controlMessage;
	}

	static hash(properties: Omit<ControlMessage.Properties, "rSignature">) {
		return Codec.Omit(ControlMessagePropertiesCodec, ["rSignature"]).encode(properties);
	}

	readonly version = VERSION.V0;
	readonly body: ControlMessageBodyMap[T];
	readonly rSignature: RSignature;

	constructor(
		properties: Pick<ControlMessage.Properties<T>, "body" | "rSignature">,
		public cache: ControlMessage.Cache = {},
	) {
		this.body = properties.body;
		this.rSignature = properties.rSignature;
	}

	get buffer(): Uint8Array {
		return this.cache.buffer ?? (this.cache.buffer = ControlMessageCodec.encode(this));
	}

	get byteLength(): number {
		return this.cache.byteLength ?? (this.cache.byteLength = ControlMessageCodec.byteLength(this));
	}

	get hash(): Uint8Array {
		return this.cache.hash ?? (this.cache.hash = ControlMessage.hash(this));
	}

	get properties(): ControlMessage.Properties<T> {
		const { version, body, rSignature } = this;

		return { version, body, rSignature };
	}

	get publicKey(): Uint8Array {
		return this.cache.publicKey ?? (this.cache.publicKey = Keys.recover(this.rSignature, this.hash));
	}
}
