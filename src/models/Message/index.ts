import { Codec } from "bufferfy";
import { MAGIC_BYTES } from "../../utilities/magicBytes";
import { type MessageProperties, MessagePropertiesCodec, VERSION } from "./Codec";
import type { ControlMessage } from "../ControlMessage";
import type { Envelope } from "../Envelope";

export namespace Message {
	export interface Properties extends MessageProperties {}
}

export class Message implements Message.Properties {
	readonly magicBytes = MAGIC_BYTES;
	readonly version = VERSION.V0;
	readonly body: ControlMessage | Envelope;

	constructor(properties: Pick<Message.Properties, "body">) {
		this.body = properties.body;
	}

	get buffer(): Uint8Array {
		return MessageCodec.encode(this);
	}

	get byteLength(): number {
		return MessageCodec.byteLength(this);
	}

	get properties(): Message.Properties {
		const { magicBytes, body } = this;

		return { magicBytes, body };
	}
}

export const MessageCodec = Codec.Transform(MessagePropertiesCodec, {
	isValid: (value) => value instanceof Message,
	decode: (properties) => new Message(properties),
	encode: (message) => message.properties,
});
