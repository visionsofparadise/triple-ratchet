import { Codec } from "bufferfy";
import { Message } from ".";
import { MAGIC_BYTES } from "../../utilities/magicBytes";
import { ControlMessageCodec } from "../ControlMessage/Codec";
import { EnvelopeCodec } from "../Envelope/Codec";

export const VERSION = {
	V0: 0,
} as const;

export const MessagePropertiesCodec = Codec.Object({
	magicBytes: Codec.Bytes(MAGIC_BYTES.byteLength),
	body: Codec.Union([ControlMessageCodec, EnvelopeCodec]),
});

export interface MessageProperties extends Codec.Type<typeof MessagePropertiesCodec> {}

export const MessageCodec = Codec.Transform(MessagePropertiesCodec, {
	isValid: (value) => value instanceof Message,
	decode: (properties) => new Message(properties),
	encode: (message) => message.properties,
});
