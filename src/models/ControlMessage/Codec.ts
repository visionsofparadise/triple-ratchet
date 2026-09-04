import { Codec } from "bufferfy";
import { RSignatureCodec } from "../Keys/Codec";
import { ControlMessageBodyCodec } from "./BodyCodec";
import { ControlMessage } from ".";

export const VERSION = {
	V0: 0,
} as const;

export const ControlMessagePropertiesCodec = Codec.Object({
	version: Codec.UInt(8),
	body: ControlMessageBodyCodec,
	rSignature: RSignatureCodec,
});

export interface ControlMessageProperties extends Codec.Type<typeof ControlMessagePropertiesCodec> {}

export const ControlMessageCodec = Codec.Transform(ControlMessagePropertiesCodec, {
	isValid: (value) => value instanceof ControlMessage,
	decode: (properties) => new ControlMessage(properties),
	encode: (controlMessage) => controlMessage.properties,
});
