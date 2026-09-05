import { Codec } from "bufferfy";
import { RSignatureCodec } from "../Keys/Codec";
import { ControlMessageBodyCodec } from "./BodyCodec";

export const VERSION = {
	V0: 0,
} as const;

export const ControlMessagePropertiesCodec = Codec.Object({
	version: Codec.UInt(8),
	body: ControlMessageBodyCodec,
	rSignature: RSignatureCodec,
});

export interface ControlMessageProperties extends Codec.Type<typeof ControlMessagePropertiesCodec> {}
