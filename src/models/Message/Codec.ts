import { Codec } from "bufferfy";
import { MAGIC_BYTES } from "../../utilities/magicBytes";
import { ControlMessageCodec } from "../ControlMessage";
import { EnvelopeCodec } from "../Envelope";

export const VERSION = {
	V0: 0,
} as const;

export const MessagePropertiesCodec = Codec.Object({
	magicBytes: Codec.Bytes(MAGIC_BYTES.byteLength),
	body: Codec.Union([ControlMessageCodec, EnvelopeCodec]),
});

export interface MessageProperties extends Codec.Type<typeof MessagePropertiesCodec> {}
