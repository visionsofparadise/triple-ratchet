import { Codec } from "bufferfy";
import type { Envelope } from "..";
import { createHash } from "../../../utilities/Hash";
import { EnvelopePropertiesCodec } from "../Codec";

export const hashEnvelope = (properties: Omit<Envelope.Properties, "rSignature">): Uint8Array => {
	return createHash(Codec.Omit(EnvelopePropertiesCodec, ["rSignature"]).encode(properties));
};
