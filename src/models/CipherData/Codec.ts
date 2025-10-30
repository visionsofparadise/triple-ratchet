import { Codec } from "bufferfy";
import { CipherData } from ".";

export const NonceCodec = Codec.Bytes(24);

export const CipherDataPropertiesCodec = Codec.Object({
	nonce: NonceCodec,
	data: Codec.Bytes(),
});

export type CipherDataProperties = Codec.Type<typeof CipherDataPropertiesCodec>;

export const CipherDataCodec = Codec.Transform(CipherDataPropertiesCodec, {
	isValid: (value) => value instanceof CipherData,
	decode: (properties) => new CipherData(properties),
	encode: (cipherData) => cipherData.properties,
});
