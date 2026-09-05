import { Codec } from "bufferfy";

export const NonceCodec = Codec.Bytes(24);

export const CipherDataPropertiesCodec = Codec.Object({
	nonce: NonceCodec,
	data: Codec.Bytes(),
});

export type CipherDataProperties = Codec.Type<typeof CipherDataPropertiesCodec>;
