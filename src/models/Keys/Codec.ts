import { Codec } from "bufferfy";
import { Keys } from ".";

export const SecretKeyCodec = Codec.Bytes(32);
export const PublicKeyCodec = Codec.Bytes(33);

export const SignatureCodec = Codec.Bytes(64);
export const RSignatureCodec = Codec.Object({
	recoveryBit: Codec.UInt(8),
	signature: SignatureCodec,
});

export type RSignature = Codec.Type<typeof RSignatureCodec>;

export const KeysPropertiesCodec = Codec.Object({
	secretKey: SecretKeyCodec,
});

export type KeysProperties = Codec.Type<typeof KeysPropertiesCodec>;

export const KeysCodec = Codec.Transform(KeysPropertiesCodec, {
	decode: (properties) => new Keys(properties),
	encode: (keys) => keys.properties,
});
