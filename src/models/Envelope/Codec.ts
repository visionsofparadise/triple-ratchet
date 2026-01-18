import { Codec } from "bufferfy";
import { Envelope } from ".";
import { CipherDataCodec } from "../CipherData/Codec";
import { RSignatureCodec } from "../Keys/Codec";
import { KeyIdCodec } from "../RatchetKeys/KeyIdCodec";
import { MlKemCipherTextCodec } from "../RatchetKeys/MlKemCodec";
import { X25519PublicKeyCodec } from "../RatchetKeys/X25519Codec";

export const EnvelopePropertiesCodec = Codec.Object({
	version: Codec.UInt(8),
	keyId: KeyIdCodec,
	dhPublicKey: X25519PublicKeyCodec,
	messageNumber: Codec.VarInt(60),
	previousChainLength: Codec.VarInt(60),
	kemCiphertext: Codec.Optional(MlKemCipherTextCodec),
	cipherData: CipherDataCodec,
	rSignature: RSignatureCodec,
});

export type EnvelopeProperties = Codec.Type<typeof EnvelopePropertiesCodec>;

export const EnvelopeCodec = Codec.Transform(EnvelopePropertiesCodec, {
	isValid: (value) => value instanceof Envelope,
	decode: (properties, buffer) => new Envelope(properties, { buffer, byteLength: buffer.byteLength }),
	encode: (envelope) => envelope.properties,
});
