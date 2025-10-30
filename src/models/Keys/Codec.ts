import { Codec } from "bufferfy";
import { ShortHashCodec } from "../../utilities/Hash";

export const SecretKeyCodec = Codec.Bytes(32);
export const PublicKeyCodec = Codec.Bytes(33);
export const NodeIdCodec = ShortHashCodec;

export const SignatureCodec = Codec.Bytes(64);
export const RSignatureCodec = Codec.Object({
	recoveryBit: Codec.UInt(8),
	signature: SignatureCodec,
});

export type RSignature = Codec.Type<typeof RSignatureCodec>;
