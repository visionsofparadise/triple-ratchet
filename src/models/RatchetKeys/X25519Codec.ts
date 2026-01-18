import { Codec } from "bufferfy";

export const X25519PublicKeyCodec = Codec.Bytes(32);
export const X25519SecretKeyCodec = Codec.Bytes(32);
