import { Codec } from "bufferfy";
import { KeyIdCodec } from "./KeyIdCodec";
import { MlKemPublicKeyCodec } from "./MlKemCodec";
import { X25519PublicKeyCodec } from "./X25519Codec";

export const RatchetKeysPublicCodec = Codec.Object({
	keyId: KeyIdCodec,
	encryptionKey: MlKemPublicKeyCodec,
	dhPublicKey: X25519PublicKeyCodec,
});

export type RatchetKeysPublic = Codec.Type<typeof RatchetKeysPublicCodec>;
