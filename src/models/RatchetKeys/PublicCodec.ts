import { Codec } from "bufferfy";
import { RatchetPublicKeys } from "./Public";
import { KeyIdCodec } from "./KeyIdCodec";
import { MlKemPublicKeyCodec } from "./MlKemCodec";
import { X25519PublicKeyCodec } from "./X25519Codec";

export const RatchetPublicKeysPropertiesCodec = Codec.Object({
	keyId: KeyIdCodec,
	encryptionKey: MlKemPublicKeyCodec,
	dhPublicKey: X25519PublicKeyCodec,
});

export type RatchetPublicKeysProperties = Codec.Type<typeof RatchetPublicKeysPropertiesCodec>;

export const RatchetPublicKeysCodec = Codec.Transform(RatchetPublicKeysPropertiesCodec, {
	decode: (properties) => new RatchetPublicKeys(properties),
	encode: (ratchetPublicKeys) => ratchetPublicKeys.properties,
});

// Legacy type alias
export type RatchetKeysPublic = RatchetPublicKeysProperties;
