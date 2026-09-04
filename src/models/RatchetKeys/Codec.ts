import { Codec } from "bufferfy";
import { MlKemSeedCodec } from "./MlKemCodec";
import { X25519SecretKeyCodec } from "./X25519Codec";
import { RatchetKeys } from ".";

export const RatchetKeysPropertiesCodec = Codec.Object({
	mlKemSeed: MlKemSeedCodec,
	dhSecretKey: X25519SecretKeyCodec,
});

export type RatchetKeysProperties = Codec.Type<typeof RatchetKeysPropertiesCodec>;

export const RatchetKeysCodec = Codec.Transform(RatchetKeysPropertiesCodec, {
	isValid: (value) => value instanceof RatchetKeys,
	decode: (properties) => new RatchetKeys(properties),
	encode: (ratchetKeys) => ratchetKeys.properties,
});
