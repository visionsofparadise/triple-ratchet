import { Codec } from "bufferfy";
import { MlKemSeedCodec } from "./MlKemCodec";
import { X25519SecretKeyCodec } from "./X25519Codec";

export const RatchetKeysPropertiesCodec = Codec.Object({
	mlKemSeed: MlKemSeedCodec,
	dhSecretKey: X25519SecretKeyCodec,
});

export type RatchetKeysProperties = Codec.Type<typeof RatchetKeysPropertiesCodec>;
