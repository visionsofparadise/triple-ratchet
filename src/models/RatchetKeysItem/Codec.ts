import { Codec } from "bufferfy";
import { MlKemSeedCodec } from "./MlKemCodec.js";
import { X25519SecretKeyCodec } from "./X25519Codec.js";

export const RatchetKeysItemValueCodec = Codec.Object({
	mlKemSeed: MlKemSeedCodec,
	dhSecretKey: X25519SecretKeyCodec,
});

export type RatchetKeysItemValue = Codec.Type<typeof RatchetKeysItemValueCodec>;
