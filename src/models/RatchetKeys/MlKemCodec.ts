import { Codec } from "bufferfy";

export const MlKemSeedCodec = Codec.Bytes(64);
export const MlKemPublicKeyCodec = Codec.Bytes(1568);
export const MlKemCipherTextCodec = Codec.Bytes(1568);
