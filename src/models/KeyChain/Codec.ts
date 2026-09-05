import { Codec } from "bufferfy";
import { ChainKeyCodec } from "./ChainKeyCodec";

export const KeyChainPropertiesCodec = Codec.Object({
	chainKey: Codec.Optional(ChainKeyCodec),
	messageNumber: Codec.VarInt(60),
});

export type KeyChainProperties = Codec.Type<typeof KeyChainPropertiesCodec>;
