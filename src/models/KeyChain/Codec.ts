import { Codec } from "bufferfy";
import { ChainKeyCodec } from "./ChainKeyCodec";
import { KeyChain } from ".";

export const KeyChainPropertiesCodec = Codec.Object({
	chainKey: Codec.Optional(ChainKeyCodec),
	messageNumber: Codec.VarInt(60),
});

export type KeyChainProperties = Codec.Type<typeof KeyChainPropertiesCodec>;

export const KeyChainCodec = Codec.Transform(KeyChainPropertiesCodec, {
	decode: (properties) => new KeyChain(properties),
	encode: (keyChain) => keyChain.properties,
});
