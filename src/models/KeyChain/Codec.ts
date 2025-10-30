import { Codec } from "bufferfy";
import { KeyChain } from ".";
import { ChainKeyCodec } from "./ChainKeyCodec";

export const KeyChainCodec = Codec.Transform(
	Codec.Object({
		chainKey: Codec.Optional(ChainKeyCodec),
		messageNumber: Codec.VarInt(60),
	}),
	{
		decode: (properties) => new KeyChain(properties),
		encode: (keyChain) => ({
			chainKey: keyChain.chainKey,
			messageNumber: keyChain.messageNumber,
		}),
	}
);

export type KeyChainProperties = Codec.Type<typeof KeyChainCodec>;
