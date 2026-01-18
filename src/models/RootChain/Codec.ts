import { Codec } from "bufferfy";
import { RootChain } from ".";
import { KeyChainCodec } from "../KeyChain/Codec";
import { X25519PublicKeyCodec, X25519SecretKeyCodec } from "../RatchetKeys/X25519Codec";
import { RootKeyCodec } from "./KeyCodec";

export const RootChainPropertiesCodec = Codec.Object({
	rootKey: RootKeyCodec,
	dhSecretKey: X25519SecretKeyCodec,
	remoteDhPublicKey: X25519PublicKeyCodec,
	sendingChain: KeyChainCodec,
	receivingChain: KeyChainCodec,
});

export type RootChainProperties = Codec.Type<typeof RootChainPropertiesCodec>;

export const RootChainCodec = Codec.Transform(RootChainPropertiesCodec, {
	decode: (properties) => new RootChain(properties),
	encode: (rootChain) => rootChain.properties,
});
