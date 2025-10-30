import { Codec } from "bufferfy";
import { RootChain } from ".";
import { KeyChainCodec } from "../KeyChain/Codec";
import { X25519PublicKeyCodec, X25519SecretKeyCodec } from "../RatchetKeysItem/X25519Codec";
import { RootKeyCodec } from "./KeyCodec";

export const RootChainProperties = Codec.Object({
	rootKey: RootKeyCodec,
	dhSecretKey: X25519SecretKeyCodec,
	remoteDhPublicKey: X25519PublicKeyCodec,
	sendingChain: KeyChainCodec,
	receivingChain: KeyChainCodec,
});

export interface RootChainProperties extends Codec.Type<typeof RootChainProperties> {}

export const RootChainCodec = Codec.Transform(RootChainProperties, {
	decode: (properties) => new RootChain(properties),
	encode: (rootChain) => ({
		rootKey: rootChain.rootKey,
		dhSecretKey: rootChain.dhSecretKey,
		remoteDhPublicKey: rootChain.remoteDhPublicKey,
		sendingChain: rootChain.sendingChain,
		receivingChain: rootChain.receivingChain,
	}),
});
