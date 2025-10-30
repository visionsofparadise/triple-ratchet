import { Codec } from "bufferfy";
import { KeyIdCodec } from "../RatchetKeysItem/KeyIdCodec.js";
import { RootChainCodec } from "../RootChain/Codec.js";
import { MessageSecretCodec } from "./SecretCodec.js";

const SkippedKeyEntryCodec = Codec.Object({
	messageNumber: Codec.VarInt(60),
	secret: MessageSecretCodec,
	createdAt: Codec.VarInt(60),
});

const SkippedKeysCodec = Codec.Array(SkippedKeyEntryCodec);

export const RatchetStateItemValueCodec = Codec.Object({
	remoteKeyId: Codec.Optional(KeyIdCodec),
	rootChain: RootChainCodec,
	previousChainLength: Codec.VarInt(60),
	skippedKeys: SkippedKeysCodec,
	ratchetAt: Codec.VarInt(60),
});

export type RatchetStateItemValue = Codec.Type<typeof RatchetStateItemValueCodec>;
