import { Codec } from "bufferfy";
import { HashCodec } from "../../utilities/Hash";
import { KeyIdCodec } from "../RatchetKeys/KeyIdCodec";
import { RootChainCodec } from "../RootChain";
import { MessageSecretCodec } from "./SecretCodec";

const SkippedKeyEntryCodec = Codec.Object({
	messageNumber: Codec.VarInt(60),
	secret: MessageSecretCodec,
	createdAt: Codec.VarInt(60),
});

const SkippedKeysCodec = Codec.Array(SkippedKeyEntryCodec);

export const RatchetStatePropertiesCodec = Codec.Object({
	ratchetId: HashCodec,
	remoteKeyId: Codec.Optional(KeyIdCodec),
	rootChain: RootChainCodec,
	previousChainLength: Codec.VarInt(60),
	skippedKeys: SkippedKeysCodec,
	ratchetAt: Codec.VarInt(60),
});

export type RatchetStateProperties = Codec.Type<typeof RatchetStatePropertiesCodec>;
