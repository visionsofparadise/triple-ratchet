import { Codec } from "bufferfy";
import { KeysCodec } from "../Keys";
import { PublicKeyCodec } from "../Keys/Codec";
import { RatchetKeysCodec } from "../RatchetKeys";
import { RatchetStateCodec } from "../RatchetState";

export const SessionPropertiesCodec = Codec.Object({
	localKeys: KeysCodec,
	localInitiationKeys: Codec.Optional(RatchetKeysCodec),
	remotePublicKey: PublicKeyCodec,
	ratchetState: Codec.Optional(RatchetStateCodec),
});

export type SessionProperties = Codec.Type<typeof SessionPropertiesCodec>;
