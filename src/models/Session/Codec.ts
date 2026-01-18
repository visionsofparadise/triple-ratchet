import { Codec } from "bufferfy";
import { Session } from ".";
import { KeysCodec, PublicKeyCodec } from "../Keys/Codec";
import { RatchetKeysCodec } from "../RatchetKeys/Codec";
import { RatchetStateCodec } from "../RatchetState/Codec";

export const SessionPropertiesCodec = Codec.Object({
	localKeys: KeysCodec,
	localInitiationKeys: Codec.Optional(RatchetKeysCodec),
	remotePublicKey: PublicKeyCodec,
	ratchetState: Codec.Optional(RatchetStateCodec),
});

export type SessionProperties = Codec.Type<typeof SessionPropertiesCodec>;

export const SessionCodec = Codec.Transform(SessionPropertiesCodec, {
	decode: (properties) => new Session(properties),
	encode: (session) => session.properties,
});
