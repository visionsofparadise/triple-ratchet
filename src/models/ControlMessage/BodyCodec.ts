import { Codec } from "bufferfy";
import { RatchetPublicKeysCodec } from "../RatchetKeys/Public";
import { TransactionIdCodec } from "../TransactionId/Codec";

export enum ControlMessageBodyType {
	GET_INITIATION_KEYS,
	INITIATION_KEYS,
}

const GetInitiationKeysBodyCodec = Codec.Object({
	type: Codec.Constant(ControlMessageBodyType.GET_INITIATION_KEYS),
	transactionId: TransactionIdCodec,
});

const InitiationKeysBodyCodec = Codec.Object({
	type: Codec.Constant(ControlMessageBodyType.INITIATION_KEYS),
	transactionId: TransactionIdCodec,
	initiationKeys: RatchetPublicKeysCodec,
});

export const ControlMessageBodyCodec = Codec.Union([GetInitiationKeysBodyCodec, InitiationKeysBodyCodec]);

type ControlMessageBody = Codec.Type<typeof ControlMessageBodyCodec>;

export type ControlMessageBodyMap = {
	[T in ControlMessageBody["type"]]: Extract<ControlMessageBody, { type: T }>;
};
