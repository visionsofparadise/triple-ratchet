import { Codec } from "bufferfy";
import { RatchetPublicKeysCodec } from "../RatchetKeys/PublicCodec";
import { TransactionIdCodec } from "../TransactionId/Codec";

export enum ControlMessageBodyType {
	GET_INITIATION_KEYS,
	INITIATION_KEYS,
}

export const GetInitiationKeysBodyCodec = Codec.Object({
	type: Codec.Constant(ControlMessageBodyType.GET_INITIATION_KEYS),
	transactionId: TransactionIdCodec,
});

export interface GetInitiationKeysBody extends Codec.Type<typeof GetInitiationKeysBodyCodec> {}

export const InitiationKeysBodyCodec = Codec.Object({
	type: Codec.Constant(ControlMessageBodyType.INITIATION_KEYS),
	transactionId: TransactionIdCodec,
	initiationKeys: RatchetPublicKeysCodec,
});

export interface InitiationKeysBody extends Codec.Type<typeof InitiationKeysBodyCodec> {}

export const ControlMessageBodyCodec = Codec.Union([GetInitiationKeysBodyCodec, InitiationKeysBodyCodec]);

export type ControlMessageBody = Codec.Type<typeof ControlMessageBodyCodec>;

export type ControlMessageBodyMap = {
	[T in ControlMessageBody["type"]]: Extract<ControlMessageBody, { type: T }>;
};
