import { Codec } from "bufferfy";

export const TransactionIdCodec = Codec.Bytes(6);

export const createTransactionId = () => crypto.getRandomValues(new Uint8Array(TransactionIdCodec.byteLength()));
