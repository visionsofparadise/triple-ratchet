import { Codec } from "bufferfy";
import { MessageType } from "./index.js";

const NodeIdCodec = Codec.Bytes(20);

const RequestInitiationKeysBodyCodec = Codec.Object({
	nodeId: NodeIdCodec,
});

const InitiationKeysResponseBodyCodec = Codec.Object({
	publicKeys: Codec.Bytes(), // Variable length RatchetKeysPublic
	signature: Codec.Bytes(65), // Recoverable signature (r:32, s:32, v:1)
});

const DataBodyCodec = Codec.Object({
	envelope: Codec.Bytes(), // Variable length Envelope
});

/**
 * Message codec with discriminated union by type
 */
export const MessageCodec = Codec.Transform(
	Codec.Object({
		type: Codec.UInt(8),
		bodyBytes: Codec.Bytes(),
	}),
	{
		decode: ({ type, bodyBytes }) => {
			switch (type) {
				case MessageType.REQUEST_INITIATION_KEYS:
					return {
						type,
						body: {
							type: MessageType.REQUEST_INITIATION_KEYS as const,
							...RequestInitiationKeysBodyCodec.decode(bodyBytes),
						},
					};

				case MessageType.INITIATION_KEYS_RESPONSE:
					return {
						type,
						body: {
							type: MessageType.INITIATION_KEYS_RESPONSE as const,
							...InitiationKeysResponseBodyCodec.decode(bodyBytes),
						},
					};

				case MessageType.DATA:
					return {
						type,
						body: {
							type: MessageType.DATA as const,
							...DataBodyCodec.decode(bodyBytes),
						},
					};

				default:
					throw new Error(`Unknown message type: ${type}`);
			}
		},
		encode: (message) => {
			let bodyBytes: Uint8Array;

			switch (message.type) {
				case MessageType.REQUEST_INITIATION_KEYS:
					bodyBytes = RequestInitiationKeysBodyCodec.encode({
						nodeId: message.body.nodeId,
					});
					break;

				case MessageType.INITIATION_KEYS_RESPONSE:
					bodyBytes = InitiationKeysResponseBodyCodec.encode({
						publicKeys: message.body.publicKeys,
						signature: message.body.signature,
					});
					break;

				case MessageType.DATA:
					bodyBytes = DataBodyCodec.encode({
						envelope: message.body.envelope,
					});
					break;

				default:
					throw new Error(`Unknown message type: ${(message as any).type}`);
			}

			return {
				type: message.type,
				bodyBytes,
			};
		},
	}
);

export type MessageWire = Codec.Type<typeof MessageCodec>;
