/**
 * Control message types for the ratchet protocol
 */

export enum MessageType {
	/**
	 * Request initiation keys from peer
	 */
	REQUEST_INITIATION_KEYS = 0x01,

	/**
	 * Response containing initiation keys
	 */
	INITIATION_KEYS_RESPONSE = 0x02,

	/**
	 * Encrypted data message (Envelope)
	 */
	DATA = 0x03,
}

export type MessageBody =
	| {
			type: MessageType.REQUEST_INITIATION_KEYS;
			nodeId: Uint8Array; // Requester's nodeId
	  }
	| {
			type: MessageType.INITIATION_KEYS_RESPONSE;
			publicKeys: Uint8Array; // Serialized RatchetKeysPublic
			signature: Uint8Array; // Recoverable signature
	  }
	| {
			type: MessageType.DATA;
			envelope: Uint8Array; // Serialized Envelope
	  };

export interface Message {
	type: MessageType;
	body: MessageBody;
}
