# @xkore/triple-ratchet

Transport-agnostic bounded triple ratchet for quantum-resistant encrypted P2P communication.

## Overview

**@xkore/triple-ratchet** provides end-to-end encrypted sessions between peers using a bounded triple ratchet protocol combining:

- **ML-KEM-1024** (NIST FIPS 203) - Quantum-resistant key encapsulation
- **X25519** - Classical ECDH for defense-in-depth
- **XChaCha20-Poly1305** - Authenticated encryption
- **Bounded rotation** - Enforced message/time limits to prevent stale quantum-resistant keys

Inspired by Signal's SPQR protocol, adapted for P2P environments where communication can be one-sided.

## Features

- ✅ **Transport-agnostic** - No I/O, no network, pure crypto
- ✅ **Event-based API** - Emit `send` events, handle `receive` calls
- ✅ **Out-of-band key exchange** - User controls key distribution
- ✅ **Automatic ratcheting** - Forward & backward secrecy
- ✅ **Bounded rotation** - Time & message-based ML-KEM rotation
- ✅ **Out-of-order handling** - Skipped message keys (up to 1000 gap)
- ✅ **Serializable state** - Persist sessions with `getState()`
- ✅ **Browser compatible** - No Node.js dependencies

## Installation

```bash
npm install @xkore/triple-ratchet
```

## Quick Start

```typescript
import { Session, Keys, RatchetKeys } from "@xkore/triple-ratchet";

// Setup local keys
const localKeys = new Keys();
const localInitiationKeys = new RatchetKeys();

// Get remote peer's public initiation keys (out-of-band exchange)
const remoteInitiationKeys = remoteInitiationKeysFromSomewhere;

// Create session
const session = new Session({
	localKeys,
	localInitiationKeys,
	remoteNodeId: remoteKeys.nodeId,
	remoteInitiationKeys,
});

// Handle outgoing buffers
session.on("send", (buffer) => {
	myTransport.send(remoteAddress, buffer);
});

// Handle incoming decrypted messages
session.on("message", (data) => {
	console.log("Received:", data);
});

// Handle state changes (for persistence)
session.on("stateChanged", () => {
	db.put(remoteNodeId, session.getState());
});

// Send encrypted data
await session.send(new TextEncoder().encode("hello"));

// Receive from transport
myTransport.on("message", (buffer) => {
	session.receive(buffer);
});
```

After initial key exchange, the session handles all cryptographic state updates automatically. The `stateChanged` event fires after each `send()` or `receive()` so you can persist the updated state.

## Key Exchange

The initiator must fetch the responder's initiation keys before the first message. This is a one-time, one-way exchange—once the session is established, key rotation happens automatically via the ratchet protocol.

```typescript
import { RatchetPublicKeys } from "@xkore/triple-ratchet";

// Publish your keys (responder)
app.get("/initiation-keys", (req, res) => {
	res.json(localInitiationKeys.publicKeys.toJson());
});

// Fetch remote peer's keys (initiator)
const response = await fetch(`https://peer.example.com/initiation-keys`);
const remoteKeys = RatchetPublicKeys.fromJson(await response.json());

const session = new Session({
	localKeys,
	localInitiationKeys,
	remotePublicKey,
	remoteInitiationKeys: remoteKeys,
});
```

## Session Persistence

Sessions can be serialized and restored using either JSON or binary formats:

### Using JSON

```typescript
import { RatchetState } from "@xkore/triple-ratchet";

// Save state as JSON
session.events.on("stateChanged", async () => {
	const state = session.ratchetState;

	if (state) {
		await db.put(remoteNodeId, JSON.stringify(state.toJson()));
	}
});

// Restore from JSON
const savedJson = await db.get(remoteNodeId);
const ratchetState = savedJson ? RatchetState.fromJson(JSON.parse(savedJson)) : undefined;

const session = new Session({ localKeys, localInitiationKeys, remotePublicKey, ratchetState });
```

### Using Binary

```typescript
// Save state as binary (more compact)
session.events.on("stateChanged", async () => {
	const state = session.ratchetState;

	if (state) {
		await db.put(remoteNodeId, state.buffer);
	}
});

// Restore from binary
const savedBuffer = await db.get(remoteNodeId);
const ratchetState = savedBuffer ? RatchetState.fromBuffer(savedBuffer) : undefined;

const session = new Session({ localKeys, localInitiationKeys, remotePublicKey, ratchetState });
```

## Transport Integration

### WebSocket Example

```typescript
const ws = new WebSocket("wss://peer.example.com");

session.events.on("send", (buffer) => {
	ws.send(buffer);
});

ws.onmessage = (event) => {
	session.receive(new Uint8Array(event.data));
};

// Send a message
await session.send(new TextEncoder().encode("Hello over WebSocket!"));
```

### UDP Example

```typescript
import dgram from "dgram";

const socket = dgram.createSocket("udp4");

session.events.on("send", (buffer) => {
	socket.send(buffer, remotePort, remoteHost);
});

socket.on("message", (buffer) => {
	session.receive(buffer);
});

// Send a message
await session.send(new TextEncoder().encode("Hello over UDP!"));
```

## Security Properties

- **Forward secrecy**: Compromised state doesn't reveal past messages
- **Backward secrecy**: Compromised state doesn't reveal future messages after next ratchet
- **Post-quantum security**: ML-KEM-1024 protects against quantum computers
- **Bounded rotation**: Keys rotate every 100 messages or 1 hour (configurable)
- **Out-of-order tolerance**: Up to 1000 message gap before rejection (DoS protection)

## Configuration

Session accepts optional configuration for ratchet bounds and limits:

```typescript
const session = new Session(
	{
		localKeys,
		localInitiationKeys,
		remotePublicKey,
	},
	{
		// ML-KEM rotation triggers
		messageBound: 100, // Rotate after 100 messages (default)
		timeBound: 3600000, // Rotate after 1 hour in ms (default)

		// Out-of-order message handling
		maxMessageSkip: 1000, // Max gap before rejection (default)
		maxStoredSkippedKeys: 2000, // Max stored skipped keys (default)
		skippedKeyMaxAge: 86400000, // Prune skipped keys after 24h (default)
	},
);
```

## API Reference

### Session

```typescript
class Session {
  constructor(options: SessionOptions)

  send(data: Uint8Array): Promise<void>
  receive(buffer: Uint8Array): void
  getState(): RatchetState | undefined
  setRemoteInitiationKeys(keys: RatchetPublicKeys): void

  // Events
  on('send', (buffer: Uint8Array) => void)
  on('message', (data: Uint8Array) => void)
  on('stateChanged', () => void)
  on('error', (error: Error) => void)
}
```

### Keys

```typescript
class Keys {
	constructor(properties?: { secretKey?: Uint8Array });

	readonly secretKey: Uint8Array;
	readonly publicKey: Uint8Array;
	readonly nodeId: Uint8Array;

	rSign(message: Uint8Array): RSignature;
	static recover(signature: RSignature, message: Uint8Array): Uint8Array;
}
```

### RatchetKeys

```typescript
class RatchetKeys {
	constructor(properties?: { dhSecretKey?: Uint8Array; mlKemSeed?: Uint8Array });

	readonly keyId: Uint8Array;
	readonly encryptionKey: Uint8Array;
	readonly decryptionKey: Uint8Array;
	readonly dhPublicKey: Uint8Array;

	get publicKeys(): RatchetPublicKeys;
	toPublicBuffer(): Uint8Array;
	static fromPublicBuffer(buffer: Uint8Array): RatchetPublicKeys;
}
```

## Architecture

```
Session (event-based communication)
  ├─ Keys (secp256k1 identity)
  ├─ RatchetKeys (ML-KEM-1024 + X25519 initiation keys)
  └─ RatchetState (per-peer triple ratchet state)
      ├─ RootChain (root key + DH ratchet)
      │   ├─ KeyChain (symmetric sending chain)
      │   └─ KeyChain (symmetric receiving chain)
      └─ Envelope (wire format with XChaCha20-Poly1305)
```

## Comparison to Signal Protocol

| Feature            | Signal             | @xkore/triple-ratchet |
| ------------------ | ------------------ | --------------------- |
| Quantum resistance | SPQR (optional)    | ML-KEM-1024 (always)  |
| Transport          | Centralized server | Any transport         |
| Key exchange       | X3DH               | Out-of-band           |
| Rotation bounds    | None               | Enforced (100 msg/1h) |
| Use case           | Mobile messaging   | P2P applications      |

## License

MIT

## Credits

Built with [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum), [@noble/curves](https://github.com/paulmillr/noble-curves), and [@noble/ciphers](https://github.com/paulmillr/noble-ciphers).

Inspired by [Signal's SPQR protocol](https://signal.org/docs/specifications/pqxdh/).
