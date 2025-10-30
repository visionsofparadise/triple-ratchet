/**
 * @xkore/ratchet - Transport-agnostic bounded triple ratchet for encrypted P2P communication
 */

// Main API
export { Session, type SessionOptions, type SessionEvents } from "./models/Session/index.js";

// Crypto primitives
export { Keys } from "./models/Keys/index.js";
export { RatchetKeysItem } from "./models/RatchetKeysItem/index.js";
export { RatchetStateItem } from "./models/RatchetStateItem/index.js";
export { CipherData } from "./models/CipherData/index.js";

// Key chain components
export { RootChain } from "./models/RootChain/index.js";
export { KeyChain } from "./models/KeyChain/index.js";

// Wire format
export { Envelope } from "./models/Envelope/index.js";

// Error
export { RatchetError } from "./models/Error/index.js";

// Control protocol (for advanced use)
export { MessageType, type MessageBody, type Message } from "./models/Message/index.js";

// Utilities
export { computeRatchetId } from "./utilities/computeRatchetId.js";
export { createHash, createShortHash, createChecksum } from "./utilities/Hash.js";
