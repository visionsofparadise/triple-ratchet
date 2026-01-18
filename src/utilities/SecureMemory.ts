export const secureZero = (buffer: Uint8Array): void => {
	crypto.getRandomValues(buffer);
	buffer.fill(0);
};
