/**
 * Make certain properties required, leave others optional
 */
export type RequiredProperties<T, K extends keyof T> = Required<Pick<T, K>> & Partial<Omit<T, K>>;
