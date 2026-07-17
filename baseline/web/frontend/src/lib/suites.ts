export const SYMMETRIC_SUITES = [
  { id: "AES_256_GCM", keyBytes: 32 },
  { id: "SM4_GCM", keyBytes: 16 },
  { id: "AES_256_ECB", keyBytes: 32 },
  { id: "SM4_ECB", keyBytes: 16 },
] as const;

export const suiteKeyBytes: Record<string, number> = Object.fromEntries(
  SYMMETRIC_SUITES.map((suite) => [suite.id, suite.keyBytes]),
);
