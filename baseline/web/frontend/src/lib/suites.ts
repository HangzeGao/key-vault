export type ServiceType = "AUTH_ONLY" | "ENCRYPT_ONLY" | "AUTH_ENCRYPT";

export const SYMMETRIC_SUITES = [
  { id: "AES_256_GCM", keyBytes: 32, serviceType: "AUTH_ENCRYPT", purpose: "encrypt_decrypt" },
  { id: "SM4_GCM", keyBytes: 16, serviceType: "AUTH_ENCRYPT", purpose: "encrypt_decrypt" },
  { id: "AES_256_CTR", keyBytes: 32, serviceType: "ENCRYPT_ONLY", purpose: "encrypt_decrypt" },
  { id: "SM4_CTR", keyBytes: 16, serviceType: "ENCRYPT_ONLY", purpose: "encrypt_decrypt" },
  { id: "AES_256_CMAC", keyBytes: 32, serviceType: "AUTH_ONLY", purpose: "authenticate_verify" },
  { id: "SM4_CMAC", keyBytes: 16, serviceType: "AUTH_ONLY", purpose: "authenticate_verify" },
] as const;

export const suitesForPurpose = (purpose: string) =>
  SYMMETRIC_SUITES.filter((suite) => suite.purpose === purpose);

export const suitesForService = (serviceType: ServiceType) =>
  SYMMETRIC_SUITES.filter((suite) => suite.serviceType === serviceType);

export const serviceTypeForSuite = (suiteID: string): ServiceType | undefined =>
  SYMMETRIC_SUITES.find((suite) => suite.id === suiteID)?.serviceType;

export const purposeForSuite = (suiteID: string): "encrypt_decrypt" | "authenticate_verify" =>
  serviceTypeForSuite(suiteID) === "AUTH_ONLY" ? "authenticate_verify" : "encrypt_decrypt";

export const suiteKeyBytes: Record<string, number> = Object.fromEntries(
  SYMMETRIC_SUITES.map((suite) => [suite.id, suite.keyBytes]),
);
