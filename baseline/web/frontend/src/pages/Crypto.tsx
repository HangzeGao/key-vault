import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { useAuth } from "../lib/store";
import { PageContainer } from "../components";
import { EncryptPanel } from "../components/crypto/EncryptPanel";
import { DecryptPanel } from "../components/crypto/DecryptPanel";
import { EnvelopeInspector } from "../components/crypto/EnvelopeInspector";
import type { KeyDTO, EnvelopeFormatDescription, TenantEnvelopeConfig } from "../lib/types";

export function CryptoPage() {
  const { tenantId } = useAuth();
  const [decryptSeed, setDecryptSeed] = useState<{ ciphertext: string; aad: string; format: string; version: number }>({
    ciphertext: "",
    aad: "",
    format: "",
    version: 0,
  });

  const { data: keysData } = useQuery({
    queryKey: ["keys", tenantId],
    queryFn: () => api.get<{ keys: KeyDTO[] }>(apiPaths.keys),
  });
  const keys = (keysData?.keys ?? []).filter((k) => k.status === "ACTIVE");

  const { data: formatsData } = useQuery({
    queryKey: ["envelope-formats"],
    queryFn: () => api.get<{ formats: EnvelopeFormatDescription[] }>(apiPaths.envelopeFormats),
  });
  const formats = formatsData?.formats ?? [];

  const { data: envelopeConfig } = useQuery({
    queryKey: ["envelope-config", tenantId],
    queryFn: () => api.get<TenantEnvelopeConfig>(apiPaths.tenantEnvelopeConfig(tenantId)),
    enabled: !!tenantId,
    retry: false,
  });
  const formatOptions = useMemo(() => [
    ...new Set([
      ...formats.map((f) => f.format_id),
      ...(envelopeConfig?.allowed_formats ?? []),
      ...(envelopeConfig?.profiles ?? []).map((p) => p.format_id),
    ]),
  ], [formats, envelopeConfig]);

  const handleSendToDecrypt = (ciphertext: string, aad: string, format: string) => {
    setDecryptSeed((prev) => ({ ciphertext, aad, format, version: prev.version + 1 }));
  };

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Crypto Sandbox</h1>
          <p className="section-subtitle">Data-plane encrypt and decrypt workflows with server-side key boundaries and envelope inspection</p>
        </div>
      </div>

      <div className="grid-2 page-section">
        <EncryptPanel
          keys={keys}
          formatOptions={formatOptions}
          onSendToDecrypt={handleSendToDecrypt}
        />
        <DecryptPanel
          formatOptions={formatOptions}
          seedCiphertext={decryptSeed.ciphertext}
          seedAAD={decryptSeed.aad}
          seedFormat={decryptSeed.format}
          seedVersion={decryptSeed.version}
        />
      </div>

      <EnvelopeInspector
        formatOptions={formatOptions}
      />
    </PageContainer>
  );
}
