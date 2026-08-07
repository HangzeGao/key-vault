import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { apiPaths } from "../lib/apiPaths";
import { useAuth } from "../lib/store";
import { PageContainer } from "../components";
import { EncryptPanel } from "../components/crypto/EncryptPanel";
import { DecryptPanel } from "../components/crypto/DecryptPanel";
import { EnvelopeInspector } from "../components/crypto/EnvelopeInspector";
import { AuthenticatePanel } from "../components/crypto/AuthenticatePanel";
import type { KeyDTO, EnvelopeFormatDescription, TenantEnvelopeConfig } from "../lib/types";

function envelopeFormatOptions(formats: EnvelopeFormatDescription[], config?: TenantEnvelopeConfig): string[] {
  const registered = new Set(formats.map((format) => format.format_id));
  const validProfiles = (config?.profiles ?? [])
    .filter((profile) => registered.has(profile.adapter))
    .map((profile) => profile.format_id);
  return [
    ...new Set([
      ...formats.map((format) => format.format_id),
      ...(config?.allowed_formats ?? []).filter((format) => registered.has(format) || validProfiles.includes(format)),
      ...validProfiles,
    ]),
  ];
}

export function CryptoPage() {
  const { tenantId } = useAuth();
  const [decryptSeed, setDecryptSeed] = useState<{ envelope: string; aad: string; format: string; version: number }>({
    envelope: "",
    aad: "",
    format: "",
    version: 0,
  });

  const { data: keysData } = useQuery({
    queryKey: ["keys", tenantId],
    queryFn: () => api.get<{ keys: KeyDTO[] }>(apiPaths.keys),
  });
  const keys = (keysData?.keys ?? []).filter((k) => k.status === "ACTIVE");
  const encryptionKeys = keys.filter((key) => key.service_type === "ENCRYPT_ONLY" || key.service_type === "AUTH_ENCRYPT");
  const authenticationKeys = keys.filter((key) => key.service_type === "AUTH_ONLY");

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
  const formatOptions = useMemo(() => envelopeFormatOptions(formats, envelopeConfig), [formats, envelopeConfig]);

  const handleSendToDecrypt = (envelope: string, aad: string, format: string) => {
    setDecryptSeed((prev) => ({ envelope, aad, format, version: prev.version + 1 }));
  };

  return (
    <PageContainer>
      <div className="page-header">
        <div>
          <h1 className="section-title">Crypto Sandbox</h1>
          <p className="section-subtitle">AUTH_ONLY → CMAC · ENCRYPT_ONLY → CTR · AUTH_ENCRYPT → GCM</p>
        </div>
      </div>

      <div className="grid-2 page-section">
        <EncryptPanel
          keys={encryptionKeys}
          formatOptions={formatOptions}
          onSendToDecrypt={handleSendToDecrypt}
        />
        <DecryptPanel
          formatOptions={formatOptions}
          seedEnvelope={decryptSeed.envelope}
          seedAAD={decryptSeed.aad}
          seedFormat={decryptSeed.format}
          seedVersion={decryptSeed.version}
        />
      </div>

      <div className="page-section">
        <AuthenticatePanel keys={authenticationKeys} />
      </div>

      <EnvelopeInspector
        formatOptions={formatOptions}
      />
    </PageContainer>
  );
}
