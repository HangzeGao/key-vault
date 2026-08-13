const BFF = "/ui/api/v1" as const;

const query = (path: string, params: Record<string, string | number | undefined>) => {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== "") search.set(key, String(value));
  });
  const suffix = search.toString();
  return suffix ? `${path}?${suffix}` : path;
};

export const apiPaths = {
  ccsds: {
    protectTC: `${BFF}/ccsds/tc:protect`,
    unprotectDownlink: `${BFF}/ccsds/downlink:unprotect`,
  },
  audit: {
    events: (params: Record<string, string | number | undefined> = {}) => query(`${BFF}/audit/events`, params),
    heads: `${BFF}/audit/chain/heads`,
    verify: (chain?: string) => query(`${BFF}/audit/chain/verify`, { chain }),
  },
  ops: {
    dbStatus: `${BFF}/ops/db/status`,
	ccsdsStatus: `${BFF}/ops/ccsds/status`,
  },
} as const;
