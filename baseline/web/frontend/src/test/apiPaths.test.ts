import { describe, expect, it } from "vitest";
import { apiPaths } from "../lib/apiPaths";

describe("current mission BFF contract", () => {
  it("exposes only the two CCSDS data-plane operations", () => {
    expect(apiPaths.ccsds.protectTC).toBe("/ui/api/v1/ccsds/tc:protect");
	expect(apiPaths.ops.ccsdsStatus).toBe("/ui/api/v1/ops/ccsds/status");
    expect(apiPaths.ccsds.unprotectDownlink).toBe("/ui/api/v1/ccsds/downlink:unprotect");
  });

  it("builds audit query strings without empty values", () => {
    expect(apiPaths.audit.events({ limit: 50, action: "root prepare", target: undefined })).toBe("/ui/api/v1/audit/events?limit=50&action=root+prepare");
  });
});
