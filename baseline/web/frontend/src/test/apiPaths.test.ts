import { describe, expect, it } from "vitest";
import { apiPaths } from "../lib/apiPaths";

describe("BFF route contract", () => {
  it("encodes resource IDs and uses implementation route names", () => {
    expect(apiPaths.key("a/b")).toBe("/ui/api/v1/keys/a%2Fb");
    expect(apiPaths.keyAction("a/b", "archive")).toBe("/ui/api/v1/keys/a%2Fb/archive");
    expect(apiPaths.ops.retryJob("job/1")).toBe("/ui/api/v1/ops/lifecycle/jobs/job%2F1/retry");
    expect(apiPaths.ops.replayOutbox("event 1")).toBe("/ui/api/v1/ops/outbox/event%201/replay");
  });
  it("builds query strings without manual concatenation", () => {
    expect(apiPaths.audit.events({ limit: 50, action: "key rotate", target: undefined })).toBe("/ui/api/v1/audit/events?limit=50&action=key+rotate");
    expect(apiPaths.keysList({ include_archived: true })).toBe("/ui/api/v1/keys?include_archived=true");
  });
});
