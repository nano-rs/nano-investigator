import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  INGESTION_TOOLS,
  INGESTION_READ_TOOLS,
  handleIngestionTool,
} from "./ingestion.js";
import { NanosiemClient } from "@nano-rs/investigator-core";
const call = (name: string, args: Record<string, unknown>) => handleIngestionTool(name, args, new NanosiemClient({ apiUrl: process.env.NANOSIEM_API_URL!, apiKey: process.env.NANOSIEM_API_KEY! }));
const source = "lsrc_00000000000000000000000001";
const revision = "2026-10-17T11:00:00Z";
const draft = {
  id: source,
  name: "Fixture",
  updated_at: revision,
  parser_vrl: ".message = string!(.message)",
  extension_vrl: ".severity_id = 1",
  extension_enabled: true,
};
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status });
const data = (value: Awaited<ReturnType<typeof call>>) =>
  JSON.parse(value.content[0].text);
beforeEach(() => {
  vi.stubEnv("NANOSIEM_API_URL", "https://workspace.test");
  vi.stubEnv("NANOSIEM_API_KEY", "fixture-key");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});
const tools = [
  [
    "create_pipeline",
    "log_sources:create",
    "/api/log-sources",
    { name: "Fixture", source_type: "http", parser_vrl: "." },
  ],
  [
    "update_pipeline_draft",
    "log_sources:edit",
    `/api/log-sources/${source}`,
    { source_id: source, expected_updated_at: revision, parser_vrl: "." },
  ],
  [
    "preview_pipeline",
    "log_sources:view",
    `/api/log-sources/${source}/pipe-preview`,
    {
      source_id: source,
      expected_updated_at: revision,
      events: [{ message: "hello" }],
    },
  ],
  [
    "review_pipeline_release",
    "log_sources:view",
    "/api/log-sources/validate-vrl",
    { source_id: source, expected_updated_at: revision },
  ],
  [
    "rollback_pipeline_release",
    "log_sources:deploy",
    `/api/log-sources/${source}/versions/7/revert`,
    { source_id: source, version_id: 7, user_confirmed: true },
  ],
] as const;
describe("pipeline authoring", () => {
  it.each(tools)(
    "%s uses fixed endpoint, method and scope, and remains outside Locked",
    async (name, scope, endpoint, args) => {
      const fetcher = vi.fn(async (url: string) =>
        json(
          new URL(url).pathname.endsWith("draft-status")
            ? draft
            : url.endsWith("validate-vrl")
              ? { valid: true }
              : { id: source },
        ),
      );
      vi.stubGlobal("fetch", fetcher);
      expect((await call(name, args)).isError).not.toBe(true);
      const request = fetcher.mock.calls.find(
        ([url]) => url === `https://workspace.test${endpoint}`,
      )!;
      expect(request).toBeDefined();
      expect((request as unknown as [string, RequestInit])[1].method).toBe(
        name === "update_pipeline_draft" ? "PUT" : "POST",
      );
      const definition = INGESTION_TOOLS.find((tool) => tool.name === name)!;
      expect(definition.description).toMatch(/^WRITE:/);
      expect(
        definition._meta["io.nano/permission-requirements"].alternatives[0]
          .allOf,
      ).toContain(scope);
      expect(INGESTION_READ_TOOLS).not.toContain(name);
      if (name === "create_pipeline")
        expect(
          JSON.parse(
            (request as unknown as [string, RequestInit])[1].body as string,
          ).lifecycle_status,
        ).toBe("draft");
    },
  );
  it("serializes v2 steps including route input identities using editor format and CAS", async () => {
    const fetcher = vi.fn(async () => json(draft));
    vi.stubGlobal("fetch", fetcher);
    const steps = [
      {
        id: "route",
        name: "Route",
        kind: "route",
        enabled: true,
        config: { mode: "first", fallback: "keep", routes: [{ label: "Push", inputs: [`push:${source}`] }] },
      },
    ];
    await call("update_pipeline_draft", {
      source_id: source,
      expected_updated_at: revision,
      steps,
      draft_revision: 2,
    });
    const body = JSON.parse(
      (fetcher.mock.calls[0] as unknown as [string, RequestInit])[1]
        .body as string,
    );
    expect(body.expected_updated_at).toBe(revision);
    expect(body.parser_vrl).toBe(
      `# nano-pipe-v2 ${JSON.stringify({ version: 2, revision: 2, steps })}\n# Processing plan compiled by Nano at publication.\nnano_pipe_plan_v2()`,
    );
  });
  it("previews full parser and extension separately without storing supplied samples", async () => {
    const fetcher = vi.fn(async (url: string) =>
      json(new URL(url).pathname.endsWith("draft-status") ? draft : {}),
    );
    vi.stubGlobal("fetch", fetcher);
    await call("preview_pipeline", {
      source_id: source,
      expected_updated_at: revision,
      events: [{ message: "hello" }],
    });
    const body = JSON.parse(
      (fetcher.mock.calls[1] as unknown as [string, RequestInit])[1]
        .body as string,
    );
    expect(body.steps[0].vrl).toBe(draft.parser_vrl);
    expect(body.extension_vrl).toBe(draft.extension_vrl);
    expect(fetcher.mock.calls).toHaveLength(2);
  });
  it("requires a live reviewed revision and confirmation, publishes with CAS and consumes the plan", async () => {
    const fetcher = vi.fn(async (url: string) =>
      json(
        new URL(url).pathname.endsWith("draft-status")
          ? draft
          : { valid: true, rollout: { state: "queued" } },
      ),
    );
    vi.stubGlobal("fetch", fetcher);
    const plan = data(
      await call("review_pipeline_release", {
        source_id: source,
        expected_updated_at: revision,
      }),
    );
    const args = {
      source_id: source,
      plan_revision: plan.plan_revision,
      user_confirmed: true,
    };
    expect(
      (
        await call("publish_pipeline_release", {
          ...args,
          user_confirmed: false,
        })
      ).isError,
    ).toBe(true);
    expect((await call("publish_pipeline_release", args)).isError).not.toBe(
      true,
    );
    const posts = fetcher.mock.calls.filter(([url]) =>
      url.endsWith("/publish"),
    );
    expect(posts).toHaveLength(1);
    expect((posts[0] as unknown as [string, RequestInit])[1].method).toBe(
      "POST",
    );
    expect(
      JSON.parse(
        (posts[0] as unknown as [string, RequestInit])[1].body as string,
      ),
    ).toEqual({ expected_updated_at: revision });
    expect((await call("publish_pipeline_release", args)).isError).toBe(true);
    const definition = INGESTION_TOOLS.find(
      (t) => t.name === "publish_pipeline_release",
    )!;
    expect(
      definition._meta["io.nano/permission-requirements"].alternatives[0].allOf,
    ).toEqual(["log_sources:view", "log_sources:deploy"]);
    expect(INGESTION_READ_TOOLS).not.toContain(definition.name);
  });
  it.each(["changed", "workspace", "expired", "invalid"])(
    "refuses %s review before publication",
    async (mode) => {
      let current = draft;
      const fetcher = vi.fn(async (url: string) =>
        json(new URL(url).pathname.endsWith("draft-status") ? current : { valid: true }),
      );
      vi.stubGlobal("fetch", fetcher);
      const plan = data(
        await call("review_pipeline_release", {
          source_id: source,
          expected_updated_at: revision,
        }),
      );
      if (mode === "changed")
        current = { ...draft, parser_vrl: ".changed = true" };
      if (mode === "workspace")
        vi.stubEnv("NANOSIEM_API_KEY", "another-fixture-key");
      if (mode === "expired")
        vi.spyOn(Date, "now").mockReturnValue(Date.now() + 16 * 60000);
      expect(
        (
          await call("publish_pipeline_release", {
            source_id: source,
            plan_revision: mode === "invalid" ? "invented" : plan.plan_revision,
            user_confirmed: true,
          })
        ).isError,
      ).toBe(true);
      expect(fetcher.mock.calls.some(([url]) => url.endsWith("/publish"))).toBe(
        false,
      );
      vi.restoreAllMocks();
    },
  );
  it.each(tools)(
    "%s does not echo denied responses or credentials",
    async (name, _scope, _endpoint, args) => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => json({ secret: "private-fixture" }, 403)),
      );
      const result = await call(name, args);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).not.toContain("private-fixture");
    },
  );
  it.each([
    ["create_pipeline", { name: "", source_type: "http", parser_vrl: "." }],
    ["update_pipeline_draft", { source_id: source, parser_vrl: "." }],
    [
      "preview_pipeline",
      { source_id: source, expected_updated_at: revision, events: [] },
    ],
    [
      "review_pipeline_release",
      { source_id: "../escape", expected_updated_at: revision },
    ],
    [
      "publish_pipeline_release",
      { source_id: source, plan_revision: "invented", user_confirmed: false },
    ],
    [
      "rollback_pipeline_release",
      { source_id: source, version_id: "../escape", user_confirmed: true },
    ],
  ])("%s refuses invalid arguments without transport", async (name, args) => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    expect(
      (await call(name as string, args as Record<string, unknown>)).isError,
    ).toBe(true);
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("refuses stale previews and invalid validation before a review capability is issued", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        json(new URL(url).pathname.endsWith("draft-status") ? draft : { valid: false }),
      ),
    );
    expect(
      (
        await call("preview_pipeline", {
          source_id: source,
          expected_updated_at: "2026-10-16T00:00:00Z",
          events: [{}],
        })
      ).isError,
    ).toBe(true);
    expect(
      (
        await call("review_pipeline_release", {
          source_id: source,
          expected_updated_at: revision,
        })
      ).isError,
    ).toBe(true);
  });
});


it("completes create → preview → review → publish using the same saved revision", async () => {
  const fetcher = vi.fn(async (url: string, _options?: RequestInit) => json(new URL(url).pathname.endsWith("validate-vrl") ? { valid: true } : draft));
  vi.stubGlobal("fetch", fetcher);
  const created = data(await call("create_pipeline", { name: "Fixture", source_type: "http", parser_vrl: draft.parser_vrl }));
  expect(created.id).toBe(source);
  expect((await call("preview_pipeline", { source_id: created.id, expected_updated_at: created.updated_at, events: [{ message: "fixture" }] })).isError).not.toBe(true);
  const plan = data(await call("review_pipeline_release", { source_id: created.id, expected_updated_at: created.updated_at }));
  expect((await call("publish_pipeline_release", { source_id: created.id, plan_revision: plan.plan_revision, user_confirmed: true })).isError).not.toBe(true);
  const writes = fetcher.mock.calls.filter(([, options]) => (options as RequestInit).method !== "GET");
  expect(writes.map(([url]) => new URL(url).pathname)).toEqual(["/api/log-sources", `/api/log-sources/${source}/pipe-preview`, "/api/log-sources/validate-vrl", "/api/log-sources/validate-vrl", `/api/log-sources/${source}/publish`]);
  for (const [, options] of fetcher.mock.calls) {
    expect((options as RequestInit).redirect).toBe("error");
    expect((options as RequestInit).headers).toMatchObject({ "X-API-Key": "fixture-key" });
  }
});

it("rejects writes to routes outside the lifecycle allowlist without transport", async () => {
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  const client = new NanosiemClient({ apiUrl: "https://workspace.test", apiKey: "fixture-key" });
  for (const path of ["/api/users", "/api/log-sources/../users", `/api/log-sources/${source}/deploy`, `/api/log-sources/${source}/versions/../revert`]) {
    expect((await client.writeIngestion(path, "POST", {})).success).toBe(false);
  }
  expect(fetcher).not.toHaveBeenCalled();
});
