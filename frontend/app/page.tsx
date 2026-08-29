"use client";

import { useState, type ReactNode } from "react";

// Deployment-safe backend URL. Local development defaults to the local
// FastAPI server; set NEXT_PUBLIC_API_BASE_URL at build time in production
// (e.g. on Vercel) to point at the deployed Render backend.
const API_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000"
).replace(/\/+$/, "");

// The user-facing AI layer is branded "Nosana AI". Provider/model technical
// strings from the backend are never rendered in the main UI.
const AI_LABEL = "Nosana AI";

type ApplicationRecord = {
  target_id: string;
  origin: string;
  display_name: string;
  created_at: string;
  last_assessed_at: string | null;
  assessment_count: number;
};

type TargetVersion = {
  key: string;
  label: string;
  ref: string;
};

type TargetInfo = {
  target_type: string;
  name: string;
  description: string;
  repository: string;
  port: number;
  local_origin: string;
  supported_methods: string[];
  application_identity?: string;
  versions?: TargetVersion[];
};

type TargetsResponse = {
  targets: TargetInfo[];
};

type ApplicationContext = {
  target_id: string;
  name: string;
  framework: string;
  runtime_origin: string;
  routes: { method: string; path: string; source: string }[];
  auth_signals: string[];
  models: string[];
  security_relevant_components: string[];
  discovery_summary: string;
  frontend_routes?: { path: string; component: string; source: string }[];
  api_references?: { url: string; kind: string; method: string; source: string }[];
  storage_signals?: { storage_type: string; key: string; source: string }[];
  environment_references?: string[];
  external_services?: string[];
};

type ApplicationVersion = {
  repository: string | null;
  ref: string | null;
  commit_sha: string | null;
};

type SecurityFinding = {
  id: string;
  target_id: string;
  source: string;
  category: string;
  title: string;
  severity: string;
  status: string;
  description: string;
  evidence: Record<string, unknown>;
  remediation: string;
  test_definition: Record<string, unknown> | null;
  assessment_id: string;
  application_version: ApplicationVersion | null;
};

type RegressionReplayResult = {
  entry_id: string;
  title: string;
  status: string;
  expected_status: number;
  observed_status: number | null;
  error: string | null;
  severity: string;
  category?: string;
  invariant?: string;
  method?: string;
  path?: string;
  first_detected_version?: string | null;
  last_replayed_version?: string | null;
};

type RegressionSection = {
  tests_replayed: number;
  passed: number;
  regressions: number;
  errors: number;
  results: RegressionReplayResult[];
};

type DeterministicSection = {
  checks_executed: number;
  passed: number;
  issues: number;
  results: SecurityFinding[];
};

type AiExplorationItem = {
  hypothesis: string;
  reason: string;
  title: string;
  category: string;
  experiment: { method?: string; path?: string };
  expected_status: number | null;
  observed_status: number | null;
  verification: string;
  rejection_reason?: string | null;
  kind?: "experiment" | "observation";
  evidence?: string[];
  verification_requirement?: string;
};

type AiExplorationSection = {
  provider: string;
  model: string;
  hypotheses_generated: number;
  tests_executed: number;
  verified_findings: number;
  hypotheses_rejected: number;
  observations: number;
  executable_experiments: number;
  results: AiExplorationItem[];
  status?: "ok" | "unavailable" | "error";
  error_message?: string;
};

type SecurityTwinAssessment = {
  assessment_id: string;
  target: {
    target_type: string;
    name: string;
    repository: string;
    port: number;
    application_identity?: string;
  };
  security_twin: {
    sandbox_provider: string;
    application_version: ApplicationVersion | null;
  };
  regression: RegressionSection;
  deterministic: DeterministicSection;
  discovery: ApplicationContext | null;
  ai_exploration: AiExplorationSection;
  findings: SecurityFinding[];
  summary: {
    security_regressions: number;
    new_verified_findings: number;
    deterministic_issues: number;
    controls_passed: number;
  };
  timings?: Record<string, number>;
};

type SecurityTwinResponse = {
  application: ApplicationRecord;
  context: ApplicationContext;
  assessment: SecurityTwinAssessment;
};

type SaveVerifiedResponse = {
  saved: number;
  new: number;
  already_in_library: number;
  total_in_library: number;
};

type LibraryEntry = {
  id: string;
  fingerprint: string;
  title: string;
  category: string;
  severity: string;
  invariant: string;
  actor: { name: string; user_id: number };
  request: { method: string; path: string; headers?: Record<string, string> | null };
  expected: { status: number };
  original_observed: {
    status: number;
    body: Record<string, unknown> | string | null;
  };
  original_status: string;
  source: string;
  kind: string;
  first_seen: string;
  last_replayed: string | null;
  replay_count: number;
  current_status: string | null;
  latest_observed_status: number | null;
  first_detected_version?: string | null;
  last_replayed_version?: string | null;
};

type LibraryListResponse = {
  total: number;
  entries: LibraryEntry[];
};

// ---------------------------------------------------------------------------
// Inspection orchestration types (kept separate from rendering)
// ---------------------------------------------------------------------------

type StageKey =
  | "create"
  | "discover"
  | "checks"
  | "ai"
  | "save"
  | "replay"
  | "regression";

type StageStatus = "pending" | "running" | "done" | "skipped" | "error";

type InspectionStage = {
  key: StageKey;
  label: string;
  status: StageStatus;
  detail?: string;
};

type InspectionRun = {
  url: string;
  application: ApplicationRecord | null;
  target: TargetInfo | null;
  stages: InspectionStage[];
  baseline: SecurityTwinResponse | null;
  saved: SaveVerifiedResponse | null;
  fixed: SecurityTwinResponse | null;
  regression: SecurityTwinResponse | null;
  memory: LibraryListResponse | null;
  error: string | null;
  stageErrors: Partial<Record<StageKey, string>>;
};

const STAGE_DEFS: { key: StageKey; label: string }[] = [
  { key: "create", label: "Creating Security Twin" },
  { key: "discover", label: "Discovering Application" },
  { key: "checks", label: "Running Security Checks" },
  { key: "ai", label: "AI Security Exploration" },
  { key: "save", label: "Saving Verified BreakTraces" },
  { key: "replay", label: "Replaying Security Memory" },
  { key: "regression", label: "Checking for Regressions" },
];

const STATUS_TEXT: Record<number, string> = {
  200: "OK",
  201: "Created",
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  500: "Internal Server Error",
};

function statusLabel(code: number): string {
  return STATUS_TEXT[code] || "Unknown";
}

function normalizeOrigin(input: string): string {
  let raw = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;
  try {
    const u = new URL(raw);
    let port = "";
    const isDefaultPort =
      (u.protocol === "https:" && u.port === "443") ||
      (u.protocol === "http:" && u.port === "80");
    if (u.port && !isDefaultPort) port = `:${u.port}`;
    return `${u.protocol}//${u.hostname.toLowerCase()}${port}`;
  } catch {
    return raw.toLowerCase();
  }
}

function scrollToId(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
}

// ---------------------------------------------------------------------------
// Orchestrator: the whole inspection lifecycle, driven by real backend calls.
// The V1/V2/V3 version refs stay INTERNAL — the user only ever sees stages.
// ---------------------------------------------------------------------------

function makeStages(): InspectionStage[] {
  return STAGE_DEFS.map((s) => ({ key: s.key, label: s.label, status: "pending" }));
}

async function inspectApplication(
  url: string,
  onStages: (stages: InspectionStage[]) => void,
): Promise<InspectionRun> {
  let stages = makeStages();
  const stageErrors: Partial<Record<StageKey, string>> = {};
  const run: InspectionRun = {
    url,
    application: null,
    target: null,
    stages,
    baseline: null,
    saved: null,
    fixed: null,
    regression: null,
    memory: null,
    error: null,
    stageErrors,
  };

  const setStage = (
    key: StageKey,
    status: StageStatus,
    detail?: string,
  ) => {
    stages = stages.map((s) =>
      s.key === key ? { ...s, status, detail } : s,
    );
    onStages(stages);
  };

  const errMsg = (e: unknown, fallback: string): string =>
    e instanceof Error ? e.message : fallback;

  // -- Stage: Creating Security Twin (resolve application + target) --------
  setStage("create", "running");
  let target: TargetInfo | null = null;
  try {
    const targetsRes = await fetch(`${API_URL}/targets`);
    const targetsData = (await targetsRes.json()) as TargetsResponse;
    const targets = targetsData.targets || [];
    target =
      targets.find(
        (t) =>
          t.application_identity &&
          normalizeOrigin(t.application_identity) === normalizeOrigin(url),
      ) ?? null;
    if (!target) {
      const detail =
        "BreakTrace could not inspect this application with the current demo configuration.";
      setStage("create", "error", detail);
      run.error = detail;
      return run;
    }
    run.target = target;

    const res = await fetch(`${API_URL}/applications/resolve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(
        data.detail || data.error || `Request failed (HTTP ${res.status})`,
      );
    }
    run.application = (data as { application: ApplicationRecord }).application;
    setStage("create", "done");
  } catch (e) {
    const detail = errMsg(e, "Could not resolve the application identity.");
    setStage("create", "error", detail);
    run.error = detail;
    return run;
  }

  const versions = target?.versions?.length ? target.versions : [];

  // The regression-demo lifecycle is the ONLY flow with allowlisted versions.
  // Before replaying it, wipe THIS application's Security Memory so every
  // one-click inspection starts from the same clean, reproducible state
  // (exactly BT-001 + BT-002 created fresh by the baseline stage). Memory of
  // every other application is untouched by the backend reset endpoint.
  if (versions.length > 0 && run.application) {
    try {
      const res = await fetch(
        `${API_URL}/applications/${run.application.target_id}/breaktraces/reset`,
        { method: "POST" },
      );
      if (!res.ok) {
        stageErrors.create =
          "Security Memory reset for this demo application failed; the inspection continues.";
      }
    } catch {
      stageErrors.create =
        "Security Memory reset for this demo application failed; the inspection continues.";
    }
  }

  const assess = async (
    versionKey: string,
    onErrorKey: StageKey,
  ): Promise<SecurityTwinResponse | null> => {
    try {
      const res = await fetch(`${API_URL}/security-twin/assess`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_type: target?.target_type,
          url,
          version: versionKey,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(
          data.detail || data.error || `Request failed (HTTP ${res.status})`,
        );
      }
      return data as SecurityTwinResponse;
    } catch (e) {
      const detail = errMsg(e, "The assessment stage could not complete.");
      stageErrors[onErrorKey] = detail;
      return null;
    }
  };

  const saveVerified = async (
    requireVerifiedPrincipal = false,
  ): Promise<SaveVerifiedResponse | null> => {
    try {
      const res = await fetch(`${API_URL}/breaktrace/ai/assessment/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          requireVerifiedPrincipal ? { require_verified_principal: true } : {},
        ),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(
          data.detail || data.error || `Request failed (HTTP ${res.status})`,
        );
      }
      return data as SaveVerifiedResponse;
    } catch (e) {
      stageErrors.save = errMsg(
        e,
        "Verified findings could not be saved to Security Memory.",
      );
      return null;
    }
  };

  // -------------------------------------------------------------------------
  // Versioned lifecycle (e.g. the regression demo: V1 -> save -> V2 -> V3).
  // The version keys stay internal; the user only sees the inspection stages.
  // -------------------------------------------------------------------------
  if (versions.length > 0) {
    // STEP A — baseline (vulnerable) stage
    setStage("discover", "running");
    setStage("checks", "running");
    setStage("ai", "running");
    const v1 = await assess(versions[0].key, "ai");
    if (!v1) {
      setStage("discover", "error", "Baseline assessment failed.");
      setStage("checks", "skipped", "Depends on the baseline stage.");
      setStage("ai", "skipped", "Depends on the baseline stage.");
      run.error = "The baseline security assessment could not complete.";
      return run;
    }
    run.baseline = v1;
    setStage("discover", "done");
    setStage("checks", "done");
    setStage("ai", "done");

    // Save verified findings to Security Memory when the baseline found some.
    setStage("save", "running");
    const hasVerified = (v1.assessment.summary.new_verified_findings ?? 0) > 0;
    if (hasVerified) {
      // The demo lifecycle saves through the verified-principal quality gate
      // so only the authenticated cross-user authorization failures (with
      // identity headers) become Security Memory tests - never the
      // unauthenticated baseline check.
      const saved = await saveVerified(true);
      run.saved = saved;
      setStage(
        "save",
        saved ? "done" : "error",
        saved
          ? `${saved.new} verified BreakTrace${saved.new === 1 ? "" : "s"} saved`
          : (stageErrors.save ?? "Save failed."),
      );
    } else {
      setStage("save", "skipped", "No verified findings to save.");
    }

    // STEP B — fixed stage: replay Security Memory against the fix
    if (versions.length >= 2) {
      setStage("replay", "running");
      const v2 = await assess(versions[1].key, "replay");
      if (v2) {
        run.fixed = v2;
        const reg = v2.assessment.regression;
        setStage(
          "replay",
          "done",
          `${reg.tests_replayed} test${reg.tests_replayed === 1 ? "" : "s"} replayed · ${reg.passed} passed · ${reg.regressions} regression${reg.regressions === 1 ? "" : "s"}`,
        );
      } else {
        setStage(
          "replay",
          "error",
          stageErrors.replay ?? "Fix verification replay failed.",
        );
      }
    } else {
      setStage("replay", "skipped", "No fixed version configured.");
    }

    // STEP C — regression stage: replay the SAME memory again
    if (versions.length >= 3) {
      setStage("regression", "running");
      const v3 = await assess(versions[2].key, "regression");
      if (v3) {
        run.regression = v3;
        const reg = v3.assessment.regression;
        setStage(
          "regression",
          "done",
          `${reg.tests_replayed} test${reg.tests_replayed === 1 ? "" : "s"} replayed · ${reg.regressions} regression${reg.regressions === 1 ? "" : "s"} detected`,
        );
      } else {
        setStage(
          "regression",
          "error",
          stageErrors.regression ?? "Regression replay failed.",
        );
      }
    } else {
      setStage("regression", "skipped", "No regression version configured.");
    }
  } else {
    // -----------------------------------------------------------------------
    // Normal application (no V1/V2/V3 demo sequence): run one assessment.
    // We never pretend fix verification or regression detection happened if
    // there were no historical versions / Security Memory replays available.
    // -----------------------------------------------------------------------
    setStage("discover", "running");
    setStage("checks", "running");
    setStage("ai", "running");
    const res = await assess("", "ai");
    if (!res) {
      setStage("discover", "error", "Assessment failed.");
      setStage("checks", "skipped", "Depends on the assessment.");
      setStage("ai", "skipped", "Depends on the assessment.");
      run.error = "The security assessment could not complete.";
      return run;
    }
    run.baseline = res;
    setStage("discover", "done");
    setStage("checks", "done");
    setStage("ai", "done");

    // Save verified findings when present (real Security Memory creation).
    setStage("save", "running");
    const hasVerified = (res.assessment.summary.new_verified_findings ?? 0) > 0;
    if (hasVerified) {
      const saved = await saveVerified();
      run.saved = saved;
      setStage(
        "save",
        saved ? "done" : "error",
        saved
          ? `${saved.new} verified BreakTrace${saved.new === 1 ? "" : "s"} saved`
          : (stageErrors.save ?? "Save failed."),
      );
    } else {
      setStage("save", "skipped", "No verified findings to save.");
    }

    // Replay/regression only reflect real data from this single assessment.
    const reg = res.assessment.regression;
    if (reg.tests_replayed > 0) {
      setStage(
        "replay",
        "done",
        `${reg.tests_replayed} stored test${reg.tests_replayed === 1 ? "" : "s"} replayed · ${reg.passed} passed`,
      );
      setStage(
        "regression",
        "done",
        `${reg.regressions} regression${reg.regressions === 1 ? "" : "s"} detected`,
      );
    } else {
      setStage(
        "replay",
        "skipped",
        "No Security Memory existed for this application yet.",
      );
      setStage(
        "regression",
        "skipped",
        "No Security Memory to replay against.",
      );
    }
  }

  // Load Security Memory for the report.
  if (run.application) {
    try {
      const res = await fetch(
        `${API_URL}/applications/${run.application.target_id}/breaktraces`,
      );
      if (res.ok) {
        run.memory = (await res.json()) as LibraryListResponse;
      }
    } catch {
      run.memory = null;
    }
  }

  return run;
}

// ---------------------------------------------------------------------------
// Shared UI primitives
// ---------------------------------------------------------------------------

const CARD = "rounded-xl border border-slate-200 bg-white shadow-sm";
const EYEBROW = "text-xs font-semibold uppercase tracking-wide";

function Brand({ size = "md" }: { size?: "md" | "lg" }) {
  return (
    <span className="inline-flex items-center gap-2.5 text-slate-900">
      <span
        className={`grid place-items-center rounded-md bg-indigo-600 text-white ${
          size === "lg" ? "h-9 w-9" : "h-7 w-7"
        }`}
      >
        <svg
          viewBox="0 0 20 20"
          fill="currentColor"
          className={size === "lg" ? "h-5 w-5" : "h-4 w-4"}
          aria-hidden="true"
        >
          <path
            fillRule="evenodd"
            d="M10 1a9 9 0 0 0-5.5 1.8A8.97 8.97 0 0 0 1.7 9.2a9 9 0 0 0 2.6 6.2A9 9 0 0 0 10 19a9 9 0 0 0 5.7-3.6A8.97 8.97 0 0 0 18.3 9.2 9 9 0 0 0 10 1Zm3.7 6.7a.75.75 0 0 0-1.4-.5l-2.4 4-1.3-1.2a.75.75 0 1 0-1 1.1l2.1 2a.75.75 0 0 0 1.2-.1l3-5Z"
            clipRule="evenodd"
          />
        </svg>
      </span>
      <span
        className={`font-bold tracking-tight ${
          size === "lg" ? "text-2xl" : "text-lg"
        }`}
      >
        BreakTrace
      </span>
    </span>
  );
}

function SectionHeading({
  eyebrow,
  children,
}: {
  eyebrow?: string;
  children: ReactNode;
}) {
  return (
    <div className="mb-3">
      {eyebrow && (
        <p className={`${EYEBROW} text-slate-400`}>{eyebrow}</p>
      )}
      <h2 className="text-lg font-semibold text-slate-900">{children}</h2>
    </div>
  );
}

// Compact professional status/severity chips. Emoji-free; color + text only.
function Chip({
  children,
  tone,
}: {
  children: ReactNode;
  tone: "green" | "red" | "amber" | "slate" | "blue" | "violet";
}) {
  const styles: Record<string, string> = {
    green: "bg-green-50 text-green-700 border-green-200",
    red: "bg-red-50 text-red-700 border-red-200",
    amber: "bg-amber-50 text-amber-700 border-amber-200",
    slate: "bg-slate-50 text-slate-600 border-slate-200",
    blue: "bg-blue-50 text-blue-700 border-blue-200",
    violet: "bg-violet-50 text-violet-700 border-violet-200",
  };
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold ${styles[tone]}`}
    >
      {children}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  const tone = s === "high" ? "red" : s === "medium" ? "amber" : "slate";
  return <Chip tone={tone}>{severity.toUpperCase()}</Chip>;
}

function StatusGlyph({
  status,
  size = 16,
}: {
  status: "done" | "error" | "running" | "skipped" | "pending";
  size?: number;
}) {
  if (status === "running") {
    return (
      <span
        style={{ width: size, height: size }}
        className="inline-block animate-spin rounded-full border-2 border-indigo-200 border-t-indigo-600"
      />
    );
  }
  const color =
    status === "done"
      ? "text-green-600"
      : status === "error"
        ? "text-red-600"
        : status === "skipped"
          ? "text-slate-300"
          : "text-slate-200";
  return (
    <span style={{ width: size, height: size }} className={`${color} inline-flex items-center justify-center`}>
      {status === "done" ? (
        <svg viewBox="0 0 16 16" fill="none" style={{ width: size, height: size }}>
          <circle cx="8" cy="8" r="7" fill="currentColor" opacity="0.15" />
          <path d="M5 8l2 2 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ) : status === "error" ? (
        <svg viewBox="0 0 16 16" fill="none" style={{ width: size, height: size }}>
          <circle cx="8" cy="8" r="7" fill="currentColor" opacity="0.15" />
          <path d="M5.5 5.5l5 5M10.5 5.5l-5 5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
      ) : status === "skipped" ? (
        <svg viewBox="0 0 16 16" fill="none" style={{ width: size, height: size }}>
          <circle cx="8" cy="8" r="7" fill="currentColor" />
        </svg>
      ) : (
        <svg viewBox="0 0 16 16" fill="none" style={{ width: size, height: size }}>
          <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="1.5" />
        </svg>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Landing + inspection progress
// ---------------------------------------------------------------------------

function LandingView({
  url,
  setUrl,
  onSubmit,
  busy,
  error,
}: {
  url: string;
  setUrl: (v: string) => void;
  onSubmit: () => void;
  busy: boolean;
  error: string | null;
}) {
  const pipeline = [
    { label: "Application", tone: "slate" as const },
    { label: "Daytona Security Twin", tone: "slate" as const },
    { label: AI_LABEL, tone: "violet" as const },
    { label: "Security Memory", tone: "violet" as const },
    { label: "Regression Detection", tone: "slate" as const },
  ];
  return (
    <div className="flex w-full flex-1 flex-col items-center justify-center px-6 py-20">
      <div className="flex flex-col items-center gap-3 text-center">
        <Brand size="lg" />
        <h1 className="max-w-2xl text-2xl font-semibold tracking-tight text-slate-900">
          Security regression testing that remembers what broke.
        </h1>
        <p className="max-w-xl text-sm leading-relaxed text-slate-500">
          Enter an application URL. BreakTrace inspects it in an isolated
          security twin and turns verified failures into regression tests.
        </p>
      </div>

      <form
        className="mt-10 w-full max-w-3xl"
        onSubmit={(e) => {
          e.preventDefault();
          if (url.trim()) onSubmit();
        }}
      >
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <svg
              viewBox="0 0 20 20"
              fill="none"
              className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400"
              aria-hidden="true"
            >
              <path
                d="M4 10h8m0 0l-3-3m3 3l-3 3M14 5h2a1 1 0 011 1v8a1 1 0 01-1 1h-2"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              disabled={busy}
              className="h-14 w-full rounded-xl border border-slate-200 bg-white pl-10 pr-4 font-mono text-[15px] text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-4 focus:ring-indigo-100 disabled:cursor-not-allowed disabled:opacity-60"
            />
          </div>
          <button
            type="submit"
            disabled={busy || !url.trim()}
            className="h-14 shrink-0 rounded-xl bg-indigo-600 px-8 text-[15px] font-semibold text-white shadow-sm transition-colors hover:bg-indigo-700 focus:outline-none focus:ring-4 focus:ring-indigo-200 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy ? "Inspecting..." : "Inspect Application"}
          </button>
        </div>
      </form>

      <div className="mt-9 flex flex-wrap items-center justify-center gap-2">
        {pipeline.map((step, i) => (
          <span key={step.label} className="flex items-center gap-2">
            {i > 0 && <span className="text-slate-300">→</span>}
            <span
              className={`rounded-md border bg-white px-2.5 py-1 text-xs font-medium text-slate-600 ${
                step.tone === "violet" ? "border-violet-200 text-violet-700" : "border-slate-200"
              }`}
            >
              {step.label}
            </span>
          </span>
        ))}
      </div>

      {error && (
        <div className="mt-8 w-full max-w-3xl rounded-xl border border-red-200 bg-red-50 p-4">
          <p className="text-sm font-semibold text-red-700">Inspection Error</p>
          <p className="mt-1 whitespace-pre-wrap break-words text-sm text-red-600">
            {error}
          </p>
        </div>
      )}
    </div>
  );
}

function InspectionProgress({ stages }: { stages: InspectionStage[] }) {
  return (
    <div className="mx-auto w-full max-w-2xl py-20">
      <div className="flex flex-col items-center gap-2 text-center">
        <h2 className="text-xl font-semibold text-slate-900">
          Inspecting Application
        </h2>
        <p className="text-sm text-slate-500">
          Running inside an isolated Daytona Security Twin — never against the
          live URL.
        </p>
      </div>

      <div className="mt-8 flex flex-col gap-2.5">
        {stages.map((stage, index) => (
          <div
            key={stage.key}
            className={`flex items-center gap-3 rounded-xl border bg-white px-4 py-3 shadow-sm transition-colors ${
              stage.status === "running"
                ? "border-indigo-200 ring-4 ring-indigo-50"
                : stage.status === "error"
                  ? "border-red-200"
                  : "border-slate-200"
            }`}
          >
            <div className="flex h-6 w-6 items-center justify-center">
              <StatusGlyph status={stage.status} />
            </div>
            <span
              className={`text-sm font-medium ${
                stage.status === "skipped" ? "text-slate-400" : "text-slate-800"
              }`}
            >
              {index + 1}. {stage.label}
            </span>
            <div className="ml-auto flex items-center gap-2">
              {stage.detail && stage.status !== "running" ? (
                <span className="truncate font-mono text-[11px] text-slate-500">
                  {stage.detail}
                </span>
              ) : (
                stage.status === "pending" && (
                  <span className="text-[11px] text-slate-400">queued</span>
                )
              )}
              {stage.status === "running" && (
                <span
                  className="animate-pulse rounded-md bg-indigo-50 px-2 py-0.5 text-xs font-semibold text-indigo-600"
                >
                  Working…
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      <p className="mt-5 text-center text-xs text-slate-400">
        Stages complete only when the corresponding backend response returns —
        nothing is shown as complete early.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Result view — the consolidated report, all values derived from real data
// ---------------------------------------------------------------------------

function MetricCard({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: string;
  hint?: string;
  accent: "blue" | "violet" | "green" | "red";
}) {
  const accents = {
    blue: { text: "text-blue-600", bar: "bg-blue-600" },
    violet: { text: "text-violet-600", bar: "bg-violet-600" },
    green: { text: "text-green-600", bar: "bg-green-600" },
    red: { text: "text-red-600", bar: "bg-red-600" },
  } as const;
  return (
    <div className={`${CARD} p-4`}>
      <p className={`${EYEBROW} text-slate-400`}>{label}</p>
      <div className="mt-2 flex items-baseline gap-2">
        <span className={`text-3xl font-bold tracking-tight ${accents[accent].text}`}>
          {value}
        </span>
        {hint && <span className="font-mono text-xs text-slate-500">{hint}</span>}
      </div>
      <span className={`mt-3 block h-1 w-10 rounded-full ${accents[accent].bar}`} />
    </div>
  );
}

// Overall status alert card. Red is used sparingly (only for regression).
function OverallStatus({
  status,
}: {
  status: {
    tone: "detect" | "verify" | "discover" | "neutral";
    title: string;
    message: string;
    detail?: string;
  };
}) {
  const styles = {
    detect: {
      wrap: "border-red-200 bg-red-50",
      iconWrap: "bg-red-100 text-red-600",
      title: "text-slate-900",
      message: "text-red-700",
      detail: "text-red-600/80",
    },
    verify: {
      wrap: "border-green-200 bg-green-50",
      iconWrap: "bg-green-100 text-green-600",
      title: "text-slate-900",
      message: "text-green-700",
      detail: "text-green-600/80",
    },
    discover: {
      wrap: "border-blue-200 bg-blue-50",
      iconWrap: "bg-blue-100 text-blue-600",
      title: "text-slate-900",
      message: "text-blue-700",
      detail: "text-blue-600/80",
    },
    neutral: {
      wrap: "border-slate-200 bg-white",
      iconWrap: "bg-indigo-50 text-indigo-600",
      title: "text-slate-900",
      message: "text-slate-600",
      detail: "text-slate-500",
    },
  } as const;
  const s = styles[status.tone];
  return (
    <div className={`flex items-start gap-4 rounded-xl border p-5 ${s.wrap}`}>
      <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-lg ${s.iconWrap}`}>
        {status.tone === "detect" ? (
          <svg viewBox="0 0 20 20" fill="currentColor" className="h-5 w-5" aria-hidden="true">
            <path fillRule="evenodd" d="M8.5 3a1.5 1.5 0 0 0-1.06.44L2.44 8.44A1.5 1.5 0 0 0 2 9.5v1.06c0 .4.16.78.44 1.06l5 5A1.5 1.5 0 0 0 8.5 17h1.06c.4 0 .78-.16 1.06-.44l5-5a1.5 1.5 0 0 0 .44-1.06V9.5c0-.4-.16-.78-.44-1.06l-5-5A1.5 1.5 0 0 0 9.56 3H8.5Zm3.7 4.2a.75.75 0 1 1 1.1 1.02l-4 4.3a.75.75 0 0 1-1.1.02L6.2 10.4a.75.75 0 1 1 1.1-1.02l1.1 1.2 3.8-4.38Z" clipRule="evenodd" />
          </svg>
        ) : status.tone === "verify" ? (
          <svg viewBox="0 0 20 20" fill="currentColor" className="h-5 w-5" aria-hidden="true">
            <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.86-9.13a.75.75 0 0 0-1.22-.87l-2.8 3.9-1.4-1.4a.75.75 0 1 0-1.06 1.06l2 2a.75.75 0 0 0 1.13-.06l3.35-4.63Z" clipRule="evenodd" />
          </svg>
        ) : status.tone === "discover" ? (
          <svg viewBox="0 0 20 20" fill="currentColor" className="h-5 w-5" aria-hidden="true">
            <path fillRule="evenodd" d="M4.25 3A2.25 2.25 0 0 0 2 5.25v9.5A2.25 2.25 0 0 0 4.25 17h11.5A2.25 2.25 0 0 0 18 14.75v-9.5A2.25 2.25 0 0 0 15.75 3H4.25Zm2.3 3.7a.75.75 0 1 0-1.1 1.02l1.3 1.28-1.3 1.28a.75.75 0 1 0 1.1 1.02l1.34-1.31a.75.75 0 0 0 0-1.06L6.55 6.7Zm4.2 0a.75.75 0 0 1 0 1.06l-1 1a.75.75 0 1 1-1.5 0l1-1a.75.75 0 0 1 1.5 0Zm2.25 1.55a.75.75 0 0 1 .75-.75h1a.75.75 0 0 1 0 1.5h-1a.75.75 0 0 1-.75-.75Z" clipRule="evenodd" />
          </svg>
        ) : (
          <svg viewBox="0 0 20 20" fill="currentColor" className="h-5 w-5" aria-hidden="true">
            <path fillRule="evenodd" d="M10 1a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm.75 5.75a.75.75 0 0 0-1.5 0v3.5a.75.75 0 0 0 .63.74l2.5.5a.75.75 0 1 0 .24-1.48l-1.87-.37V6.75Z" clipRule="evenodd" />
          </svg>
        )}
      </span>
      <div className="min-w-0">
        <h3 className={`text-lg font-semibold ${s.title}`}>{status.title}</h3>
        <p className={`mt-0.5 text-sm font-medium ${s.message}`}>{status.message}</p>
        {status.detail && (
          <p className={`mt-1 text-sm ${s.detail}`}>{status.detail}</p>
        )}
      </div>
    </div>
  );
}

function LifecycleStepper({
  steps,
}: {
  steps: {
    label: string;
    value: string;
    caption: string;
    accent: "blue" | "violet" | "green" | "red";
  }[];
}) {
  const accents = {
    blue: "bg-blue-600 border-blue-600 text-white",
    violet: "bg-violet-600 border-violet-600 text-white",
    green: "bg-green-600 border-green-600 text-white",
    red: "bg-red-600 border-red-600 text-white",
  } as const;
  return (
    <div className={`${CARD} p-5`}>
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-900">
          BreakTrace lifecycle
        </h3>
        <span className="text-xs text-slate-400">
          Find → Remember → Verify → Detect
        </span>
      </div>
      <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {steps.map((step, i) => (
          <div key={step.label} className="flex items-start gap-4 sm:flex-col sm:gap-3">
            <div className="flex items-center gap-3 lg:flex-1">
              <span
                className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full border-2 font-mono text-sm font-bold ${accents[step.accent]}`}
              >
                {i + 1}
              </span>
              {i < steps.length - 1 && (
                <span className="hidden flex-1 lg:block">
                  <span className="block h-px w-full bg-slate-200" />
                </span>
              )}
            </div>
            <div className="min-w-0">
              <p className={`${EYEBROW} ${accentLabel(step.accent)}`}>{step.label}</p>
              <p className="mt-0.5 text-2xl font-bold tracking-tight text-slate-900">
                {step.value}
              </p>
              <p className="mt-0.5 text-xs leading-relaxed text-slate-500">
                {step.caption}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function accentLabel(accent: "blue" | "violet" | "green" | "red") {
  return {
    blue: "text-blue-600",
    violet: "text-violet-600",
    green: "text-green-600",
    red: "text-red-600",
  }[accent];
}

// Side-by-side Fix Verification vs Regression Detection
function ReplayRow({ item }: { item: RegressionReplayResult }) {
  const reg = item.status === "regression";
  const isError = item.status === "error";
  return (
    <div
      className={`flex flex-wrap items-center gap-3 rounded-lg border px-3 py-2.5 ${
        reg ? "border-red-100 bg-red-50/50" : "border-slate-200 bg-white"
      }`}
    >
      <span className="w-12 shrink-0 font-mono text-xs font-semibold text-slate-700">
        {item.entry_id}
      </span>
      <span className="min-w-0 flex-1 truncate text-sm text-slate-700">
        {item.title}
      </span>
      <span className="font-mono text-xs text-slate-600">
        {item.expected_status}
        <span className="text-slate-400"> → </span>
        <span className={reg ? "font-semibold text-red-600" : "text-slate-800"}>
          {item.observed_status != null ? item.observed_status : "n/a"}
        </span>
      </span>
      <Chip tone={reg ? "red" : isError ? "amber" : "green"}>
        {reg ? "Regression" : isError ? "Error" : "Passed"}
      </Chip>
    </div>
  );
}

function ReplayPanel({
  title,
  variant,
  results,
  replayed,
  passed,
  regressions,
}: {
  title: string;
  variant: "fixed" | "regression";
  results: RegressionReplayResult[];
  replayed: number;
  passed: number;
  regressions: number;
}) {
  const isFixed = variant === "fixed";
  const tone = isFixed ? "green" : "red";
  const badge = isFixed
    ? `${passed} / ${replayed} passed`
    : regressions > 0
      ? `${regressions} regression${regressions === 1 ? "" : "s"}`
      : "No regressions";
  const emptyText = isFixed
    ? "No fix-verification replay is available. Security Memory has not been replayed against a fixed version."
    : "No regression replay is available. Security Memory tests found nothing to replay for this stage.";

  return (
    <div className={`${CARD} overflow-hidden`}>
      <div
        className={`flex items-center justify-between gap-3 border-b px-5 py-4 ${
          isFixed ? "border-green-100 bg-green-50/60" : "border-red-100 bg-red-50/60"
        }`}
      >
        <h3 className="text-base font-semibold text-slate-900">{title}</h3>
        {replayed > 0 && (
          <Chip tone={tone}>
            {badge}
          </Chip>
        )}
      </div>
      <div className="p-4">
        {replayed === 0 || results.length === 0 ? (
          <p className="rounded-lg border border-dashed border-slate-200 px-3 py-6 text-center text-sm text-slate-500">
            {emptyText}
          </p>
        ) : (
          <div className="space-y-2">
            {results.map((item) => {
              const replayKey = `${item.entry_id}-${item.method}-${item.path}`;
              return <ReplayRow key={replayKey} item={item} />;
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// Verified findings: important cross-user findings get cards; others a list.
function crossUserOf(findings: SecurityFinding[]): SecurityFinding[] {
  return findings.filter((f) => {
    const ev = f.evidence as Record<string, unknown>;
    return ev["cross_user_access"] === true;
  });
}

function FindingEvidence({ finding }: { finding: SecurityFinding }) {
  const ev = finding.evidence as Record<string, unknown>;
  return (
    <div className="mt-3 space-y-2 border-t border-slate-100 pt-3">
      {finding.description && (
        <p className="text-sm leading-relaxed text-slate-600">{finding.description}</p>
      )}
      <pre className="max-h-56 overflow-y-auto whitespace-pre-wrap break-words rounded-md bg-slate-50 p-3 font-mono text-[11px] leading-relaxed text-slate-600">
        {JSON.stringify(ev, null, 2)}
      </pre>
      {finding.remediation && (
        <p className="text-xs text-slate-500">
          <span className="font-semibold text-slate-600">Remediation:</span>{" "}
          {finding.remediation}
        </p>
      )}
    </div>
  );
}

function CrossUserCard({ finding }: { finding: SecurityFinding }) {
  const ev = finding.evidence as Record<string, unknown>;
  const request = (ev["request"] as { method?: string; path?: string }) || {};
  const principalLabel =
    typeof ev["principal_label"] === "string"
      ? ev["principal_label"]
      : `user ${ev["principal"] ?? "?"}`;
  const ownerLabel =
    typeof ev["resource_owner_label"] === "string"
      ? ev["resource_owner_label"]
      : `owner ${ev["resource_owner"] ?? "?"}`;
  const method = request.method || "GET";
  const tdPath = finding.test_definition?.["path"];
  const path = request.path || (typeof tdPath === "string" ? tdPath : "") || "";
  const expected =
    typeof ev["expected_status"] === "number" ? ev["expected_status"] : undefined;
  const observed =
    typeof ev["observed_status"] === "number" ? ev["observed_status"] : undefined;
  const headers = (ev["request_headers"] as Record<string, string> | undefined) || {};
  const safeHeaders = Object.entries(headers).filter(
    ([name]) => !/authorization|cookie|token|session|secret|api[-_]?key/i.test(name),
  );

  return (
    <div className={`${CARD} overflow-hidden`}>
      <div className="border-b border-slate-100 px-5 py-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className={`${EYEBROW} text-slate-400`}>
              {finding.category.replace(/_/g, " ")}
            </p>
            <h4 className="mt-1 text-lg font-semibold text-slate-900">
              {finding.title}
            </h4>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <SeverityBadge severity={finding.severity} />
          </div>
        </div>
      </div>

      <div className="px-5 py-4">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 font-mono text-xs text-slate-700">
            {principalLabel}
          </span>
          <span className="text-slate-400">↓</span>
          <span className="rounded-lg border border-blue-200 bg-blue-50 px-2.5 py-1 font-mono text-xs font-semibold text-blue-700">
            {method} {path || "…"}
          </span>
          <span className="text-slate-400">↓</span>
          <span className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 font-mono text-xs text-slate-700">
            {ownerLabel}&apos;{path ? ` ${path.split("/").filter(Boolean).pop()}` : " resource"}
          </span>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-slate-200 bg-white p-3">
            <p className={`${EYEBROW} text-slate-400`}>Expected</p>
            <p className="mt-1 font-mono text-lg font-semibold text-slate-700">
              {expected != null ? `${expected} ${statusLabel(expected)}` : "—"}
            </p>
          </div>
          <div className="rounded-lg border border-red-200 bg-red-50/60 p-3">
            <p className={`${EYEBROW} text-red-400`}>Observed</p>
            <p className="mt-1 font-mono text-lg font-semibold text-red-600">
              {observed != null ? `${observed} ${statusLabel(observed)}` : "—"}
            </p>
          </div>
        </div>

        <div className="mt-3">
          <Chip tone="green">Verified vulnerability</Chip>
        </div>

        <details className="mt-3">
          <summary className="cursor-pointer select-none text-sm font-medium text-indigo-600 hover:text-indigo-700">
            Technical Evidence
          </summary>
          <div className="mt-2 space-y-1 font-mono text-[11px] text-slate-500">
            <p>Request method: {method}</p>
            <p>Request path: {path}</p>
            {safeHeaders.map(([name, value]) => (
              <p key={name}>
                Request header: <span className="text-slate-700">{name}: {value}</span>
              </p>
            ))}
            <p>Principal: <span className="text-slate-700">{principalLabel}</span></p>
            <p>Resource owner: <span className="text-slate-700">{ownerLabel}</span></p>
            <p>Expected status: <span className="text-slate-700">{expected}</span></p>
            <p>Observed status: <span className="text-slate-700">{observed}</span></p>
            {ev["observed_body"] != null && (
              <pre className="mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap break-words rounded-md bg-slate-50 p-2 text-slate-600">
                {JSON.stringify(ev["observed_body"], null, 2)}
              </pre>
            )}
          </div>
        </details>
      </div>
    </div>
  );
}

function SecurityMemorySection({ run }: { run: InspectionRun }) {
  const entries = run.memory?.entries ?? [];
  return (
    <div id="security-memory" className={`${CARD} flex h-full flex-col`}>
      <div className="border-b border-slate-100 px-5 py-4">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-base font-semibold text-slate-900">Security Memory</h3>
          <span className="text-xs text-slate-400">{entries.length} test{entries.length === 1 ? "" : "s"}</span>
        </div>
        <p className="mt-1 text-xs text-slate-500">
          Verified security failures become permanent regression tests.
        </p>
      </div>
      <div className="flex-1 space-y-2.5 p-4">
        {entries.length === 0 ? (
          <div className="rounded-lg border border-dashed border-violet-200 bg-violet-50/40 p-4 text-center">
            <p className="text-sm font-semibold text-violet-700">No Security Memory yet</p>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">
              This is the first inspection of this application. Every verified
              failure becomes a test remembered for tomorrow.
            </p>
          </div>
        ) : (
          entries.map((entry) => (
            <SecurityMemoryRow key={entry.fingerprint} entry={entry} />
          ))
        )}
      </div>
    </div>
  );
}

function SecurityMemoryRow({ entry }: { entry: LibraryEntry }) {
  const headers = entry.request.headers ?? {};
  const safeHeaders = Object.entries(headers).filter(
    ([name]) => !/authorization|cookie|token|session|secret|api[-_]?key/i.test(name),
  );
  const regressed = entry.current_status === "failed";
  const passed = entry.current_status === "passed";
  return (
    <div className="rounded-lg border border-slate-200 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-xs font-bold text-violet-700">{entry.id}</span>
        <span className={`${EYEBROW} ${regressed ? "text-red-600" : passed ? "text-green-600" : "text-slate-400"}`}>
          {regressed ? "Regression" : passed ? "Verified" : "Pending"}
        </span>
      </div>
      <p className="mt-1 text-sm leading-snug text-slate-700">{entry.title}</p>
      <p className="mt-1 font-mono text-[11px] text-slate-500">
        {entry.request.method} {entry.request.path}
        {safeHeaders.map(([name, value]) => (
          <span key={name} className="text-slate-400"> · {name}: {value}</span>
        ))}
      </p>
      <div className="mt-1.5 flex items-center justify-between gap-2 text-[11px] text-slate-500">
        <span>
          Expected <span className="font-mono font-semibold text-slate-700">{entry.expected.status}</span>
        </span>
        {entry.invariant && (
          <span className="truncate font-mono">{entry.invariant}</span>
        )}
      </div>
    </div>
  );
}

function FindingsPanel({ verified }: { verified: SecurityFinding[] }) {
  const crossUser = crossUserOf(verified);
  const others = verified.filter((f) => {
    const ev = f.evidence as Record<string, unknown>;
    return ev["cross_user_access"] !== true;
  });

  if (verified.length === 0) {
    return (
      <div className={`${CARD} flex h-full flex-col`}>
        <div className="border-b border-slate-100 px-5 py-4">
          <h3 className="text-base font-semibold text-slate-900">Verified Findings</h3>
        </div>
        <div className="flex-1 p-4">
          <p className="rounded-lg border border-dashed border-slate-200 px-3 py-6 text-center text-sm text-slate-500">
            No verified vulnerabilities in this inspection.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {crossUser.map((f) => (
        <CrossUserCard key={f.id} finding={f} />
      ))}
      {others.length > 0 && (
        <div className={`${CARD} overflow-hidden`}>
          <div className="border-b border-slate-100 px-5 py-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-slate-900">Verified Findings</h3>
              <span className="text-xs text-slate-400">{others.length}</span>
            </div>
          </div>
          <div className="divide-y divide-slate-100">
            {others.map((f) => (
              <details key={f.id} className="group px-5 py-3">
                <summary className="flex cursor-pointer select-none flex-wrap items-center gap-3">
                  <SeverityBadge severity={f.severity} />
                  <span className="min-w-0 flex-1 text-sm text-slate-800">{f.title}</span>
                  <span className="hidden text-xs text-slate-400 sm:inline">
                    {f.category.replace(/_/g, " ")}
                  </span>
                  <Chip tone="green">Verified</Chip>
                </summary>
                <FindingEvidence finding={f} />
              </details>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// Lower technical area: deterministic checks + Nosana AI, both collapsible.
function DeterministicPanel({
  deterministic,
}: {
  deterministic: DeterministicSection | undefined;
}) {
  const checks = deterministic;
  const countLabel = checks
    ? `${checks.checks_executed} executed · ${checks.passed} passed · ${checks.issues} issues`
    : "No checks";
  return (
    <div className={`${CARD} overflow-hidden`}>
      <div className="flex items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
        <h3 className="text-base font-semibold text-slate-900">Deterministic Checks</h3>
        <Chip tone={checks && checks.issues > 0 ? "amber" : "green"}>{countLabel}</Chip>
      </div>
      {!checks || checks.checks_executed === 0 ? (
        <p className="px-5 py-6 text-center text-sm text-slate-500">
          No deterministic checks were executed in this inspection.
        </p>
      ) : (
        <div className="p-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wide text-slate-400">
                <th className="pb-2 pr-3 font-semibold">Severity</th>
                <th className="pb-2 pr-3 font-semibold">Check</th>
                <th className="pb-2 text-right font-semibold">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {checks.results.map((f) => {
                const issue = f.status === "verified";
                return (
                  <tr key={f.id}>
                    <td className="py-2 pr-3"><SeverityBadge severity={f.severity} /></td>
                    <td className="py-2 pr-3 text-slate-700">{f.title}</td>
                    <td className="py-2 text-right">
                      <Chip tone={issue ? "amber" : "green"}>
                        {issue ? "Issue" : "Passed"}
                      </Chip>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function NosanaAiPanel({ ai }: { ai: AiExplorationSection | undefined }) {
  const unavailable = ai?.status === "unavailable" || ai?.status === "error";
  return (
    <div className={`${CARD} overflow-hidden`}>
      <div className="flex items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
        <h3 className="text-base font-semibold text-slate-900">{AI_LABEL} Exploration</h3>
        {unavailable ? (
          <Chip tone="amber">Unavailable</Chip>
        ) : (
          ai && (
            <Chip tone="slate">
              {ai.verified_findings} verified
            </Chip>
          )
        )}
      </div>
      {unavailable ? (
        <div className="p-4">
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-4">
            <p className="text-sm font-semibold text-amber-700">
              {AI_LABEL} Exploration Unavailable
            </p>
            <p className="mt-1 text-xs leading-relaxed text-amber-700/80">
              Security Memory replay, deterministic checks, and discovery
              completed successfully — fresh AI hypothesis generation did not.
            </p>
            {ai?.error_message && (
              <pre className="mt-2 max-h-24 overflow-y-auto whitespace-pre-wrap break-words rounded-md bg-white p-2 font-mono text-[11px] text-amber-700">
                {ai.error_message}
              </pre>
            )}
          </div>
        </div>
      ) : !ai ? (
        <p className="px-5 py-6 text-center text-sm text-slate-500">
          No {AI_LABEL} exploration data for this inspection.
        </p>
      ) : (
        <div className="p-4">
          <div className="mb-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-500">
            <span>{ai.hypotheses_generated} hypothesis{ai.hypotheses_generated === 1 ? "" : "es"}</span>
            <span>{ai.executable_experiments} experiment{ai.executable_experiments === 1 ? "" : "s"}</span>
            <span>{ai.tests_executed} executed</span>
            <span className="font-semibold text-green-600">{ai.verified_findings} verified</span>
            <span>{ai.hypotheses_rejected} rejected</span>
          </div>
          {ai.results.length > 0 ? (
            <div className="space-y-1.5">
              {ai.results.map((item, index) => (
                <div key={index} className="flex items-start gap-2 text-xs text-slate-600">
                  <span
                    className={`mt-0.5 inline-block h-1.5 w-1.5 shrink-0 rounded-full ${
                      item.verification === "verified"
                        ? "bg-green-500"
                        : item.verification === "rejected" || item.verification === "error"
                          ? "bg-amber-500"
                          : "bg-slate-300"
                    }`}
                  />
                  <span>{item.title || item.hypothesis}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500">No hypotheses were generated.</p>
          )}
        </div>
      )}
    </div>
  );
}

// Dense technical details, collapsed by default.
function DenseTechnical({ run }: { run: InspectionRun }) {
  const baseline = run.baseline?.assessment;
  const context = run.baseline?.context ?? baseline?.discovery ?? null;

  return (
    <details id="technical-details" className={`${CARD} group overflow-hidden`}>
      <summary className="flex cursor-pointer select-none items-center justify-between px-5 py-4">
        <span className="text-base font-semibold text-slate-900">Technical Details</span>
        <svg
          viewBox="0 0 20 20"
          fill="currentColor"
          className="h-5 w-5 text-slate-400 transition-transform group-open:rotate-180"
          aria-hidden="true"
        >
          <path fillRule="evenodd" d="M5.3 7.3a1 1 0 0 1 1.4 0L10 10.6l3.3-3.3a1 1 0 1 1 1.4 1.4l-4 4a1 1 0 0 1-1.4 0l-4-4a1 1 0 0 1 0-1.4Z" clipRule="evenodd" />
        </svg>
      </summary>
      <div className="space-y-3 border-t border-slate-100 p-5">
        {context && (
          <details className="rounded-lg border border-slate-200">
            <summary className="cursor-pointer select-none px-4 py-2.5 text-sm font-medium text-slate-800">
              Application Discovery
            </summary>
            <div className="space-y-1 border-t border-slate-100 px-4 py-3 font-mono text-[11px] leading-relaxed text-slate-500">
              <p>Name: <span className="text-slate-700">{context.name}</span></p>
              <p>Framework: <span className="text-slate-700">{context.framework || "unknown"}</span></p>
              <p>Runtime origin: <span className="text-slate-700">{context.runtime_origin}</span></p>
              <p>Routes: <span className="text-slate-700">
                {context.routes.map((r) => `${r.method} ${r.path}`).join(", ") || "none"}
              </span></p>
              <p>Discovery: <span className="text-slate-700">{context.discovery_summary || "no summary"}</span></p>
            </div>
          </details>
        )}

        <details className="rounded-lg border border-slate-200">
          <summary className="cursor-pointer select-none px-4 py-2.5 text-sm font-medium text-slate-800">
            Security Memory Details
          </summary>
          <div className="space-y-1 border-t border-slate-100 px-4 py-3 font-mono text-[11px] text-slate-500">
            {run.memory && run.memory.entries.length > 0 ? (
              run.memory.entries.map((e) => (
                <p key={e.fingerprint} className="leading-relaxed">
                  <span className="font-semibold text-slate-700">{e.id}</span> · {e.request.method} {e.request.path} · expected {e.expected.status} · current: {e.current_status || "not replayed"}
                </p>
              ))
            ) : (
              <p className="text-sm">No Security Memory entries.</p>
            )}
          </div>
        </details>

        <details className="rounded-lg border border-slate-200">
          <summary className="cursor-pointer select-none px-4 py-2.5 text-sm font-medium text-slate-800">
            Raw Assessment Responses
          </summary>
          <div className="space-y-3 border-t border-slate-100 px-4 py-3">
            {[
              { title: "Baseline assessment", data: run.baseline },
              { title: "Fix verification assessment", data: run.fixed },
              { title: "Regression assessment", data: run.regression },
              { title: "Security Memory save", data: run.saved },
            ].map(
              (raw) =>
                raw.data && (
                  <div key={raw.title}>
                    <p className={`${EYEBROW} mb-1 text-slate-400`}>{raw.title}</p>
                    <pre className="max-h-72 overflow-y-auto whitespace-pre-wrap break-words rounded-md bg-slate-50 p-3 font-mono text-[10px] leading-relaxed text-slate-600">
                      {JSON.stringify(raw.data, null, 2)}
                    </pre>
                  </div>
                ),
            )}
          </div>
        </details>
      </div>
    </details>
  );
}

function Landing({ onReset }: { onReset: () => void }) {
  return (
    <button
      onClick={onReset}
      className="inline-flex h-10 items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50"
    >
      Inspect Another Application
    </button>
  );
}

function ResultView({
  run,
  onReset,
}: {
  run: InspectionRun;
  onReset: () => void;
}) {
  const baseline = run.baseline?.assessment;
  const fixedReg = run.fixed?.assessment.regression;
  const regressionReg = run.regression?.assessment.regression;
  const verified = baseline?.findings.filter((f) => f.status === "verified") ?? [];
  const crossUserFindings = crossUserOf(verified);
  // Real cross-user findings drive the headline count when present (the
  // regression-demo story); otherwise every verified finding counts.
  const verifiedCount =
    crossUserFindings.length > 0 ? crossUserFindings.length : verified.length;
  const memoryCount = run.memory?.total ?? run.saved?.new ?? 0;
  const fixesVerified = fixedReg
    ? fixedReg.passed
    : baseline?.regression.tests_replayed
      ? baseline.regression.passed
      : 0;
  const regressionsDetected = regressionReg
    ? regressionReg.regressions
    : baseline?.regression.regressions ?? 0;
  const testsReplayed = (fixedReg && fixedReg.tests_replayed > 0)
    ? fixedReg.tests_replayed
    : baseline?.regression.tests_replayed ?? 0;
  const hasStageError = Object.keys(run.stageErrors).length > 0;

  // Overall status (red stays rare).
  let status: {
    tone: "detect" | "verify" | "discover" | "neutral";
    title: string;
    message: string;
    detail?: string;
  };
  if (regressionsDetected > 0) {
    status = {
      tone: "detect",
      title: "Security Regression Detected",
      message: `${regressionsDetected} previously fixed security condition${regressionsDetected === 1 ? "" : "s"} have returned.`,
      detail: `${regressionsDetected} regression${regressionsDetected === 1 ? "" : "s"} require attention.`,
    };
  } else if (testsReplayed > 0 && fixVerifiedAllClear(run)) {
    status = {
      tone: "verify",
      title: "Fix Verified",
      message: "All stored Security Memory tests held against the fixed application.",
    };
  } else if (verifiedCount > 0) {
    status = {
      tone: "discover",
      title: "Verified Vulnerabilities Found",
      message: `${verifiedCount} verified security finding${verifiedCount === 1 ? "" : "s"} discovered in this application.`,
    };
  } else {
    status = {
      tone: "neutral",
      title: "Inspection Complete",
      message: "No verified security issues were detected.",
    };
  }

  const lifecycleSteps = [
    {
      label: "Discover",
      value: `${verifiedCount}`,
      caption: crossUserFindings.length > 0
        ? "Cross-user access vulnerability found"
        : verifiedCount > 0
          ? "verified findings"
          : "no vulnerability found",
      accent: "blue" as const,
    },
    {
      label: "Remember",
      value: `${memoryCount}`,
      caption: memoryCount > 0 ? "tests kept in Security Memory" : "nothing to remember yet",
      accent: "violet" as const,
    },
    {
      label: "Verify",
      value: testsReplayed > 0 ? `${fixesVerified}/${testsReplayed}` : "—",
      caption: testsReplayed > 0 ? "passed after the fix" : "no fix replay available",
      accent: "green" as const,
    },
    {
      label: "Detect",
      value: `${regressionsDetected}`,
      caption: regressionsDetected > 0 ? "regressions caught" : "no regression",
      accent: regressionsDetected > 0 ? ("red" as const) : ("green" as const),
    },
  ];

  return (
    <div className="mx-auto w-full max-w-[1400px] px-4 py-10 sm:px-6 lg:px-10">
      {/* Header */}
      <header className="flex flex-wrap items-center justify-between gap-4">
        <Brand />
        <div className="flex items-center gap-3">
          <Chip tone={regressionsDetected > 0 ? "red" : "green"}>
            Inspection {regressionsDetected > 0 ? "complete · regressions found" : "complete"}
          </Chip>
          <Landing onReset={onReset} />
        </div>
      </header>

      {/* Report intro */}
      <div className="mt-8">
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          Security Regression Report
        </h1>
        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-slate-500">
          <span className="font-mono text-[13px] text-slate-700">
            {run.application?.origin || run.url}
          </span>
          {run.target?.name && (
            <span className="text-slate-400">· {run.target.name}</span>
          )}
        </div>
      </div>

      <div className="mt-6 space-y-6">
        {/* Overall status */}
        <OverallStatus status={status} />

        {/* Stage errors must never blank the screen */}
        {hasStageError && (
          <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4">
            <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full bg-amber-500" />
            <div className="text-sm">
              <p className="font-semibold text-amber-700">
                Some stages could not complete
              </p>
              {Object.entries(run.stageErrors).map(([key, detail]) => (
                <p key={key} className="mt-0.5 text-xs leading-relaxed text-amber-700/80">
                  <span className="font-semibold uppercase">{key}</span>: {detail}
                </p>
              ))}
              <p className="mt-1 text-xs text-amber-700/70">
                All earlier successful results are preserved below.
              </p>
            </div>
          </div>
        )}

        {/* Summary metrics — one row on desktop */}
        <section>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <MetricCard
              label="Verified Vulnerabilities"
              value={`${verifiedCount}`}
              accent={verifiedCount > 0 ? "blue" : "blue"}
            />
            <MetricCard
              label="Security Memory"
              value={`${memoryCount}`}
              hint="tests"
              accent="violet"
            />
            <MetricCard
              label="Fixes Verified"
              value={testsReplayed > 0 ? `${fixesVerified}/${testsReplayed}` : "0"}
              accent="green"
            />
            <MetricCard
              label="Regressions"
              value={`${regressionsDetected}`}
              accent={regressionsDetected > 0 ? "red" : "green"}
            />
          </div>
        </section>

        {/* Lifecycle — one row on desktop */}
        <LifecycleStepper steps={lifecycleSteps} />

        {/* Fix Verification vs Regression Detection */}
        <section>
          <SectionHeading eyebrow="Vulnerability fixed, then returned">
            Fix Verification vs Regression Detection
          </SectionHeading>
          <div className="grid gap-4 lg:grid-cols-2">
            <ReplayPanel
              title="Fix Verification"
              variant="fixed"
              results={fixedReg?.results ?? []}
              replayed={fixedReg?.tests_replayed ?? 0}
              passed={fixedReg?.passed ?? 0}
              regressions={fixedReg?.regressions ?? 0}
            />
            <ReplayPanel
              title="Regression Detection"
              variant="regression"
              results={regressionReg?.results ?? []}
              replayed={regressionReg?.tests_replayed ?? 0}
              passed={regressionReg?.passed ?? 0}
              regressions={regressionReg?.regressions ?? 0}
            />
          </div>
        </section>

        {/* Findings + Security Memory */}
        <section className="grid gap-4 lg:grid-cols-2">
          <div>
            <SectionHeading>Verified Findings</SectionHeading>
            <FindingsPanel verified={verified} />
          </div>
          <div>
            <SectionHeading>Security Memory</SectionHeading>
            <SecurityMemorySection run={run} />
          </div>
        </section>

        {/* Lower technical area */}
        <section>
          <SectionHeading eyebrow="Supporting detail">Technical Analysis</SectionHeading>
          <div className="grid items-start gap-4 lg:grid-cols-2">
            <DeterministicPanel deterministic={baseline?.deterministic} />
            <NosanaAiPanel ai={baseline?.ai_exploration} />
          </div>
        </section>

        <DenseTechnical run={run} />

        {/* Footer actions */}
        <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 pt-6">
          <p className="text-sm text-slate-500">
            Core concept: BreakTrace found a vulnerability, remembered it,
            verified a fix, and caught it when it returned.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => scrollToId("security-memory")}
              className="inline-flex h-10 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50"
            >
              View Security Memory
            </button>
            <button
              onClick={() => scrollToId("technical-details")}
              className="inline-flex h-10 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50"
            >
              Technical Details
            </button>
            <button
              onClick={onReset}
              className="inline-flex h-10 items-center rounded-lg bg-indigo-600 px-4 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-indigo-700"
            >
              Inspect Another Application
            </button>
          </div>
        </footer>
      </div>
    </div>
  );
}

// True when the fix stage replayed stored tests and every one passed.
function fixVerifiedAllClear(run: InspectionRun): boolean {
  const fixedReg = run.fixed?.assessment.regression;
  if (!fixedReg || fixedReg.tests_replayed === 0) return false;
  return fixedReg.regressions === 0;
}

// ---------------------------------------------------------------------------
// Home — orchestrates landing -> inspection -> result
// ---------------------------------------------------------------------------

export default function Home() {
  const [url, setUrl] = useState("");
  const [phase, setPhase] = useState<"landing" | "inspecting" | "result">(
    "landing",
  );
  const [stages, setStages] = useState<InspectionStage[]>(makeStages);
  const [run, setRun] = useState<InspectionRun | null>(null);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const startInspection = () => {
    const trimmed = url.trim();
    if (!trimmed) return;
    setInspectError(null);
    setBusy(true);
    setPhase("inspecting");
    setStages(makeStages());
    setRun(null);
    void inspectApplication(trimmed, setStages).then((result) => {
      setRun(result);
      setBusy(false);
      setPhase("result");
    });
  };

  const reset = () => {
    setRun(null);
    setStages(makeStages());
    setInspectError(null);
    setBusy(false);
    setPhase("landing");
  };

  return (
    <main className="flex flex-1 flex-col">
      {phase === "landing" && (
        <LandingView
          url={url}
          setUrl={setUrl}
          onSubmit={startInspection}
          busy={busy}
          error={inspectError}
        />
      )}
      {phase === "inspecting" && (
        <div className="px-6">
          <InspectionProgress stages={stages} />
        </div>
      )}
      {phase === "result" && run && <ResultView run={run} onReset={reset} />}
    </main>
  );
}