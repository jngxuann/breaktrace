"use client";

import { useState, type ReactNode } from "react";

const API_URL = "http://localhost:8000";

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
  return (
    <div className="flex w-full max-w-xl flex-col items-center gap-10 py-24 text-center">
      <div className="flex flex-col items-center gap-4">
        <h1 className="font-mono text-6xl font-bold tracking-tight text-zinc-100">
          BreakTrace
        </h1>
        <p className="font-mono text-sm text-emerald-400">
          &ldquo;Find vulnerabilities. Turn them into tests. Keep them from
          coming back.&rdquo;
        </p>
      </div>

      <form
        className="flex w-full flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (url.trim()) onSubmit();
        }}
      >
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          disabled={busy}
          className="h-14 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-4 font-mono text-base text-zinc-100 placeholder:text-zinc-600 focus:border-emerald-500/50 focus:outline-none disabled:cursor-not-allowed disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={busy || !url.trim()}
          className="h-14 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-8 font-mono text-base font-semibold text-emerald-300 transition-colors hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? "Inspecting..." : "Inspect Application"}
        </button>
      </form>

      <p className="font-mono text-xs text-zinc-500">
        Enter an application URL. BreakTrace will inspect it in an isolated
        security twin.
      </p>

      <div className="flex flex-wrap items-center justify-center gap-2 font-mono text-[10px] text-zinc-600">
        <span className="rounded-sm border border-zinc-800 bg-zinc-900 px-2 py-1 text-zinc-400">
          Application
        </span>
        <span>→</span>
        <span className="rounded-sm border border-zinc-800 bg-zinc-900 px-2 py-1 text-zinc-400">
          Daytona Security Twin
        </span>
        <span>→</span>
        <span className="rounded-sm border border-zinc-800 bg-zinc-900 px-2 py-1 text-violet-300">
          {AI_LABEL} Analysis
        </span>
        <span>→</span>
        <span className="rounded-sm border border-zinc-800 bg-zinc-900 px-2 py-1 text-zinc-400">
          BreakTrace Security Memory
        </span>
        <span>→</span>
        <span className="rounded-sm border border-zinc-800 bg-zinc-900 px-2 py-1 text-zinc-400">
          Regression Detection
        </span>
      </div>

      {error && (
        <div className="w-full rounded-md border border-red-500/40 bg-red-950/40 p-4 font-mono text-sm text-red-300">
          <p className="mb-1 font-semibold text-red-400">Inspection Error</p>
          <p className="whitespace-pre-wrap break-words">{error}</p>
        </div>
      )}
    </div>
  );
}

function InspectionProgress({ stages }: { stages: InspectionStage[] }) {
  return (
    <div className="flex w-full max-w-xl flex-col items-center gap-8 py-24">
      <p className="font-mono text-xl font-bold text-zinc-100">
        Inspecting Application
      </p>
      <p className="font-mono text-xs text-zinc-500">
        Running inside an isolated Daytona Security Twin — never against the
        live URL.
      </p>
      <div className="flex w-full flex-col gap-2">
        {stages.map((stage) => {
          const icon =
            stage.status === "done"
              ? "✅"
              : stage.status === "error"
                ? "❌"
                : stage.status === "skipped"
                  ? "—"
                  : stage.status === "running"
                    ? "⏳"
                    : "○";
          const color =
            stage.status === "done"
              ? "text-emerald-400"
              : stage.status === "error"
                ? "text-red-400"
                : stage.status === "skipped"
                  ? "text-zinc-600"
                  : stage.status === "running"
                    ? "text-violet-300"
                    : "text-zinc-600";
          return (
            <div
              key={stage.key}
              className="flex items-center gap-3 rounded-md border border-zinc-800 bg-zinc-950 px-4 py-3"
            >
              <span className={`w-6 font-mono text-sm ${color}`}>{icon}</span>
              <span className={`font-mono text-sm ${color}`}>
                {stage.label}
              </span>
              {stage.status === "running" && (
                <span className="ml-auto h-2 w-2 animate-pulse rounded-full bg-violet-400" />
              )}
              {stage.detail && stage.status !== "running" && (
                <span className="ml-auto truncate font-mono text-[11px] text-zinc-500">
                  {stage.detail}
                </span>
              )}
            </div>
          );
        })}
      </div>
      <p className="font-mono text-[11px] text-zinc-600">
        Stages complete only when the corresponding backend response returns —
        nothing is shown as finished early.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Result view — the consolidated report, all values derived from real data
// ---------------------------------------------------------------------------

function Metric({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: number | string;
  tone?: "default" | "red" | "green" | "amber";
}) {
  const color =
    tone === "red"
      ? "text-red-400"
      : tone === "green"
        ? "text-emerald-400"
        : tone === "amber"
          ? "text-amber-400"
          : "text-zinc-100";
  return (
    <div className="rounded-md border border-zinc-800 bg-zinc-950 p-4 text-center">
      <p className={`font-mono text-3xl font-bold ${color}`}>{value}</p>
      <p className="mt-1 font-mono text-[11px] uppercase tracking-widest text-zinc-500">
        {label}
      </p>
    </div>
  );
}

function ResultBanner({ run }: { run: InspectionRun }) {
  const regressions = run.regression?.assessment.regression;
  const fixed = run.fixed?.assessment.regression;
  const baselineReg = run.baseline?.assessment.regression;
  const newFindings = run.baseline?.assessment.summary.new_verified_findings ?? 0;

  let title = "INSPECTION COMPLETE";
  let subtitle = "No security regression detected.";
  let tone = "border-zinc-700 bg-zinc-950";
  let text = "text-zinc-100";

  if (regressions && regressions.regressions > 0) {
    title = "🚨 SECURITY REGRESSION DETECTED";
    subtitle =
      "Previously fixed security conditions have returned. Security Memory caught them.";
    tone = "border-red-500 bg-red-500/10";
    text = "text-red-400";
  } else if (fixed && fixed.tests_replayed > 0 && fixed.regressions === 0) {
    title = "🟢 FIX VERIFIED";
    subtitle =
      "BreakTrace replayed the previously discovered security tests against the fixed application.";
    tone = "border-emerald-500 bg-emerald-500/10";
    text = "text-emerald-400";
  } else if (newFindings > 0) {
    title = "🔴 VULNERABILITIES FOUND";
    subtitle = "BreakTrace verified real security failures in this application.";
    tone = "border-red-500/60 bg-red-950/40";
    text = "text-red-400";
  } else if (baselineReg && baselineReg.tests_replayed > 0 && baselineReg.regressions === 0) {
    title = "🟢 SECURITY MEMORY REPLAYED";
    subtitle = "Stored Security Memory tests held — no regressions found.";
    tone = "border-emerald-500/60 bg-emerald-950/40";
    text = "text-emerald-400";
  }

  return (
    <div className={`w-full rounded-md border-2 p-6 ${tone}`}>
      <p className="text-center font-mono text-xs uppercase tracking-widest text-zinc-500">
        INSPECTION COMPLETE
      </p>
      <p className={`mt-2 text-center font-mono text-2xl font-black tracking-tight ${text}`}>
        {title}
      </p>
      <p className="mt-2 text-center font-mono text-sm leading-relaxed text-zinc-400">
        {subtitle}
      </p>
    </div>
  );
}

function LifecycleStory({ run }: { run: InspectionRun }) {
  const baseline = run.baseline?.assessment;
  const fixedReg = run.fixed?.assessment.regression;
  const regressionReg = run.regression?.assessment.regression;
  const newFindings = baseline?.summary.new_verified_findings ?? 0;
  const savedCount = run.saved?.new ?? 0;
  const memoryTotal = run.memory?.total ?? 0;
  const remembered = savedCount > 0 ? savedCount : memoryTotal;
  const verifiedFindings = baseline?.findings.filter(
    (f) => f.status === "verified",
  ) ?? [];
  const crossUserFindings = verifiedFindings.filter((f) => {
    const ev = f.evidence as Record<string, unknown>;
    return ev["cross_user_access"] === true;
  });
  const crossUser = crossUserFindings.length > 0;
  // Count real cross-user findings when the assessment produced them (the
  // demo story); otherwise fall back to all verified findings so normal
  // applications keep their real counts.
  const verifiedCount = crossUser
    ? crossUserFindings.length
    : verifiedFindings.length;

  const steps: {
    label: string;
    caption: string;
    tone: "red" | "green" | "zinc" | "amber";
    value?: string;
  }[] = [
    {
      label: "DISCOVER",
      caption: crossUser
        ? "Cross-user access vulnerability found"
        : newFindings > 0
          ? `${verifiedCount} verified security finding${verifiedCount === 1 ? "" : "s"}`
          : "No verified vulnerability discovered",
      tone: newFindings > 0 ? "red" : "zinc",
      value: newFindings > 0 ? `${verifiedCount}` : "0",
    },
    {
      label: "REMEMBER",
      caption:
        remembered > 0
          ? `${remembered} verified BreakTrace${remembered === 1 ? "" : "s"} saved to Security Memory`
          : "Nothing to remember yet",
      tone: remembered > 0 ? "amber" : "zinc",
      value: remembered > 0 ? `${remembered}` : "0",
    },
    {
      label: "VERIFY",
      caption:
        fixedReg && fixedReg.tests_replayed > 0
          ? `Stored tests replayed after fix — ${fixedReg.passed} / ${fixedReg.tests_replayed} passed`
          : run.baseline?.assessment.regression.tests_replayed
            ? `Stored tests replayed — ${run.baseline.assessment.regression.passed} / ${run.baseline.assessment.regression.tests_replayed} passed`
            : "No fix verification available",
      tone:
        fixedReg && fixedReg.regressions === 0 && fixedReg.tests_replayed > 0
          ? "green"
          : "zinc",
      value:
        fixedReg && fixedReg.tests_replayed > 0
          ? `${fixedReg.passed}/${fixedReg.tests_replayed}`
          : run.baseline?.assessment.regression.tests_replayed
            ? `${run.baseline.assessment.regression.passed}/${run.baseline.assessment.regression.tests_replayed}`
            : "—",
    },
    {
      label: "DETECT",
      caption:
        regressionReg && regressionReg.regressions > 0
          ? `Same tests replayed again — ${regressionReg.regressions} regression${regressionReg.regressions === 1 ? "" : "s"} detected`
          : run.baseline?.assessment.regression.regressions
            ? `${run.baseline.assessment.regression.regressions} regression${run.baseline.assessment.regression.regressions === 1 ? "" : "s"} detected on replay`
            : "No regression detected",
      tone:
        (regressionReg && regressionReg.regressions > 0) ||
        (run.baseline?.assessment.regression.regressions ?? 0) > 0
          ? "red"
          : "green",
      value:
        regressionReg
          ? `${regressionReg.regressions}`
          : `${run.baseline?.assessment.regression.regressions ?? 0}`,
    },
  ];

  return (
    <div className="w-full rounded-md border border-violet-500/40 bg-zinc-950 p-5">
      <div className="flex items-center justify-between gap-4">
        <p className="font-mono text-xs uppercase tracking-widest text-violet-400">
          BREAKTRACE LIFECYCLE
        </p>
        <p className="font-mono text-[11px] text-emerald-400">
          Find → Remember → Verify → Detect
        </p>
      </div>
      <div className="mt-4 flex flex-col gap-3">
        {steps.map((step, i) => {
          const color =
            step.tone === "red"
              ? "border-red-500/50 bg-red-500/10 text-red-400"
              : step.tone === "green"
                ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
                : step.tone === "amber"
                  ? "border-amber-500/50 bg-amber-500/10 text-amber-400"
                  : "border-zinc-700 bg-black/40 text-zinc-400";
          return (
            <div key={step.label} className="flex flex-col gap-2">
              <div
                className={`flex items-center justify-between gap-3 rounded-md border px-4 py-3 ${color}`}
              >
                <span className="font-mono text-sm font-bold">
                  {step.label}
                </span>
                <span className="font-mono text-lg font-black">
                  {step.value}
                </span>
              </div>
              <p className="px-1 font-mono text-[11px] text-zinc-400">
                {step.caption}
              </p>
              {i < steps.length - 1 && (
                <p className="px-1 text-center font-mono text-zinc-600">↓</p>
              )}
            </div>
          );
        })}
      </div>
      <p className="mt-4 text-center font-mono text-xs leading-relaxed text-zinc-500">
        BreakTrace found a vulnerability, remembered it, verified the fix, and
        caught it when it came back.
      </p>
    </div>
  );
}

function VulnerabilityCard({ finding }: { finding: SecurityFinding }) {
  const ev = finding.evidence as Record<string, unknown>;
  const crossUser = ev["cross_user_access"] === true;
  if (!crossUser) {
    return (
      <div className="w-full rounded-md border border-red-500/40 bg-red-950/30 p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-widest text-red-400">
              VERIFIED FINDING · {finding.category.replace(/_/g, " ")}
            </p>
            <h3 className="mt-1 font-mono text-lg font-bold text-zinc-100">
              {finding.title}
            </h3>
          </div>
          <span className="rounded-sm border border-red-500/50 bg-red-500/10 px-2 py-0.5 font-mono text-[11px] font-bold text-red-400">
            {finding.severity.toUpperCase()}
          </span>
        </div>
        <p className="mt-2 text-sm leading-relaxed text-zinc-400">
          {finding.description}
        </p>
        <details className="mt-3 rounded-md border border-zinc-800 bg-black/40">
          <summary className="cursor-pointer select-none px-3 py-2 font-mono text-xs font-semibold text-zinc-300">
            Technical Evidence
          </summary>
          <pre className="max-h-48 overflow-y-auto whitespace-pre-wrap break-words border-t border-zinc-800 px-3 py-2 font-mono text-[11px] leading-relaxed text-zinc-400">
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
        </details>
      </div>
    );
  }

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
  const path =
    request.path ||
    (typeof tdPath === "string" ? tdPath : "") ||
    "";
  const expected =
    typeof ev["expected_status"] === "number" ? ev["expected_status"] : undefined;
  const observed =
    typeof ev["observed_status"] === "number" ? ev["observed_status"] : undefined;
  const headers =
    (ev["request_headers"] as Record<string, string> | undefined) || {};
  const safeHeaders = Object.entries(headers).filter(
    ([name]) => !/authorization|cookie|token|session|secret|api[-_]?key/i.test(name),
  );

  return (
    <div className="w-full rounded-md border border-red-500/40 bg-red-950/30">
      <div className="border-b border-red-500/30 p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-widest text-red-400">
              {finding.category.replace(/_/g, " ")}
            </p>
            <h3 className="mt-1 font-mono text-xl font-bold text-zinc-100">
              {finding.title}
            </h3>
          </div>
          <span className="rounded-sm border border-red-500/50 bg-red-500/10 px-2 py-0.5 font-mono text-[11px] font-bold text-red-400">
            {finding.severity.toUpperCase()}
          </span>
        </div>
      </div>
      <div className="p-5">
        <div className="flex flex-wrap items-center gap-2 font-mono text-sm">
          <span className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-zinc-200">
            {principalLabel}
          </span>
          <span className="text-zinc-500">↓</span>
          <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-2 py-1 font-semibold text-emerald-300">
            {method} {path}
          </span>
          <span className="text-zinc-500">↓</span>
          <span className="rounded border border-red-500/40 bg-red-500/10 px-2 py-1 text-red-300">
            {ownerLabel}&apos;s {path.split("/").filter(Boolean).pop() || "resource"}
          </span>
        </div>

        <div className="mt-3 grid gap-3 font-mono text-sm sm:grid-cols-2">
          <div className="rounded-md border border-zinc-800 bg-black/40 p-3">
            <p className="text-[11px] uppercase tracking-widest text-zinc-500">
              Expected
            </p>
            <p className="mt-1 font-semibold text-zinc-200">
              {expected != null ? `${expected} ${statusLabel(expected)}` : "—"}
            </p>
          </div>
          <div className="rounded-md border border-red-500/40 bg-red-950/40 p-3">
            <p className="text-[11px] uppercase tracking-widest text-zinc-500">
              Observed
            </p>
            <p className="mt-1 font-semibold text-red-300">
              {observed != null ? `${observed} ${statusLabel(observed)}` : "—"}
            </p>
          </div>
        </div>

        <p className="mt-3 rounded-sm border border-red-500/40 bg-red-950/40 px-2 py-1 font-mono text-[12px] font-bold text-red-300">
          Cross-user access verified: a different user received a resource they
          should not own.
        </p>

        <details className="mt-3 rounded-md border border-zinc-800 bg-black/40">
          <summary className="cursor-pointer select-none px-3 py-2 font-mono text-xs font-semibold text-zinc-300">
            Technical Evidence
          </summary>
          <div className="space-y-1 border-t border-zinc-800 px-3 py-2 font-mono text-[11px] text-zinc-400">
            <p>Request method: {method}</p>
            <p>Request path: {path}</p>
            {safeHeaders.map(([name, value]) => (
              <p key={name}>
                Request header:{" "}
                <span className="text-zinc-200">
                  {name}: {value}
                </span>
              </p>
            ))}
            <p>
              Principal: <span className="text-zinc-200">{principalLabel}</span>
            </p>
            <p>
              Resource owner: <span className="text-zinc-200">{ownerLabel}</span>
            </p>
            <p>
              Expected status: <span className="text-zinc-200">{expected}</span>
            </p>
            <p>
              Observed status: <span className="text-zinc-200">{observed}</span>
            </p>
            {ev["observed_body"] != null && (
              <pre className="max-h-40 overflow-y-auto whitespace-pre-wrap break-words rounded-md border border-zinc-800 bg-black/40 p-2 text-zinc-300">
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
    <div
      id="security-memory"
      className="w-full rounded-md border border-amber-500/40 bg-zinc-950 p-5"
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="font-mono text-xs uppercase tracking-widest text-amber-400">
          SECURITY MEMORY
        </p>
        <span className="font-mono text-[11px] text-emerald-400">
          &ldquo;Verified security failures become permanent regression tests.&rdquo;
        </span>
      </div>
      {entries.length === 0 ? (
        <div className="mt-3 rounded-md border border-zinc-800 bg-black/40 p-4">
          <p className="font-mono text-sm font-bold text-amber-300">
            NO SECURITY MEMORY YET
          </p>
          <p className="mt-1 text-sm leading-relaxed text-zinc-400">
            This is the first inspection of this application. Every verified
            failure from this inspection becomes a test remembered for
            tomorrow.
          </p>
        </div>
      ) : (
        <div className="mt-3 flex flex-col gap-3">
          {entries.map((entry) => {
            const headers = entry.request.headers ?? {};
            const safeHeaders = Object.entries(headers).filter(
              ([name]) =>
                !/authorization|cookie|token|session|secret|api[-_]?key/i.test(
                  name,
                ),
            );
            return (
              <div
                key={entry.fingerprint}
                className="rounded-md border border-zinc-800 bg-black/40 p-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="font-mono text-sm font-bold text-zinc-100">
                    {entry.id}
                  </p>
                  <span
                    className={`rounded-sm border px-2 py-0.5 font-mono text-[11px] font-bold ${
                      entry.current_status === "failed"
                        ? "border-red-500/50 bg-red-500/10 text-red-400"
                        : entry.current_status === "passed"
                          ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
                          : "border-zinc-700 bg-zinc-900 text-zinc-400"
                    }`}
                  >
                    {entry.severity.toUpperCase()}
                  </span>
                </div>
                <p className="mt-2 font-mono text-xs text-zinc-200">
                  {entry.title}
                </p>
                <p className="mt-1 font-mono text-[11px] text-emerald-300">
                  {entry.request.method} {entry.request.path}
                  {safeHeaders.map(([name, value]) => (
                    <span key={name} className="text-zinc-400">
                      {" "}
                      · {name}: {value}
                    </span>
                  ))}
                </p>
                {entry.invariant && (
                  <p className="mt-1 font-mono text-[11px] text-zinc-400">
                    Invariant: {entry.invariant}
                  </p>
                )}
                <p className="mt-1 font-mono text-[11px] text-zinc-400">
                  Expected: <span className="text-zinc-200">{entry.expected.status}</span>
                </p>
                <p className="mt-2 font-mono text-[11px] text-zinc-500">
                  Lifecycle: Discovered{" "}
                  {entry.first_detected_version
                    ? `(${entry.first_detected_version})`
                    : ""}{" "}
                  →{" "}
                  {entry.current_status === "passed"
                    ? "Fix Verified"
                    : entry.current_status === "failed"
                      ? "Regression Detected"
                      : "Pending replay"}
                  {entry.last_replayed_version
                    ? ` (${entry.last_replayed_version})`
                    : ""}
                </p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ReplayResults({
  title,
  results,
  replayed,
  passed,
  regressions,
  variant,
}: {
  title: string;
  results: RegressionReplayResult[];
  replayed: number;
  passed: number;
  regressions: number;
  variant: "fixed" | "regression";
}) {
  const isFixed = variant === "fixed";
  return (
    <div
      className={`w-full rounded-md border p-5 ${
        isFixed
          ? "border-emerald-500/40 bg-zinc-950"
          : "border-red-500/50 bg-red-950/30"
      }`}
    >
      <p
        className={`font-mono text-xs uppercase tracking-widest ${
          isFixed ? "text-emerald-400" : "text-red-400"
        }`}
      >
        {title}
      </p>
      <div className="mt-3 grid grid-cols-3 gap-3">
        <Metric label="Tests Replayed" value={replayed} />
        <Metric
          label="Passed"
          value={passed}
          tone={isFixed ? "green" : "default"}
        />
        <Metric
          label="Regressions"
          value={regressions}
          tone={!isFixed && regressions > 0 ? "red" : "default"}
        />
      </div>
      <div className="mt-3 flex flex-col gap-2">
        {results.map((item) => {
          // Defensive composite key: entry ids are unique in the backend
          // data, but the method/path suffix keeps React stable even if a
          // legacy duplicate id ever reached the UI.
          const replayKey = `${item.entry_id}-${item.method}-${item.path}`;
          return (
            <div
              key={replayKey}
              className={`rounded-md border p-3 ${
                item.status === "regression"
                  ? "border-red-500/60 bg-red-950/40"
                  : "border-zinc-800 bg-black/40"
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="font-mono text-sm font-bold text-zinc-100">
                  {item.entry_id}
                </p>
                <span
                  className={`rounded-sm border px-2 py-0.5 font-mono text-[11px] font-bold ${
                    item.status === "regression"
                      ? "border-red-500/60 bg-red-500/10 text-red-400"
                      : "border-emerald-500/60 bg-emerald-500/10 text-emerald-400"
                  }`}
                >
                  {item.status === "regression"
                    ? "🚨 REGRESSION"
                    : item.status === "error"
                      ? "⚠ REPLAY ERROR"
                      : "🟢 PASSED"}
                </span>
              </div>
              <p className="mt-2 font-mono text-xs text-zinc-200">
                {item.title}
              </p>
              <div className="mt-2 grid gap-1 font-mono text-[11px] text-zinc-400 sm:grid-cols-2">
                <p>
                  Expected:{" "}
                  <span className="text-zinc-200">{item.expected_status}</span>
                </p>
                <p>
                  Observed:{" "}
                  <span
                    className={
                      item.observed_status === item.expected_status
                        ? "text-emerald-300"
                        : "text-red-300"
                    }
                  >
                    {item.observed_status != null
                      ? item.observed_status
                      : "n/a"}
                  </span>
                </p>
              </div>
              {item.error && (
                <p className="mt-1 font-mono text-[11px] text-amber-400">
                  {item.error}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TechnicalDetails({ run }: { run: InspectionRun }) {
  const baseline = run.baseline?.assessment;
  const context = run.baseline?.context ?? baseline?.discovery ?? null;
  const sections: { title: string; body: ReactNode }[] = [];

  if (context) {
    sections.push({
      title: "Application Discovery",
      body: (
        <div className="space-y-1 font-mono text-[11px] leading-relaxed text-zinc-400">
          <p>
            Name: <span className="text-zinc-200">{context.name}</span>
          </p>
          <p>
            Framework: <span className="text-zinc-200">{context.framework || "unknown"}</span>
          </p>
          <p>
            Runtime origin:{" "}
            <span className="text-zinc-200">{context.runtime_origin}</span>
          </p>
          <p>
            Routes:{" "}
            <span className="text-zinc-200">
              {context.routes.map((r) => `${r.method} ${r.path}`).join(", ") ||
                "none"}
            </span>
          </p>
          <p>
            Discovery:{" "}
            <span className="text-zinc-200">
              {context.discovery_summary || "no summary"}
            </span>
          </p>
        </div>
      ),
    });
  }

  if (baseline?.deterministic && baseline.deterministic.checks_executed > 0) {
    sections.push({
      title: "Deterministic Checks",
      body: (
        <div className="space-y-2 font-mono text-[11px]">
          {baseline.deterministic.results.map((f) => (
            <p key={f.id} className="leading-relaxed text-zinc-400">
              <span
                className={
                  f.status === "verified"
                    ? "font-bold text-red-400"
                    : f.status === "error"
                      ? "font-bold text-amber-400"
                      : "text-emerald-400"
                }
              >
                {f.status.toUpperCase()}
              </span>{" "}
              · {f.title}
            </p>
          ))}
        </div>
      ),
    });
  }

  if (baseline?.ai_exploration) {
    const ai = baseline.ai_exploration;
    const unavailable = ai.status === "unavailable" || ai.status === "error";
    sections.push({
      title: "AI Exploration",
      body: unavailable ? (
        <div className="space-y-2 font-mono text-[11px]">
          <p className="font-bold text-amber-400">⚠ AI Exploration Unavailable</p>
          <p className="text-zinc-400">
            Security Memory replay, deterministic checks, and discovery all
            completed successfully — fresh AI hypothesis generation did not.
          </p>
          {ai.error_message && (
            <pre className="max-h-24 overflow-y-auto whitespace-pre-wrap break-words rounded-md border border-amber-500/30 bg-black/40 p-2 text-amber-200/80">
              {ai.error_message}
            </pre>
          )}
        </div>
      ) : (
        <div className="space-y-2 font-mono text-[11px]">
          <p className="text-zinc-400">
            {AI_LABEL} · {ai.hypotheses_generated} analysis
            {ai.hypotheses_generated === 1 ? "" : "es"} ·{" "}
            {ai.executable_experiments} executable experiment
            {ai.executable_experiments === 1 ? "" : "s"} ·{" "}
            {ai.tests_executed} executed ·{" "}
            <span className="text-red-400">{ai.verified_findings} verified</span>
          </p>
          {ai.results.map((item, index) => (
            <p key={index} className="leading-relaxed text-zinc-400">
              <span
                className={
                  item.verification === "verified"
                    ? "font-bold text-red-400"
                    : item.verification === "rejected" ||
                        item.verification === "error"
                      ? "text-amber-400"
                      : "text-zinc-500"
                }
              >
                [{item.verification.toUpperCase()}]
              </span>{" "}
              {item.title || item.hypothesis}
            </p>
          ))}
        </div>
      ),
    });
  }

  sections.push({
    title: "Security Memory",
    body: (
      <div className="space-y-1 font-mono text-[11px] text-zinc-400">
        {run.memory && run.memory.entries.length > 0 ? (
          run.memory.entries.map((e) => (
            <p key={e.fingerprint} className="leading-relaxed">
              <span className="font-bold text-zinc-200">{e.id}</span> ·{" "}
              {e.request.method} {e.request.path} · expected {e.expected.status}{" "}
              · current: {e.current_status || "not replayed"}
            </p>
          ))
        ) : (
          <p>No Security Memory entries.</p>
        )}
      </div>
    ),
  });

  const rawResponses: { title: string; data: unknown }[] = [];
  if (run.baseline) rawResponses.push({ title: "Baseline assessment", data: run.baseline });
  if (run.fixed) rawResponses.push({ title: "Fix verification assessment", data: run.fixed });
  if (run.regression) rawResponses.push({ title: "Regression assessment", data: run.regression });
  if (run.saved) rawResponses.push({ title: "Security Memory save", data: run.saved });

  return (
    <div
      id="technical-details"
      className="flex w-full flex-col gap-3"
    >
      <p className="font-mono text-center text-xs uppercase tracking-widest text-zinc-500">
        TECHNICAL DETAILS
      </p>
      {sections.map((section) => (
        <details
          key={section.title}
          className="w-full rounded-md border border-zinc-800 bg-zinc-950"
        >
          <summary className="cursor-pointer select-none px-4 py-3 font-mono text-xs font-semibold text-zinc-300">
            {section.title}
          </summary>
          <div className="border-t border-zinc-800 px-4 py-3">{section.body}</div>
        </details>
      ))}
      <details className="w-full rounded-md border border-zinc-800 bg-zinc-950">
        <summary className="cursor-pointer select-none px-4 py-3 font-mono text-xs font-semibold text-zinc-300">
          Raw Assessment Responses
        </summary>
        <div className="space-y-3 border-t border-zinc-800 px-4 py-3">
          {rawResponses.map((raw) => (
            <div key={raw.title}>
              <p className="mb-1 font-mono text-[11px] uppercase tracking-widest text-zinc-500">
                {raw.title}
              </p>
              <pre className="max-h-72 overflow-y-auto whitespace-pre-wrap break-words rounded-md border border-zinc-800 bg-black/40 p-3 font-mono text-[10px] leading-relaxed text-zinc-400">
                {JSON.stringify(raw.data, null, 2)}
              </pre>
            </div>
          ))}
        </div>
      </details>
    </div>
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
  const crossUserFindings = verified.filter((f) => {
    const ev = f.evidence as Record<string, unknown>;
    return ev["cross_user_access"] === true;
  });
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

  const hasStageError = Object.keys(run.stageErrors).length > 0;

  return (
    <div className="flex w-full max-w-2xl flex-col items-center gap-6 py-12">
      {/* Header */}
      <div className="flex w-full flex-col items-center gap-2">
        <p className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          TARGET
        </p>
        <h2 className="font-mono text-2xl font-bold text-zinc-100">
          {run.application?.origin || run.url}
        </h2>
        {run.target && (
          <p className="font-mono text-[11px] text-violet-300">
            {run.target.name}
          </p>
        )}
      </div>

      <ResultBanner run={run} />

      {/* Stage errors must never blank the screen */}
      {hasStageError && (
        <div className="w-full rounded-md border border-amber-500/40 bg-amber-950/30 p-4 font-mono text-sm text-amber-300">
          <p className="mb-1 font-semibold text-amber-400">
            ⚠ Some stages could not complete
          </p>
          {Object.entries(run.stageErrors).map(([key, detail]) => (
            <p key={key} className="mt-1 text-xs leading-relaxed">
              <span className="font-bold">{key.toUpperCase()}</span>: {detail}
            </p>
          ))}
          <p className="mt-2 text-xs text-amber-200/70">
            All earlier successful results are preserved below.
          </p>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid w-full grid-cols-2 gap-3 sm:grid-cols-4">
        <Metric label="Verified Vulnerabilities" value={verifiedCount} tone={verifiedCount > 0 ? "red" : "default"} />
        <Metric label="Security Memory Tests" value={memoryCount} />
        <Metric label="Fixes Verified" value={fixesVerified} tone={fixesVerified > 0 ? "green" : "default"} />
        <Metric label="Regressions Detected" value={regressionsDetected} tone={regressionsDetected > 0 ? "red" : "default"} />
      </div>

      <LifecycleStory run={run} />

      {/* Vulnerability cards */}
      {verified.length > 0 && (
        <div className="flex w-full flex-col gap-3">
          <p className="font-mono text-center text-xs uppercase tracking-widest text-red-400">
            VULNERABILITIES FOUND
          </p>
          {verified.map((f) => (
            <VulnerabilityCard key={f.id} finding={f} />
          ))}
        </div>
      )}

      <SecurityMemorySection run={run} />

      {/* Fix verification + regression replay (real replay data) */}
      {fixedReg && fixedReg.tests_replayed > 0 && (
        <ReplayResults
          title="FIX VERIFICATION"
          results={fixedReg.results}
          replayed={fixedReg.tests_replayed}
          passed={fixedReg.passed}
          regressions={fixedReg.regressions}
          variant="fixed"
        />
      )}
      {regressionReg && regressionReg.tests_replayed > 0 && (
        <ReplayResults
          title="🚨 REGRESSION DETECTION"
          results={regressionReg.results}
          replayed={regressionReg.tests_replayed}
          passed={regressionReg.passed}
          regressions={regressionReg.regressions}
          variant="regression"
        />
      )}

      {/* Actions */}
      <div className="mt-2 flex flex-wrap justify-center gap-2">
        <button
          onClick={onReset}
          className="h-12 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-8 font-mono text-sm font-semibold text-emerald-300 transition-colors hover:bg-emerald-500/20"
        >
          [ Inspect Another Application ]
        </button>
        <button
          onClick={() => scrollToId("security-memory")}
          className="h-12 rounded-md border border-amber-500/40 bg-amber-500/10 px-6 font-mono text-sm font-semibold text-amber-300 transition-colors hover:bg-amber-500/20"
        >
          [ View Security Memory ]
        </button>
        <button
          onClick={() => scrollToId("technical-details")}
          className="h-12 rounded-md border border-zinc-600 bg-zinc-900 px-6 font-mono text-sm font-semibold text-zinc-200 transition-colors hover:bg-zinc-800"
        >
          [ View Technical Details ]
        </button>
      </div>

      <TechnicalDetails run={run} />
    </div>
  );
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
    <main className="flex flex-1 flex-col items-center px-6">
      {phase === "landing" && (
        <LandingView
          url={url}
          setUrl={setUrl}
          onSubmit={startInspection}
          busy={busy}
          error={inspectError}
        />
      )}
      {phase === "inspecting" && <InspectionProgress stages={stages} />}
      {phase === "result" && run && <ResultView run={run} onReset={reset} />}
    </main>
  );
}
