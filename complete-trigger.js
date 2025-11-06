/**
 * complete-trigger.js
 * A self-contained detection trigger + catalog module with:
 * - Feature Breakdown dataset (Category, Main Type, Sub-Type/Components, Features/Functions, Purpose/Goal, Example Tools/Systems, Metrics/Evidence)
 * - Markdown/CSV/JSON exporters
 * - Pluggable trigger adapters (SIEM, Telemetry, SOAR)
 * - Synthetic event generators for "trigger all our detections"
 *
 * Works in Node and modern browsers (UMD-style export at bottom).
 */

/** @typedef {Object} FeatureRow
 * @property {string} category
 * @property {string} mainType
 * @property {string} subTypeComponents
 * @property {string} featuresFunctions
 * @property {string} purposeGoal
 * @property {string} exampleToolsSystems
 * @property {string} metricsEvidence
 */

/** =========================
 * 1) FEATURE BREAKDOWN DATA
 * =========================*/
const FEATURE_BREAKDOWN /** @type {FeatureRow[]} */ = [
  {
    category: "Detection Control",
    mainType: "Event Triggers",
    subTypeComponents: "Rule-based, Behavior-based, Anomaly-based, Signature-based",
    featuresFunctions: "Manual or automated firing of detection rules",
    purposeGoal: "Verify rule activation & coverage",
    exampleToolsSystems: "Sigma, Falco, Suricata, Zeek",
    metricsEvidence: "Detection coverage %, rule execution logs",
  },
  {
    category: "Threat Simulation",
    mainType: "Synthetic Attack Generator",
    subTypeComponents: "Atomic Red Team, MITRE ATT&CK TTP injector, Fuzzer",
    featuresFunctions: "Simulate attacker behavior to test alerts",
    purposeGoal: "Validate detection fidelity",
    exampleToolsSystems: "Atomic Red Team, Infection Monkey, Caldera",
    metricsEvidence: "TTP coverage matrix, detection delta",
  },
  {
    category: "SIEM Integration",
    mainType: "Log Collection & Correlation",
    subTypeComponents: "Syslog, OTEL, FluentBit, ELK, Splunk, Loki",
    featuresFunctions: "Aggregate detection logs from multiple sources",
    purposeGoal: "Ensure all sources feed into SOC",
    exampleToolsSystems: "ELK stack, Grafana Loki",
    metricsEvidence: "Log ingestion rate, alert forwarding rate",
  },
  {
    category: "Security Telemetry",
    mainType: "Endpoint & Network Sensors",
    subTypeComponents: "Agent-based (OSQuery), Network taps, Kernel probes",
    featuresFunctions: "Observe all runtime layers (syscalls, APIs, network)",
    purposeGoal: "Validate visibility completeness",
    exampleToolsSystems: "OSQuery, eBPF, Falco, OpenTelemetry",
    metricsEvidence: "% event types observed, missing signal map",
  },
  {
    category: "Alert Pipeline",
    mainType: "Alert Routing & Enrichment",
    subTypeComponents: "Enrich, deduplicate, correlate alerts",
    featuresFunctions: "Add context (user, asset, severity, MITRE tag)",
    purposeGoal: "Produce actionable alerts",
    exampleToolsSystems: "ElastAlert, Prometheus Alertmanager",
    metricsEvidence: "MTTA (Mean Time to Alert), enrichment success rate",
  },
  {
    category: "Detection Testing",
    mainType: "Regression & Validation Tests",
    subTypeComponents: "Unit, Integration, System, Red vs Blue tests",
    featuresFunctions: "Validate detection logic after code/policy changes",
    purposeGoal: "Prevent silent alert failures",
    exampleToolsSystems: "pytest, cargo-test, k6, GoTest",
    metricsEvidence: "% rules firing after update, false-negative rate",
  },
  {
    category: "Detection Coverage Mapping",
    mainType: "MITRE ATT&CK Mapping",
    subTypeComponents: "Enterprise, Cloud, Container, Blockchain matrix",
    featuresFunctions: "Map detections to ATT&CK techniques",
    purposeGoal: "Measure completeness of coverage",
    exampleToolsSystems: "ATT&CK Navigator, Sigma2ATT&CK",
    metricsEvidence: "% TTP coverage, duplicate rules",
  },
  {
    category: "Response Simulation",
    mainType: "Alert Response Triggers",
    subTypeComponents: "Runbooks, SOAR playbooks, automated response",
    featuresFunctions: "Trigger the whole detection-to-response chain",
    purposeGoal: "Validate SOC readiness",
    exampleToolsSystems: "Cortex XSOAR, Shuffle, StackStorm",
    metricsEvidence: "End-to-end response success rate",
  },
  {
    category: "Metrics Collection",
    mainType: "Detection Efficacy Metrics",
    subTypeComponents: "Precision, Recall, Latency, Noise ratio",
    featuresFunctions: "Evaluate detection quality",
    purposeGoal: "Reduce false positives & misses",
    exampleToolsSystems: "Prometheus, Grafana, ELK metrics",
    metricsEvidence: "FPR, FNR, latency ms, event volume",
  },
  {
    category: "Forensics & Replay",
    mainType: "Event Replay & Audit",
    subTypeComponents: "Replay historic logs to re-test new rules",
    featuresFunctions: "Ensure new rules detect past attacks",
    purposeGoal: "Elastic Replay, Zeek, Loki",
    exampleToolsSystems: "Elastic Replay, Zeek, Loki",
    metricsEvidence: "# retroactive detections, replay fidelity",
  },
  {
    category: "CI/CD Integration",
    mainType: "Security Gates & Hooks",
    subTypeComponents: "“Detection smoke tests” in CI",
    featuresFunctions: "Auto-trigger detections per deployment",
    purposeGoal: "Guarantee continuous readiness",
    exampleToolsSystems: "GitHub Actions, OPA, Kyverno",
    metricsEvidence: "CI gate pass/fail, alert webhook trigger",
  },
  {
    category: "Detection Inventory",
    mainType: "Ruleset Cataloging",
    subTypeComponents: "Inventory of all active detections",
    featuresFunctions: "Centralize and version detection logic",
    purposeGoal: "Prevent rule drift & duplication",
    exampleToolsSystems: "GitOps repo, YAML rulesets",
    metricsEvidence: "Ruleset version, drift delta",
  },
  {
    category: "AI/ML-Enhanced Detection",
    mainType: "Anomaly Models",
    subTypeComponents: "Statistical, ML, LSTM, Transformer models",
    featuresFunctions: "Generate synthetic anomalies to trigger ML alerts",
    purposeGoal: "Test model adaptability",
    exampleToolsSystems: "PyOD, Grafana Mimir, Loki ML",
    metricsEvidence: "Model retraining success, drift %",
  },
  {
    category: "Blockchain & Smart-Contract Detection",
    mainType: "On-chain Triggers",
    subTypeComponents: "Reentrancy, price manipulation, governance events",
    featuresFunctions: "Simulate malicious transactions to trigger monitors",
    purposeGoal: "Ensure DeFi/Web3 SOC coverage",
    exampleToolsSystems: "Forta, Tenderly, EigenLayer Watchers",
    metricsEvidence: "# triggered alerts per contract event",
  },
  {
    category: "User Behavior Analytics (UBA)",
    mainType: "Identity-based Detection",
    subTypeComponents: "Credential misuse, privilege escalation",
    featuresFunctions: "Simulate abnormal login or token use",
    purposeGoal: "Verify IAM anomaly alerts",
    exampleToolsSystems: "UEBA engine, OpenSearch Dashboards",
    metricsEvidence: "% user anomalies caught",
  },
  {
    category: "Deception / Honeypot",
    mainType: "Trap Triggers",
    subTypeComponents: "Fake APIs, wallets, nodes",
    featuresFunctions: "Trigger decoy events",
    purposeGoal: "Test lateral movement detections",
    exampleToolsSystems: "Canarytokens, HoneyDB",
    metricsEvidence: "# traps triggered, attacker dwell time",
  },
  {
    category: "Testing Automation",
    mainType: "Chaos / Fault Injection",
    subTypeComponents: "Drop logs, corrupt telemetry, delay events",
    featuresFunctions: "Verify alert pipeline resilience",
    purposeGoal: "Ensure fault-tolerant detection flow",
    exampleToolsSystems: "Chaos Mesh, Gremlin",
    metricsEvidence: "% alerts lost during fault test",
  },
  {
    category: "Audit & Evidence",
    mainType: "Compliance Verification",
    subTypeComponents: "SOC2, ISO, NIST control mapping",
    featuresFunctions: "Prove detection system operational",
    purposeGoal: "Satisfy governance & audit",
    exampleToolsSystems: "OPA, Evidence.dev",
    metricsEvidence: "Audit report, detection attestation",
  },
];

/** =========================
 * 2) RENDER / EXPORT HELPERS
 * =========================*/

/** Render the dataset as a Markdown table. */
function toMarkdownTable(rows = FEATURE_BREAKDOWN) {
  const header = [
    "Category",
    "Main Type",
    "Sub-Type / Components",
    "Features / Functions",
    "Purpose / Goal",
    "Example Tools / Systems",
    "Metrics / Evidence",
  ];
  const sep = header.map(() => "---");
  const lines = [];
  lines.push(`| ${header.join(" | ")} |`);
  lines.push(`| ${sep.join(" | ")} |`);
  for (const r of rows) {
    lines.push(
      `| ${r.category} | ${r.mainType} | ${r.subTypeComponents} | ${r.featuresFunctions} | ${r.purposeGoal} | ${r.exampleToolsSystems} | ${r.metricsEvidence} |`
    );
  }
  return lines.join("\n");
}

/** Convert the dataset to CSV (RFC4180-friendly enough). */
function toCSV(rows = FEATURE_BREAKDOWN) {
  const esc = (v) =>
    `"${String(v ?? "").replace(/"/g, '""').replace(/\r?\n/g, " ")}"`;
  const header = [
    "Category",
    "Main Type",
    "Sub-Type / Components",
    "Features / Functions",
    "Purpose / Goal",
    "Example Tools / Systems",
    "Metrics / Evidence",
  ];
  const lines = [header.map(esc).join(",")];
  for (const r of rows) {
    lines.push(
      [
        r.category,
        r.mainType,
        r.subTypeComponents,
        r.featuresFunctions,
        r.purposeGoal,
        r.exampleToolsSystems,
        r.metricsEvidence,
      ].map(esc).join(",")
    );
  }
  return lines.join("\n");
}

/** Export as JSON string. */
function toJSON(rows = FEATURE_BREAKDOWN, space = 2) {
  return JSON.stringify(rows, null, space);
}

/** ==========================================
 * 3) TRIGGER ENGINE (SYNTHETIC DETECTION RUNS)
 * ==========================================*/

/**
 * Adapters let you wire in your own stack (ELK/Loki/Splunk, Falco/Sigma, Forta/Tenderly, SOAR, etc.)
 * Provide functions: log(), alert(), enrich(), respond(), metric().
 *
 * Default NO-OP adapter logs to console to be safe everywhere.
 */
function createDefaultAdapters() {
  return {
    siem: {
      /** @param {object} payload */ log: (payload) =>
        console.log("[SIEM] log", payload),
      /** @param {object} alert */ alert: (alert) =>
        console.log("[SIEM] alert", alert),
    },
    telemetry: {
      /** @param {object} event */ send: (event) =>
        console.log("[Telemetry] event", event),
    },
    soar: {
      /** @param {object} ctx */ runbook: (ctx) =>
        console.log("[SOAR] runbook", ctx),
    },
    metrics: {
      /** @param {string} name @param {number} value @param {object} labels */
      record: (name, value, labels = {}) =>
        console.log("[Metrics]", name, value, labels),
    },
    enrich: {
      /** @param {object} alert */ withContext: (alert) => ({
        ...alert,
        enriched: true,
        tags: ["MITRE:Txxxx", "sev:medium"],
      }),
    },
  };
}

/** Simple ID helper */
const uid = () =>
  Math.random().toString(36).slice(2) + Date.now().toString(36);

/** Synthetic event builders per category (minimal but extensible). */
const Generators = {
  eventTrigger: () => ({
    id: uid(),
    kind: "rule.fire",
    ruleType: "signature",
    ruleName: "test_rule_signature_http_401",
    ts: new Date().toISOString(),
    details: { http_status: 401, path: "/api/test" },
  }),
  ttpSimulation: () => ({
    id: uid(),
    kind: "ttp",
    technique: "T1190 Exploit Public-Facing App",
    phase: "initial-access",
    ts: new Date().toISOString(),
    details: { payload: "synthetic", success: true },
  }),
  siemLog: () => ({
    id: uid(),
    kind: "siem.log",
    source: "app",
    level: "warn",
    message: "synthetic warning log",
    ts: new Date().toISOString(),
  }),
  telemetryEvent: () => ({
    id: uid(),
    kind: "telemetry",
    component: "gateway",
    signal: "latency_ms",
    value: Math.floor(50 + Math.random() * 200),
    ts: new Date().toISOString(),
  }),
  alertPipeline: () => ({
    id: uid(),
    kind: "alert",
    severity: "medium",
    title: "Synthetic anomaly detected",
    ts: new Date().toISOString(),
  }),
  replayEvent: () => ({
    id: uid(),
    kind: "replay",
    source: "historical-index",
    ruleCandidate: "new_sql_injection_rule",
    ts: new Date().toISOString(),
  }),
  onchainTrigger: () => ({
    id: uid(),
    kind: "onchain",
    chain: "ethereum",
    event: "governanceVoteQueued",
    contract: "0x0000000000000000000000000000000000000000",
    txHash: "0x" + "ab".repeat(32),
    ts: new Date().toISOString(),
  }),
  ueba: () => ({
    id: uid(),
    kind: "identity",
    anomaly: "impossible-travel",
    user: "synthetic-user@example.com",
    ts: new Date().toISOString(),
  }),
  honeypot: () => ({
    id: uid(),
    kind: "honeypot",
    decoy: "fake-admin-endpoint",
    action: "credential-attempt",
    ts: new Date().toISOString(),
  }),
  chaosFault: () => ({
    id: uid(),
    kind: "chaos",
    fault: "drop-5%-logs",
    duration_s: 30,
    ts: new Date().toISOString(),
  }),
  compliance: () => ({
    id: uid(),
    kind: "audit",
    mapping: ["SOC2:CC7.2", "NIST:AU-6"],
    ts: new Date().toISOString(),
  }),
};

/**
 * Trigger plan mapping the dataset to generator functions + adapter actions.
 * Extend/replace freely to match your stack.
 */
const TRIGGER_PLAN = [
  { key: "Detection Control / Event Triggers", gen: Generators.eventTrigger },
  { key: "Threat Simulation / Synthetic Attack", gen: Generators.ttpSimulation },
  { key: "SIEM Integration / Log Correlation", gen: Generators.siemLog },
  { key: "Security Telemetry / Sensors", gen: Generators.telemetryEvent },
  { key: "Alert Pipeline / Enrichment", gen: Generators.alertPipeline },
  { key: "Forensics & Replay / Audit", gen: Generators.replayEvent },
  { key: "Blockchain & Smart-Contract / On-chain", gen: Generators.onchainTrigger },
  { key: "UBA / Identity-based", gen: Generators.ueba },
  { key: "Deception / Honeypot", gen: Generators.honeypot },
  { key: "Testing Automation / Chaos", gen: Generators.chaosFault },
  { key: "Audit & Evidence / Compliance", gen: Generators.compliance },
];

/**
 * Trigger a single synthetic artifact end-to-end.
 * - Sends telemetry/logs to adapters
 * - Enriches alerts
 * - Emits SIEM alert
 * - Records a metric
 */
async function triggerOne(adapters, planItem) {
  const { siem, telemetry, soar, metrics, enrich } = adapters;
  const ev = planItem.gen();

  // 1) Raw telemetry/log
  telemetry.send({ ...ev, stage: "raw" });

  // 2) If it's an alert-able signal, enrich + alert
  if (ev.kind === "alert" || ev.kind === "onchain" || ev.kind === "identity" || ev.kind === "honeypot") {
    const enriched = enrich.withContext({
      id: ev.id,
      severity: ev.severity || "medium",
      title: ev.title || `Synthetic ${ev.kind} signal`,
      details: ev,
      ts: ev.ts,
    });
    siem.alert(enriched);
    // 3) SOAR runbook (simulation)
    soar.runbook({ alertId: enriched.id, title: enriched.title, severity: enriched.severity });
  } else {
    // Non-alert signals go as normal logs
    siem.log(ev);
  }

  // 4) Record a small success metric
  metrics.record("detection_trigger_fired_total", 1, { key: planItem.key, kind: ev.kind });

  return ev;
}

/**
 * Trigger all detections across the plan.
 * @param {object} customAdapters optional adapter overrides
 * @returns {Promise<object[]>} list of synthetic events produced
 */
async function triggerAllDetections(customAdapters = {}) {
  const adapters = { ...createDefaultAdapters(), ...customAdapters };
  const results = [];
  for (const item of TRIGGER_PLAN) {
    const ev = await triggerOne(adapters, item);
    results.push({ key: item.key, event: ev });
  }
  return results;
}

/** =========================
 * 4) PUBLIC API
 * =========================*/
const CompleteTrigger = {
  data: FEATURE_BREAKDOWN,
  toMarkdownTable,
  toCSV,
  toJSON,
  triggerAllDetections,
  createDefaultAdapters,
  Generators,
  TRIGGER_PLAN,
};

/** =========================
 * 5) CLI BEHAVIOR (Node only)
 * =========================*/
if (typeof module !== "undefined" && require.main === module) {
  const fs = require("fs");
  console.log("\n# Complete Feature Breakdown (Markdown)\n");
  console.log(toMarkdownTable(FEATURE_BREAKDOWN));
  const csv = toCSV(FEATURE_BREAKDOWN);
  fs.writeFileSync("complete-trigger.csv", csv, "utf8");
  console.log('\nWrote CSV -> complete-trigger.csv');
  console.log("\nTriggering all detections (synthetic, console adapters)...\n");

  triggerAllDetections().then((events) => {
    console.log(`\nTriggered ${events.length} synthetic detections.`);
  });
}

/** =========================
 * 6) UMD EXPORT
 * =========================*/
(function (root, factory) {
  if (typeof module === "object" && typeof module.exports === "object") {
    module.exports = factory();
  } else if (typeof define === "function" && define.amd) {
    define([], factory);
  } else {
    root.CompleteTrigger = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  return CompleteTrigger;
});
