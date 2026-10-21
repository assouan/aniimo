CREATE TABLE analysis_runs (
    analysis_id TEXT PRIMARY KEY,
    workflow_run_id TEXT NOT NULL UNIQUE,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    analysis_key TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT
);

CREATE TABLE stage_runs (
    stage_run_id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    step_id TEXT NOT NULL,
    parent_step_id TEXT,
    stage_name TEXT NOT NULL,
    substep_name TEXT,
    component_id TEXT,
    status TEXT NOT NULL,
    reason TEXT,
    cache_status TEXT NOT NULL,
    tool_name TEXT,
    tool_version TEXT,
    started_at TEXT,
    ended_at TEXT,
    duration_ms REAL NOT NULL,
    input_item_count INTEGER NOT NULL DEFAULT 0,
    input_bytes INTEGER NOT NULL DEFAULT 0,
    output_item_count INTEGER NOT NULL DEFAULT 0,
    output_bytes INTEGER NOT NULL DEFAULT 0,
    cpu_time_ms REAL,
    peak_rss_bytes INTEGER,
    error_code TEXT
);

CREATE TABLE stage_inputs (
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    input_kind TEXT NOT NULL,
    input_id TEXT NOT NULL,
    input_digest TEXT,
    PRIMARY KEY(stage_run_id, input_kind, input_id)
);

CREATE TABLE stage_outputs (
    stage_run_id TEXT NOT NULL REFERENCES stage_runs(stage_run_id),
    output_kind TEXT NOT NULL,
    output_id TEXT NOT NULL,
    output_digest TEXT NOT NULL,
    PRIMARY KEY(stage_run_id, output_kind, output_id)
);

CREATE TABLE cache_entries (
    cache_key TEXT PRIMARY KEY,
    stage_name TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    artifact_logical_path TEXT NOT NULL,
    producer_name TEXT NOT NULL,
    producer_version TEXT NOT NULL,
    context_json TEXT NOT NULL,
    created_by_analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id)
);

CREATE TABLE toolchains (
    toolchain_id TEXT PRIMARY KEY,
    lock_sha256 TEXT NOT NULL,
    image_digest_capture TEXT,
    image_digest_analyzer TEXT,
    tools_json TEXT NOT NULL
);

CREATE TABLE snapshot_handoffs (
    handoff_id TEXT PRIMARY KEY,
    workflow_run_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    manifest_sha256 TEXT NOT NULL,
    slot TEXT NOT NULL,
    status TEXT NOT NULL,
    record_logical_path TEXT NOT NULL
);

CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    snapshot_id TEXT REFERENCES snapshots(snapshot_id),
    evidence_kind TEXT NOT NULL,
    source_logical_path TEXT,
    details_json TEXT NOT NULL
);

CREATE TABLE ownership_claims (
    ownership_claim_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    ownership TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE scope_decisions (
    scope_decision_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('game_decompile', 'reference_only', 'excluded', 'needs_review')),
    reason TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    UNIQUE(snapshot_id, subject_kind, subject_id)
);

CREATE TABLE scope_exceptions (
    scope_exception_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    subject_id TEXT NOT NULL,
    justification TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL
);

CREATE INDEX stage_runs_analysis_idx ON stage_runs(analysis_id);
CREATE INDEX input_files_snapshot_idx ON input_files(snapshot_id);
CREATE INDEX scope_decisions_snapshot_idx ON scope_decisions(snapshot_id);

