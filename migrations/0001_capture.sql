CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE builds (
    build_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    backend TEXT,
    platform TEXT,
    architecture TEXT,
    unity_version TEXT,
    created_by_run_id TEXT NOT NULL
);

CREATE TABLE external_build_refs (
    external_build_ref_id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    evidence_ref TEXT
);

CREATE TABLE snapshots (
    snapshot_id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    selection_id TEXT NOT NULL,
    selection_sha256 TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    manifest_logical_path TEXT NOT NULL,
    imported_from TEXT,
    UNIQUE(manifest_sha256)
);

CREATE TABLE capture_rules (
    capture_rule_id TEXT PRIMARY KEY,
    selection_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('payload', 'inventory_only')),
    feature TEXT,
    selector TEXT NOT NULL
);

CREATE TABLE input_objects (
    input_object_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    storage_path TEXT NOT NULL
);

CREATE TABLE input_files (
    input_file_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    logical_path TEXT NOT NULL,
    input_object_id TEXT REFERENCES input_objects(input_object_id),
    identity_contribution TEXT NOT NULL,
    UNIQUE(snapshot_id, logical_path)
);

CREATE TABLE capture_observations (
    capture_observation_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    capture_rule_id TEXT,
    feature TEXT,
    mode TEXT NOT NULL CHECK(mode IN ('payload', 'inventory_only')),
    logical_path TEXT NOT NULL,
    presence TEXT NOT NULL,
    input_object_id TEXT REFERENCES input_objects(input_object_id),
    bounded_metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE input_candidates (
    input_candidate_id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    logical_path TEXT NOT NULL,
    discovery_source TEXT NOT NULL,
    inspected_zone TEXT,
    bounded_metadata_json TEXT NOT NULL DEFAULT '{}',
    review_status TEXT NOT NULL DEFAULT 'needs_review',
    UNIQUE(snapshot_id, logical_path, discovery_source)
);

CREATE TABLE components (
    component_id TEXT PRIMARY KEY,
    logical_name TEXT NOT NULL,
    component_kind TEXT NOT NULL
);

CREATE TABLE component_revisions (
    component_revision_id TEXT PRIMARY KEY,
    component_id TEXT NOT NULL REFERENCES components(component_id),
    content_sha256 TEXT,
    source_artifact_id TEXT,
    provenance_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE build_components (
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    role TEXT NOT NULL,
    PRIMARY KEY(build_id, component_revision_id, role)
);

