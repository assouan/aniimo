CREATE TABLE dependency_fingerprints (
    dependency_fingerprint_id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    native_body_id TEXT NOT NULL REFERENCES native_bodies(native_body_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    algorithm_version TEXT NOT NULL,
    raw_body_hash TEXT,
    strict_semantic_hash TEXT,
    semantic_operands_hash TEXT,
    signature_hash TEXT,
    layout_hash TEXT,
    call_targets_hash TEXT,
    referenced_data_hash TEXT,
    reference_context_hash TEXT,
    completeness TEXT NOT NULL CHECK(completeness IN ('complete', 'partial', 'unknown')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(build_id, native_body_id, algorithm_version)
);

CREATE TABLE build_comparisons (
    comparison_id TEXT PRIMARY KEY,
    comparison_key TEXT NOT NULL UNIQUE,
    source_build_id TEXT NOT NULL REFERENCES builds(build_id),
    destination_build_id TEXT NOT NULL REFERENCES builds(build_id),
    analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    producer_digest TEXT NOT NULL,
    annotation_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('completed', 'partial', 'failed')),
    output_manifest_sha256 TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE matches (
    match_id TEXT PRIMARY KEY,
    comparison_id TEXT NOT NULL REFERENCES build_comparisons(comparison_id),
    source_symbol_id TEXT REFERENCES symbols(symbol_id),
    destination_symbol_id TEXT REFERENCES symbols(symbol_id),
    source_native_body_id TEXT REFERENCES native_bodies(native_body_id),
    destination_native_body_id TEXT REFERENCES native_bodies(native_body_id),
    match_method TEXT NOT NULL CHECK(match_method IN (
        'persistent_symbol_identity', 'managed_signature_identity',
        'reviewed_annotation',
        'unique_observed_name_candidate', 'raw_body_hash_candidate',
        'bsim_candidate', 'unmatched'
    )),
    match_status TEXT NOT NULL CHECK(match_status IN (
        'confirmed', 'candidate', 'conflict', 'rejected', 'unmatched'
    )),
    score REAL,
    review_required INTEGER NOT NULL CHECK(review_required IN (0, 1)),
    evidence_json TEXT NOT NULL,
    contradictions_json TEXT NOT NULL DEFAULT '[]',
    alternatives_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE match_reviews (
    match_review_id TEXT PRIMARY KEY,
    comparison_id TEXT NOT NULL REFERENCES build_comparisons(comparison_id),
    source_symbol_id TEXT NOT NULL REFERENCES symbols(symbol_id),
    destination_symbol_id TEXT NOT NULL REFERENCES symbols(symbol_id),
    decision TEXT NOT NULL CHECK(decision IN ('confirmed', 'rejected')),
    reason TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    annotation_digest TEXT NOT NULL
);

CREATE TABLE annotations (
    annotation_id TEXT PRIMARY KEY,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    annotation_kind TEXT NOT NULL,
    applicability_json TEXT NOT NULL,
    value_json TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    author TEXT NOT NULL,
    annotation_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(subject_kind, subject_id, annotation_kind, annotation_digest)
);

CREATE TABLE comparison_changes (
    comparison_change_id TEXT PRIMARY KEY,
    comparison_id TEXT NOT NULL REFERENCES build_comparisons(comparison_id),
    match_id TEXT REFERENCES matches(match_id),
    source_symbol_id TEXT REFERENCES symbols(symbol_id),
    destination_symbol_id TEXT REFERENCES symbols(symbol_id),
    source_native_body_id TEXT REFERENCES native_bodies(native_body_id),
    destination_native_body_id TEXT REFERENCES native_bodies(native_body_id),
    change_flags_json TEXT NOT NULL,
    invalidation_status TEXT NOT NULL CHECK(invalidation_status IN (
        'unchanged', 'invalidated', 'requires_review', 'not_applicable'
    )),
    invalidation_reasons_json TEXT NOT NULL,
    dependency_evidence_json TEXT NOT NULL
);

CREATE TABLE documentation_outputs (
    documentation_output_id TEXT PRIMARY KEY,
    comparison_id TEXT NOT NULL REFERENCES build_comparisons(comparison_id),
    subject_id TEXT NOT NULL,
    dependency_digest TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    UNIQUE(comparison_id, subject_id, relative_path)
);

CREATE INDEX dependency_fingerprints_build_idx
    ON dependency_fingerprints(build_id, native_body_id);
CREATE INDEX matches_comparison_source_idx
    ON matches(comparison_id, source_symbol_id);
CREATE INDEX matches_comparison_destination_idx
    ON matches(comparison_id, destination_symbol_id);
CREATE INDEX comparison_changes_comparison_idx
    ON comparison_changes(comparison_id, invalidation_status);
CREATE INDEX documentation_outputs_comparison_idx
    ON documentation_outputs(comparison_id, subject_id);
CREATE INDEX annotations_subject_idx
    ON annotations(subject_kind, subject_id, annotation_kind);
