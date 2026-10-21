CREATE TABLE symbols (
    symbol_id TEXT PRIMARY KEY,
    symbol_kind TEXT NOT NULL CHECK(symbol_kind IN ('managed_method', 'native_function', 'lua_binding')),
    created_at TEXT NOT NULL
);

CREATE TABLE symbol_observations (
    symbol_observation_id TEXT PRIMARY KEY,
    symbol_id TEXT NOT NULL REFERENCES symbols(symbol_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    observed_name TEXT,
    namespace TEXT,
    native_entry_rva INTEGER,
    managed_signature TEXT,
    signature_key TEXT,
    static_kind TEXT,
    body_resolution_status TEXT NOT NULL CHECK(body_resolution_status IN (
        'resolved', 'shared', 'abstract', 'external', 'stripped', 'inlined',
        'unresolved', 'not_applicable'
    )),
    provenance_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE native_bodies (
    native_body_id TEXT PRIMARY KEY,
    first_seen_component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    created_at TEXT NOT NULL
);

CREATE TABLE body_observations (
    body_observation_id TEXT PRIMARY KEY,
    native_body_id TEXT NOT NULL REFERENCES native_bodies(native_body_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    module_logical_path TEXT NOT NULL,
    module_sha256 TEXT NOT NULL,
    architecture TEXT NOT NULL,
    file_format TEXT NOT NULL,
    rva INTEGER NOT NULL CHECK(rva >= 0),
    file_offset INTEGER,
    preferred_va TEXT,
    raw_body_hash TEXT,
    relocation_normalized_hash TEXT,
    body_output_status TEXT NOT NULL CHECK(body_output_status IN (
        'c_and_asm', 'asm_only', 'disassembly_failed', 'pending'
    )),
    discovery_origin TEXT NOT NULL,
    scope_decision TEXT NOT NULL CHECK(scope_decision IN (
        'game_decompile', 'reference_only', 'excluded', 'needs_review'
    )),
    diagnostic TEXT,
    asm_artifact_sha256 TEXT,
    c_artifact_sha256 TEXT,
    instruction_count INTEGER NOT NULL DEFAULT 0 CHECK(instruction_count >= 0),
    body_byte_count INTEGER NOT NULL DEFAULT 0 CHECK(body_byte_count >= 0),
    decompiler_context_hash TEXT NOT NULL,
    reference_context_hash TEXT NOT NULL,
    UNIQUE(build_id, component_revision_id, rva)
);

CREATE TABLE native_prototypes (
    native_prototype_id TEXT PRIMARY KEY,
    native_body_id TEXT NOT NULL REFERENCES native_bodies(native_body_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    architecture TEXT NOT NULL,
    abi TEXT NOT NULL,
    entrypoint_role TEXT NOT NULL,
    calling_convention TEXT,
    prototype_text TEXT,
    provenance TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE native_body_attempts (
    native_body_attempt_id TEXT PRIMARY KEY,
    native_body_id TEXT NOT NULL REFERENCES native_bodies(native_body_id),
    analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    attempt_key TEXT NOT NULL UNIQUE,
    body_output_status TEXT NOT NULL CHECK(body_output_status IN (
        'c_and_asm', 'asm_only', 'disassembly_failed', 'pending'
    )),
    budget_class TEXT NOT NULL,
    context_json TEXT NOT NULL,
    diagnostic TEXT,
    warnings_json TEXT NOT NULL DEFAULT '[]',
    asm_artifact_sha256 TEXT,
    c_artifact_sha256 TEXT,
    cache_status TEXT NOT NULL CHECK(cache_status IN ('hit', 'miss', 'not_applicable')),
    created_at TEXT NOT NULL
);

CREATE TABLE symbol_body_links (
    symbol_body_link_id TEXT PRIMARY KEY,
    symbol_id TEXT NOT NULL REFERENCES symbols(symbol_id),
    native_body_id TEXT REFERENCES native_bodies(native_body_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    entrypoint_role TEXT NOT NULL,
    generic_context TEXT,
    body_resolution_status TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(symbol_id, build_id, component_revision_id, entrypoint_role)
);

CREATE TABLE native_references (
    native_reference_id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    source_native_body_id TEXT NOT NULL REFERENCES native_bodies(native_body_id),
    reference_kind TEXT NOT NULL,
    source_instruction_rva INTEGER NOT NULL,
    target_raw TEXT,
    target_rva INTEGER,
    target_native_body_id TEXT REFERENCES native_bodies(native_body_id),
    resolution_status TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE unresolved_code_regions (
    unresolved_code_region_id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    region_kind TEXT NOT NULL CHECK(region_kind IN (
        'unattributed_executable_range', 'unconfirmed_function_candidate',
        'unresolved_call_target', 'expected_method_without_body'
    )),
    start_rva INTEGER,
    end_rva INTEGER,
    raw_target TEXT,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE native_module_analyses (
    native_module_analysis_id TEXT PRIMARY KEY,
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    analysis_context_sha256 TEXT NOT NULL,
    analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    status TEXT NOT NULL CHECK(status IN ('completed', 'partial', 'failed')),
    output_manifest_sha256 TEXT NOT NULL,
    function_count INTEGER NOT NULL DEFAULT 0,
    pending_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(component_revision_id, analysis_context_sha256)
);

CREATE TABLE coverage_reports (
    coverage_report_id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    report_sha256 TEXT NOT NULL,
    approved_body_count INTEGER NOT NULL,
    c_and_asm_count INTEGER NOT NULL,
    asm_only_count INTEGER NOT NULL,
    disassembly_failed_count INTEGER NOT NULL,
    pending_count INTEGER NOT NULL,
    exact_reconciliation INTEGER NOT NULL CHECK(exact_reconciliation IN (0, 1)),
    discovery_complete INTEGER NOT NULL CHECK(discovery_complete IN (0, 1))
);

CREATE TABLE metadata_adapter_results (
    metadata_adapter_result_id TEXT PRIMARY KEY,
    analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    binary_input_object_id TEXT REFERENCES input_objects(input_object_id),
    metadata_input_object_id TEXT REFERENCES input_objects(input_object_id),
    status TEXT NOT NULL CHECK(status IN (
        'parsed', 'unsupported_metadata_version', 'inconsistent_metadata',
        'parse_error', 'suspected_protection'
    )),
    catalog_published INTEGER NOT NULL CHECK(catalog_published IN (0, 1)),
    fallback_used INTEGER NOT NULL CHECK(fallback_used IN (0, 1)),
    details_json TEXT NOT NULL
);

CREATE INDEX symbol_observations_symbol_idx ON symbol_observations(symbol_id);
CREATE INDEX body_observations_build_idx ON body_observations(build_id, module_logical_path);
CREATE INDEX body_observations_body_idx ON body_observations(native_body_id);
CREATE INDEX native_body_attempts_body_idx ON native_body_attempts(native_body_id);
CREATE INDEX native_references_source_idx ON native_references(source_native_body_id);
CREATE INDEX unresolved_code_regions_build_idx ON unresolved_code_regions(build_id, region_kind);
