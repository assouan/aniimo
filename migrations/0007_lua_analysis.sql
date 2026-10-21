CREATE TABLE lua_analyses (
    lua_analysis_id TEXT PRIMARY KEY,
    lua_analysis_key TEXT NOT NULL UNIQUE,
    analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    producer_digest TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('completed', 'partial', 'failed')),
    output_manifest_sha256 TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE lua_archive_observations (
    lua_archive_observation_id TEXT PRIMARY KEY,
    lua_analysis_id TEXT NOT NULL REFERENCES lua_analyses(lua_analysis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    archive_role TEXT NOT NULL CHECK(archive_role IN ('active', 'bundled')),
    xdf_logical_path TEXT NOT NULL,
    xdf_sha256 TEXT NOT NULL,
    xdt_logical_path TEXT NOT NULL,
    xdt_sha256 TEXT NOT NULL,
    content_version TEXT,
    validation_status TEXT NOT NULL CHECK(validation_status IN ('validated', 'unsupported', 'failed')),
    entry_count INTEGER NOT NULL CHECK(entry_count >= 0),
    lua_entry_count INTEGER NOT NULL CHECK(lua_entry_count >= 0),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(lua_analysis_id, archive_role)
);

CREATE TABLE lua_scripts (
    lua_script_id TEXT PRIMARY KEY,
    logical_path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE lua_observations (
    lua_observation_id TEXT PRIMARY KEY,
    lua_analysis_id TEXT NOT NULL REFERENCES lua_analyses(lua_analysis_id),
    lua_script_id TEXT NOT NULL REFERENCES lua_scripts(lua_script_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    script_sha256 TEXT NOT NULL,
    extracted_artifact_sha256 TEXT NOT NULL,
    bytecode_format TEXT NOT NULL,
    parse_status TEXT NOT NULL CHECK(parse_status IN ('parsed', 'unsupported', 'parse_error')),
    module_name TEXT NOT NULL,
    prototype_count INTEGER NOT NULL DEFAULT 0 CHECK(prototype_count >= 0),
    provenance_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(lua_analysis_id, component_revision_id, lua_script_id)
);

CREATE TABLE lua_symbols (
    lua_symbol_id TEXT PRIMARY KEY,
    lua_script_id TEXT NOT NULL REFERENCES lua_scripts(lua_script_id),
    stable_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(lua_script_id, stable_key)
);

CREATE TABLE lua_symbol_observations (
    lua_symbol_observation_id TEXT PRIMARY KEY,
    lua_symbol_id TEXT NOT NULL REFERENCES lua_symbols(lua_symbol_id),
    lua_analysis_id TEXT NOT NULL REFERENCES lua_analyses(lua_analysis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    lua_path TEXT NOT NULL,
    symbol_kind TEXT NOT NULL CHECK(symbol_kind IN ('module', 'function')),
    signature TEXT,
    name_source TEXT NOT NULL,
    signature_source TEXT NOT NULL,
    observation_status TEXT NOT NULL CHECK(observation_status IN ('recovered', 'observed', 'inferred', 'reviewed', 'unsupported')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(lua_analysis_id, component_revision_id, lua_symbol_id)
);

CREATE TABLE lua_dependencies (
    lua_dependency_id TEXT PRIMARY KEY,
    lua_analysis_id TEXT NOT NULL REFERENCES lua_analyses(lua_analysis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    source_lua_script_id TEXT NOT NULL REFERENCES lua_scripts(lua_script_id),
    required_module TEXT NOT NULL,
    resolution_status TEXT NOT NULL CHECK(resolution_status IN ('resolved', 'unresolved', 'external', 'unsupported')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(lua_analysis_id, component_revision_id, source_lua_script_id, required_module)
);

CREATE TABLE lua_bindings (
    lua_binding_id TEXT PRIMARY KEY,
    lua_analysis_id TEXT NOT NULL REFERENCES lua_analyses(lua_analysis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    component_revision_id TEXT NOT NULL REFERENCES component_revisions(component_revision_id),
    lua_script_id TEXT NOT NULL REFERENCES lua_scripts(lua_script_id),
    lua_path TEXT NOT NULL,
    managed_symbol_id TEXT REFERENCES symbols(symbol_id),
    native_body_id TEXT REFERENCES native_bodies(native_body_id),
    bridge TEXT NOT NULL,
    binding_role TEXT NOT NULL,
    mapping_status TEXT NOT NULL CHECK(mapping_status IN ('resolved', 'candidate', 'unresolved', 'reference_only')),
    scope_classification TEXT NOT NULL CHECK(scope_classification IN ('game_decompile', 'reference_only', 'excluded', 'needs_review')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(lua_analysis_id, component_revision_id, lua_script_id, lua_path, binding_role)
);

CREATE TABLE lua_script_cache (
    script_cache_key TEXT PRIMARY KEY,
    script_sha256 TEXT NOT NULL,
    parser_digest TEXT NOT NULL,
    dialect_digest TEXT NOT NULL,
    analysis_artifact_sha256 TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    created_by_analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    UNIQUE(script_sha256, parser_digest, dialect_digest)
);

CREATE TABLE lua_opcode_dialects (
    opcode_dialect_id TEXT PRIMARY KEY,
    xdf_sha256 TEXT NOT NULL,
    parser_digest TEXT NOT NULL,
    mapping_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('inferred_bounded_subset', 'unsupported')),
    created_by_analysis_id TEXT NOT NULL REFERENCES analysis_runs(analysis_id),
    UNIQUE(xdf_sha256, parser_digest)
);

CREATE TABLE observation_scenarios (
    observation_scenario_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phase TEXT NOT NULL,
    description TEXT NOT NULL,
    probe_version TEXT NOT NULL,
    UNIQUE(name, phase, probe_version)
);

CREATE TABLE runtime_observation_imports (
    runtime_observation_import_id TEXT PRIMARY KEY,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id),
    probe_version TEXT NOT NULL,
    bridge TEXT NOT NULL,
    vm_identity TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('imported', 'rejected')),
    imported_at TEXT NOT NULL,
    UNIQUE(source_sha256)
);

CREATE TABLE runtime_observations (
    runtime_observation_id TEXT PRIMARY KEY,
    runtime_observation_import_id TEXT NOT NULL REFERENCES runtime_observation_imports(runtime_observation_import_id),
    observation_scenario_id TEXT NOT NULL REFERENCES observation_scenarios(observation_scenario_id),
    lua_path TEXT NOT NULL,
    value_kind TEXT NOT NULL,
    signature TEXT,
    observation_status TEXT NOT NULL CHECK(observation_status IN ('observed', 'not_tested')),
    evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX lua_observations_build_idx
    ON lua_observations(build_id, component_revision_id, lua_script_id);
CREATE INDEX lua_symbol_observations_build_idx
    ON lua_symbol_observations(build_id, component_revision_id, lua_symbol_id);
CREATE INDEX lua_dependencies_source_idx
    ON lua_dependencies(build_id, source_lua_script_id);
CREATE INDEX lua_bindings_path_idx
    ON lua_bindings(build_id, lua_path);
CREATE INDEX runtime_observations_import_idx
    ON runtime_observations(runtime_observation_import_id, observation_scenario_id);
