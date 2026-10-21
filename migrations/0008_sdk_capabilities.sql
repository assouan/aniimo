CREATE TABLE sdk_releases (
    sdk_release_id TEXT PRIMARY KEY,
    sdk_release_key TEXT NOT NULL UNIQUE,
    sdk_version TEXT NOT NULL UNIQUE,
    contract_sha256 TEXT,
    package_sha256 TEXT,
    output_manifest_sha256 TEXT,
    status TEXT NOT NULL CHECK(status IN ('draft', 'built', 'validated', 'failed')),
    created_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE TABLE adapter_releases (
    adapter_id TEXT PRIMARY KEY,
    adapter_version TEXT NOT NULL,
    backend TEXT NOT NULL,
    resolver_version TEXT NOT NULL,
    loader_kind TEXT NOT NULL,
    package_sha256 TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(adapter_version, backend, resolver_version, loader_kind)
);

CREATE TABLE capabilities (
    api_id TEXT PRIMARY KEY,
    public_name TEXT NOT NULL,
    contract_version TEXT NOT NULL,
    capability_kind TEXT NOT NULL,
    client_requirement TEXT NOT NULL CHECK(client_requirement IN ('server_only', 'client_required', 'shared_protocol', 'host_metadata_only')),
    description TEXT NOT NULL
);

CREATE TABLE capability_bases (
    capability_basis_id TEXT PRIMARY KEY,
    api_id TEXT NOT NULL REFERENCES capabilities(api_id),
    adapter_id TEXT NOT NULL REFERENCES adapter_releases(adapter_id),
    dependency_fingerprint TEXT NOT NULL,
    abi_context TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(api_id, adapter_id, dependency_fingerprint, abi_context)
);

CREATE TABLE capability_dependencies (
    capability_dependency_id TEXT PRIMARY KEY,
    capability_basis_id TEXT NOT NULL REFERENCES capability_bases(capability_basis_id),
    dependency_kind TEXT NOT NULL CHECK(dependency_kind IN ('symbol', 'body', 'layout', 'field', 'data', 'lua_binding', 'component', 'resolver', 'abi', 'test', 'loader')),
    dependency_id TEXT NOT NULL,
    required_revision_or_hash TEXT NOT NULL,
    resolver_version TEXT NOT NULL,
    abi_context TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('resolved', 'unknown', 'ambiguous', 'not_tested')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(capability_basis_id, dependency_kind, dependency_id)
);

CREATE TABLE capability_build_evaluations (
    capability_build_evaluation_id TEXT PRIMARY KEY,
    capability_basis_id TEXT NOT NULL REFERENCES capability_bases(capability_basis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    lua_analysis_id TEXT REFERENCES lua_analyses(lua_analysis_id),
    capability_status TEXT NOT NULL CHECK(capability_status IN ('compatible', 'requires_validation', 'unavailable', 'breaking')),
    static_analysis_status TEXT NOT NULL CHECK(static_analysis_status IN ('passed', 'failed', 'not_tested')),
    required_tests_status TEXT NOT NULL CHECK(required_tests_status IN ('passed', 'failed', 'partial', 'not_tested')),
    runtime_validation_status TEXT NOT NULL CHECK(runtime_validation_status IN ('passed', 'failed', 'not_tested')),
    transfer_rule TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    evaluated_at TEXT NOT NULL,
    UNIQUE(capability_basis_id, build_id)
);

CREATE TABLE loader_evaluations (
    loader_evaluation_id TEXT PRIMARY KEY,
    loader_name TEXT NOT NULL,
    loader_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    backend TEXT NOT NULL,
    artifact_sha256 TEXT,
    evaluation_status TEXT NOT NULL CHECK(evaluation_status IN ('selected_candidate', 'rejected', 'not_tested')),
    installation_status TEXT NOT NULL CHECK(installation_status IN ('not_installed', 'installed_authorized_environment')),
    runtime_validation_status TEXT NOT NULL CHECK(runtime_validation_status IN ('passed', 'failed', 'not_tested')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    evaluated_at TEXT NOT NULL,
    UNIQUE(loader_name, loader_version, platform, backend)
);

CREATE TABLE mod_packages (
    mod_package_id TEXT PRIMARY KEY,
    mod_id TEXT NOT NULL,
    mod_version TEXT NOT NULL,
    sdk_release_id TEXT NOT NULL REFERENCES sdk_releases(sdk_release_id),
    package_sha256 TEXT NOT NULL UNIQUE,
    package_size_bytes INTEGER NOT NULL CHECK(package_size_bytes >= 0),
    signer_identity TEXT,
    build_scope_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE capability_validations (
    capability_validation_id TEXT PRIMARY KEY,
    api_id TEXT NOT NULL REFERENCES capabilities(api_id),
    capability_basis_id TEXT NOT NULL REFERENCES capability_bases(capability_basis_id),
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    runtime_environment_id TEXT NOT NULL,
    test_suite TEXT NOT NULL,
    validation_kind TEXT NOT NULL CHECK(validation_kind IN ('static_contract', 'offline_adapter', 'runtime_game')),
    validation_status TEXT NOT NULL CHECK(validation_status IN ('passed', 'failed', 'not_tested')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    validated_at TEXT NOT NULL,
    UNIQUE(capability_basis_id, build_id, runtime_environment_id, test_suite, validation_kind)
);

CREATE TABLE runtime_authorizations (
    runtime_authorization_id TEXT PRIMARY KEY,
    mod_package_id TEXT NOT NULL REFERENCES mod_packages(mod_package_id),
    package_sha256 TEXT NOT NULL,
    mod_version TEXT NOT NULL,
    signer_identity TEXT,
    declared_build_scope_json TEXT NOT NULL,
    authorization_status TEXT NOT NULL CHECK(authorization_status IN ('not_requested', 'pending', 'approved', 'rejected', 'expired', 'unknown')),
    valid_from TEXT,
    valid_until TEXT,
    evidence_reference TEXT,
    recorded_at TEXT NOT NULL
);

CREATE INDEX capability_build_evaluations_build_idx
    ON capability_build_evaluations(build_id, capability_status);
CREATE INDEX capability_dependencies_basis_idx
    ON capability_dependencies(capability_basis_id, dependency_kind);
CREATE INDEX capability_validations_build_idx
    ON capability_validations(build_id, validation_kind, validation_status);
