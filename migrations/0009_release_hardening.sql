CREATE TABLE sdk_binary_compatibility_tests (
    compatibility_test_id TEXT PRIMARY KEY,
    sdk_release_id TEXT NOT NULL REFERENCES sdk_releases(sdk_release_id),
    old_plugin_sha256 TEXT NOT NULL,
    old_contract_assembly_version TEXT NOT NULL,
    current_contract_sha256 TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    build_scope_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('passed', 'failed', 'not_tested')),
    evidence_json TEXT NOT NULL DEFAULT '{}',
    tested_at TEXT NOT NULL,
    UNIQUE(sdk_release_id, old_plugin_sha256, current_contract_sha256, adapter_version)
);

CREATE TABLE distribution_attestations (
    distribution_attestation_id TEXT PRIMARY KEY,
    sdk_release_id TEXT NOT NULL REFERENCES sdk_releases(sdk_release_id),
    package_sha256 TEXT NOT NULL,
    package_manifest_schema INTEGER NOT NULL CHECK(package_manifest_schema >= 1),
    verification_status TEXT NOT NULL CHECK(verification_status IN ('passed', 'failed')),
    signature_status TEXT NOT NULL CHECK(signature_status IN ('unsigned', 'signed')),
    signer_identity TEXT,
    sbom_sha256 TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(sdk_release_id, package_sha256)
);

CREATE INDEX sdk_binary_compatibility_release_idx
    ON sdk_binary_compatibility_tests(sdk_release_id, status);
CREATE INDEX distribution_attestations_package_idx
    ON distribution_attestations(package_sha256, verification_status);
