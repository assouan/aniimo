CREATE INDEX body_observations_component_rva_idx
    ON body_observations(component_revision_id, rva);

CREATE INDEX symbol_observations_component_rva_idx
    ON symbol_observations(component_revision_id, native_entry_rva);

CREATE INDEX symbol_observations_component_signature_idx
    ON symbol_observations(component_revision_id, signature_key);

CREATE INDEX symbol_body_links_build_body_idx
    ON symbol_body_links(build_id, native_body_id);

CREATE INDEX native_prototypes_build_body_idx
    ON native_prototypes(build_id, native_body_id);

CREATE INDEX native_references_build_source_idx
    ON native_references(build_id, source_native_body_id);
