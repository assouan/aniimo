CREATE INDEX symbol_observations_build_component_symbol_idx
    ON symbol_observations(build_id, component_revision_id, symbol_id);

CREATE INDEX native_references_build_source_instruction_idx
    ON native_references(
        build_id,
        source_native_body_id,
        source_instruction_rva,
        native_reference_id
    );
