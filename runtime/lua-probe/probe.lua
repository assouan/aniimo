-- Bounded observational probe for an already-authorized Aniimo Lua process.
-- Loading this file has no side effect: the host must explicitly call capture().

local Probe = {}

local raw_next = next
local raw_rawget = rawget
local raw_type = type

local function bounded_integer(config, name, fallback, minimum, maximum)
    local value = raw_rawget(config, name)
    if raw_type(value) ~= "number" or value < minimum or value > maximum then
        return fallback
    end
    return math.floor(value)
end

local function string_field(config, name)
    local value = raw_rawget(config, name)
    if raw_type(value) ~= "string" or value == "" then
        error("missing probe identity field: " .. name)
    end
    return value
end

local function key_segment(key)
    if raw_type(key) ~= "string" then
        return nil
    end
    if key == "" or #key > 256 or string.find(key, "[%z\r\n]", 1) then
        return nil
    end
    return key
end

local function append_observation(state, path, kind, detail)
    if state.count >= state.max_observations then
        state.truncated = true
        return false
    end
    state.count = state.count + 1
    state.observations[state.count] = {
        lua_path = path,
        value_kind = kind,
        detail = detail,
    }
    return true
end

local function walk_table(value, path, depth, state)
    if state.visited[value] then
        append_observation(state, path, "table_cycle", "already_visited")
        return
    end
    state.visited[value] = true
    if depth >= state.max_depth then
        append_observation(state, path, "table", "max_depth_reached")
        return
    end

    local key = nil
    local examined = 0
    while examined < state.max_entries_per_table do
        local item
        key, item = raw_next(value, key)
        if key == nil then
            return
        end
        examined = examined + 1
        local segment = key_segment(key)
        if segment ~= nil then
            local child_path = path .. "." .. segment
            local kind = raw_type(item)
            if not append_observation(state, child_path, kind, nil) then
                return
            end
            if kind == "table" then
                walk_table(item, child_path, depth + 1, state)
                if state.truncated then
                    return
                end
            end
        else
            state.skipped_non_string_keys = state.skipped_non_string_keys + 1
        end
    end
    state.truncated_tables = state.truncated_tables + 1
end

local function observe_root(root, path, state)
    if raw_type(root) ~= "table" then
        append_observation(state, path, raw_type(root), "root_not_table")
        return
    end
    state.visited = {}
    walk_table(root, path, 0, state)
end

function Probe.capture(config)
    if raw_type(config) ~= "table" then
        error("probe configuration must be a plain table")
    end
    local scenario = raw_rawget(config, "scenario")
    if raw_type(scenario) ~= "table" then
        error("probe scenario must be a plain table")
    end
    local state = {
        count = 0,
        max_depth = bounded_integer(config, "max_depth", 4, 0, 12),
        max_entries_per_table = bounded_integer(
            config, "max_entries_per_table", 256, 1, 4096
        ),
        max_observations = bounded_integer(
            config, "max_observations", 10000, 1, 100000
        ),
        observations = {},
        skipped_non_string_keys = 0,
        truncated = false,
        truncated_tables = 0,
        visited = {},
    }

    observe_root(_G, "_G", state)
    local package_table = raw_rawget(_G, "package")
    if raw_type(package_table) == "table" then
        local loaded = raw_rawget(package_table, "loaded")
        observe_root(loaded, "package.loaded", state)
    end

    return {
        schema_version = 1,
        snapshot_id = string_field(config, "snapshot_id"),
        build_id = string_field(config, "build_id"),
        probe_version = "1.0.0",
        bridge = string_field(config, "bridge"),
        vm_identity = string_field(config, "vm_identity"),
        module_sha256 = string_field(config, "module_sha256"),
        scenario = {
            name = string_field(scenario, "name"),
            phase = string_field(scenario, "phase"),
            description = string_field(scenario, "description"),
        },
        observations = state.observations,
        coverage = {
            exhaustive = false,
            max_depth = state.max_depth,
            max_entries_per_table = state.max_entries_per_table,
            max_observations = state.max_observations,
            skipped_non_string_keys = state.skipped_non_string_keys,
            truncated = state.truncated,
            truncated_tables = state.truncated_tables,
            unknown_functions_invoked = 0,
            getters_invoked = 0,
            modules_loaded = 0,
        },
    }
end

return Probe
