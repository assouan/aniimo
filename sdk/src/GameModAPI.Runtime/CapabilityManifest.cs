using System.Text.Json;
using System.Text.Json.Serialization;
using GameModAPI.Contracts;

namespace GameModAPI.Runtime;

public sealed class CapabilityManifest
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; init; }

    [JsonPropertyName("api_id")]
    public string ApiId { get; init; } = string.Empty;

    [JsonPropertyName("build_id")]
    public string BuildId { get; init; } = string.Empty;

    [JsonPropertyName("snapshot_id")]
    public string SnapshotId { get; init; } = string.Empty;

    [JsonPropertyName("capability_basis_id")]
    public string CapabilityBasisId { get; init; } = string.Empty;

    [JsonPropertyName("capability_status")]
    public string CapabilityStatus { get; init; } = string.Empty;

    [JsonPropertyName("runtime_validation_status")]
    public string RuntimeValidationStatus { get; init; } = string.Empty;

    [JsonPropertyName("catalog_sha256")]
    public string CatalogSha256 { get; init; } = string.Empty;

    [JsonPropertyName("modules")]
    public List<LuaModuleManifestEntry> Modules { get; init; } = new();

    [JsonPropertyName("build_identity")]
    public BuildIdentityManifest? BuildIdentity { get; init; }

    public static CapabilityManifest Load(string path)
    {
        using FileStream stream = File.OpenRead(path);
        CapabilityManifest? manifest = JsonSerializer.Deserialize<CapabilityManifest>(stream);
        if (manifest is null)
        {
            throw new InvalidDataException("Capability manifest is empty.");
        }

        manifest.Validate();
        return manifest;
    }

    private void Validate()
    {
        if (SchemaVersion is not (1 or 2) || ApiId != "aniimo.lua-module-catalog")
        {
            throw new InvalidDataException("Unsupported capability manifest contract.");
        }

        if (!IsIdentifier(BuildId, "build-") || !IsIdentifier(SnapshotId, "snapshot-"))
        {
            throw new InvalidDataException("Invalid build or snapshot identity.");
        }

        if (!CapabilityBasisId.StartsWith("capability-basis:", StringComparison.Ordinal)
            || !IsSha256(CatalogSha256))
        {
            throw new InvalidDataException("Invalid capability basis.");
        }

        if (CapabilityStatus != "requires_validation"
            || RuntimeValidationStatus != "not_tested")
        {
            throw new InvalidDataException("Unsafe capability status in untested adapter.");
        }

        string? previous = null;
        foreach (LuaModuleManifestEntry module in Modules)
        {
            if (string.IsNullOrWhiteSpace(module.ModuleName)
                || module.ParseStatus is not ("parsed" or "unsupported" or "parse_error")
                || !IsSha256(module.ScriptSha256)
                || (previous is not null
                    && string.CompareOrdinal(previous, module.ModuleName) >= 0))
            {
                throw new InvalidDataException("Invalid or ambiguous Lua module catalog.");
            }

            previous = module.ModuleName;
        }

        if (Modules.Count == 0)
        {
            throw new InvalidDataException("Lua module catalog is empty.");
        }

        if (SchemaVersion == 2)
        {
            if (BuildIdentity is null
                || BuildIdentity.ApiId != "aniimo.build-identity"
                || !BuildIdentity.CapabilityBasisId.StartsWith(
                    "capability-basis:", StringComparison.Ordinal)
                || !IsSha256(
                    BuildIdentity.CapabilityBasisId["capability-basis:".Length..])
                || BuildIdentity.CapabilityStatus != "requires_validation"
                || BuildIdentity.RuntimeValidationStatus != "not_tested"
                || BuildIdentity.Backend != "Unity IL2CPP"
                || BuildIdentity.Architecture != "x86_64")
            {
                throw new InvalidDataException("Invalid build identity capability.");
            }
        }
    }

    private static bool IsIdentifier(string value, string prefix)
    {
        return value.StartsWith(prefix, StringComparison.Ordinal)
            && IsSha256(value[prefix.Length..]);
    }

    private static bool IsSha256(string value)
    {
        return value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }
}

public sealed class BuildIdentityManifest
{
    [JsonPropertyName("api_id")]
    public string ApiId { get; init; } = string.Empty;

    [JsonPropertyName("architecture")]
    public string Architecture { get; init; } = string.Empty;

    [JsonPropertyName("backend")]
    public string Backend { get; init; } = string.Empty;

    [JsonPropertyName("capability_basis_id")]
    public string CapabilityBasisId { get; init; } = string.Empty;

    [JsonPropertyName("capability_status")]
    public string CapabilityStatus { get; init; } = string.Empty;

    [JsonPropertyName("runtime_validation_status")]
    public string RuntimeValidationStatus { get; init; } = string.Empty;
}

public sealed class LuaModuleManifestEntry
{
    [JsonPropertyName("module_name")]
    public string ModuleName { get; init; } = string.Empty;

    [JsonPropertyName("script_sha256")]
    public string ScriptSha256 { get; init; } = string.Empty;

    [JsonPropertyName("parse_status")]
    public string ParseStatus { get; init; } = string.Empty;
}

public sealed class ManifestLuaModuleCatalog : ILuaModuleCatalog
{
    private readonly IReadOnlyDictionary<string, LuaModuleDescriptor> modules;

    public ManifestLuaModuleCatalog(CapabilityManifest manifest)
    {
        ApiId = manifest.ApiId;
        BuildId = manifest.BuildId;
        CapabilityBasisId = manifest.CapabilityBasisId;
        Availability = CapabilityAvailability.RequiresValidation;
        modules = manifest.Modules.ToDictionary(
            item => item.ModuleName,
            item => new LuaModuleDescriptor(
                item.ModuleName,
                item.ScriptSha256,
                item.ParseStatus),
            StringComparer.Ordinal);
        Modules = modules.Values.OrderBy(item => item.ModuleName, StringComparer.Ordinal).ToArray();
    }

    public string ApiId { get; }

    public string BuildId { get; }

    public string CapabilityBasisId { get; }

    public CapabilityAvailability Availability { get; }

    public IReadOnlyCollection<LuaModuleDescriptor> Modules { get; }

    public bool TryGetModule(string moduleName, out LuaModuleDescriptor? module)
    {
        return modules.TryGetValue(moduleName, out module);
    }
}

public sealed class ManifestBuildIdentity : IBuildIdentity
{
    public ManifestBuildIdentity(CapabilityManifest manifest)
    {
        BuildIdentityManifest identity = manifest.BuildIdentity
            ?? throw new InvalidDataException("Build identity capability is absent.");
        ApiId = identity.ApiId;
        BuildId = manifest.BuildId;
        SnapshotId = manifest.SnapshotId;
        Backend = identity.Backend;
        Architecture = identity.Architecture;
        CapabilityBasisId = identity.CapabilityBasisId;
        Availability = CapabilityAvailability.RequiresValidation;
    }

    public string ApiId { get; }

    public string BuildId { get; }

    public string SnapshotId { get; }

    public string Backend { get; }

    public string Architecture { get; }

    public string CapabilityBasisId { get; }

    public CapabilityAvailability Availability { get; }
}
