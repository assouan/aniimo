using GameModAPI.Contracts;
using GameModAPI.Runtime;

namespace GameModAPI.Adapter.Aniimo;

public sealed class AniimoAdapterRegistry
{
    private readonly IReadOnlyDictionary<string, CapabilityManifest> manifests;

    private AniimoAdapterRegistry(IReadOnlyDictionary<string, CapabilityManifest> manifests)
    {
        this.manifests = manifests;
    }

    public static AniimoAdapterRegistry LoadDirectory(string path)
    {
        Dictionary<string, CapabilityManifest> manifests = new(StringComparer.Ordinal);
        foreach (string file in Directory.EnumerateFiles(path, "build-*.json").Order())
        {
            CapabilityManifest manifest = CapabilityManifest.Load(file);
            string expectedName = $"{manifest.BuildId}.json";
            if (!string.Equals(Path.GetFileName(file), expectedName, StringComparison.Ordinal)
                || !manifests.TryAdd(manifest.BuildId, manifest))
            {
                throw new InvalidDataException("Ambiguous build adapter manifest.");
            }
        }

        if (manifests.Count == 0)
        {
            throw new InvalidDataException("No build adapter manifest was found.");
        }

        return new AniimoAdapterRegistry(manifests);
    }

    public AdapterResolution Resolve(string buildId)
    {
        if (!manifests.TryGetValue(buildId, out CapabilityManifest? manifest))
        {
            return AdapterResolution.Unavailable(buildId, "unknown_build_fail_closed");
        }

        return AdapterResolution.Known(manifest);
    }
}

public sealed class AdapterResolution
{
    private AdapterResolution(
        string buildId,
        CapabilityAvailability availability,
        string reason,
        ILuaModuleCatalog? catalog,
        IBuildIdentity? buildIdentity)
    {
        BuildId = buildId;
        Availability = availability;
        Reason = reason;
        Catalog = catalog;
        BuildIdentity = buildIdentity;
    }

    public string BuildId { get; }

    public CapabilityAvailability Availability { get; }

    public string Reason { get; }

    public ILuaModuleCatalog? Catalog { get; }

    public IBuildIdentity? BuildIdentity { get; }

    internal static AdapterResolution Known(CapabilityManifest manifest)
    {
        ManifestLuaModuleCatalog catalog = new(manifest);
        return new AdapterResolution(
            catalog.BuildId,
            CapabilityAvailability.RequiresValidation,
            "offline_manifest_resolved_runtime_not_tested",
            catalog,
            manifest.BuildIdentity is null ? null : new ManifestBuildIdentity(manifest));
    }

    internal static AdapterResolution Unavailable(string buildId, string reason)
    {
        return new AdapterResolution(
            buildId,
            CapabilityAvailability.Unavailable,
            reason,
            null,
            null);
    }
}
