using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using GameModAPI.Adapter.Aniimo;
using GameModAPI.Contracts;
using GameModAPI.Runtime;

namespace GameModAPI.Tests;

internal static class Program
{
    private const string RequiredModule = "Common.Ability.AbilityManager";

    private static int Main(string[] args)
    {
        if (args.Length != 4)
        {
            Console.Error.WriteLine(
                "usage: GameModAPI.Tests <adapter-dir> <old-plugin-dll> <report> <expected-builds>"
            );
            return 2;
        }

        try
        {
            string[] expectedBuilds = args[3]
                .Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(item => item.Trim())
                .ToArray();
            if (expectedBuilds.Length != 2 || expectedBuilds.Distinct().Count() != 2)
            {
                throw new InvalidDataException("Exactly two distinct builds are required.");
            }

            AssemblyName currentContract = typeof(IGameMod).Assembly.GetName();
            Assert(
                currentContract.Version == new Version(1, 0, 0, 0),
                "The additive SDK release changed the public contract assembly version.");
            Assembly pluginAssembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(
                Path.GetFullPath(args[1]));
            AssemblyName pluginContract = pluginAssembly.GetReferencedAssemblies().Single(
                item => item.Name == "GameModAPI.Contracts");
            Assert(
                pluginContract.Version == new Version(1, 0, 0, 0),
                "The supplied old plugin was not compiled for contract assembly 1.0.0.0.");
            Type pluginType = pluginAssembly.GetTypes().Single(type =>
                typeof(IGameMod).IsAssignableFrom(type) && !type.IsAbstract);
            PropertyInfo lastResult = pluginType.GetProperty("LastResult")
                ?? throw new InvalidDataException("Old plugin result property is absent.");

            AniimoAdapterRegistry registry = AniimoAdapterRegistry.LoadDirectory(args[0]);
            List<BuildResult> results = new();
            string? sharedCatalogBasis = null;
            string? sharedModuleHash = null;
            foreach (string buildId in expectedBuilds)
            {
                AdapterResolution resolution = registry.Resolve(buildId);
                Assert(
                    resolution.Availability == CapabilityAvailability.RequiresValidation,
                    "Known build must remain requires_validation before runtime tests: "
                        + $"{buildId} => {resolution.Availability} ({resolution.Reason}).");
                Assert(resolution.Catalog is not null, "Known build catalog was not resolved.");
                Assert(
                    resolution.BuildIdentity is not null,
                    "Known build identity capability was not resolved.");
                ILuaModuleCatalog catalog = resolution.Catalog!;
                IBuildIdentity identity = resolution.BuildIdentity!;
                Assert(catalog.Modules.Count == 8636, "Unexpected Lua module count.");
                Assert(
                    catalog.TryGetModule(RequiredModule, out LuaModuleDescriptor? module),
                    "Required example module is missing.");
                Assert(module is not null, "Required module result is null.");
                Assert(identity.BuildId == buildId, "Build identity differs from selection.");
                Assert(
                    identity.SnapshotId.StartsWith("snapshot-", StringComparison.Ordinal),
                    "Snapshot identity is absent.");
                Assert(identity.Backend == "Unity IL2CPP", "Backend identity differs.");
                Assert(identity.Architecture == "x86_64", "Architecture identity differs.");

                IGameMod mod = (IGameMod)(Activator.CreateInstance(pluginType)
                    ?? throw new InvalidDataException("Old plugin could not be instantiated."));
                ListModLogger logger = new();
                mod.Initialize(new ModContext(logger, catalog, identity));
                Assert(
                    Equals(lastResult.GetValue(mod), $"found:{module!.ScriptSha256}"),
                    "Old plugin result differs with the new adapter.");
                Assert(logger.Entries.Count == 1, "Mod emitted an unexpected number of logs.");
                sharedCatalogBasis ??= catalog.CapabilityBasisId;
                sharedModuleHash ??= module.ScriptSha256;
                Assert(sharedCatalogBasis == catalog.CapabilityBasisId, "Catalog basis differs.");
                Assert(sharedModuleHash == module.ScriptSha256, "Module dependency differs.");
                results.Add(
                    new BuildResult
                    {
                        BuildId = buildId,
                        CapabilityBasisId = catalog.CapabilityBasisId,
                        BuildIdentityBasisId = identity.CapabilityBasisId,
                        ModuleSha256 = module.ScriptSha256,
                        ModuleCount = catalog.Modules.Count,
                        Status = "passed",
                    });
            }

            AdapterResolution unknown = registry.Resolve("build-" + new string('0', 64));
            Assert(
                unknown.Availability == CapabilityAvailability.Unavailable
                    && unknown.Catalog is null
                    && unknown.BuildIdentity is null,
                "Unknown build did not fail closed.");

            string pluginSha256 = Convert.ToHexString(
                SHA256.HashData(File.ReadAllBytes(args[1]))).ToLowerInvariant();
            TestReport report = new()
            {
                BuildIds = expectedBuilds.Order(StringComparer.Ordinal).ToArray(),
                PluginSha256 = pluginSha256,
                Results = results.OrderBy(item => item.BuildId, StringComparer.Ordinal).ToArray(),
                CurrentContractAssemblyVersion = currentContract.Version!.ToString(),
                OldContractAssemblyVersion = pluginContract.Version!.ToString(),
            };
            File.WriteAllText(
                args[2],
                JsonSerializer.Serialize(
                    report,
                    new JsonSerializerOptions { WriteIndented = true }) + "\n");
            Console.WriteLine(
                $"PASS old plugin {pluginSha256} without recompilation against SDK 1.1.0");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}

internal sealed class TestReport
{
    [JsonPropertyName("schema_version")]
    public int SchemaVersion => 2;

    [JsonPropertyName("status")]
    public string Status => "passed";

    [JsonPropertyName("build_ids")]
    public required string[] BuildIds { get; init; }

    [JsonPropertyName("same_plugin_binary")]
    public bool SamePluginBinary => true;

    [JsonPropertyName("plugin_sha256")]
    public required string PluginSha256 { get; init; }

    [JsonPropertyName("plugin_compiled_sdk_version")]
    public string PluginCompiledSdkVersion => "1.0.0";

    [JsonPropertyName("adapter_sdk_version")]
    public string AdapterSdkVersion => "1.1.0";

    [JsonPropertyName("binary_compatibility_status")]
    public string BinaryCompatibilityStatus => "passed";

    [JsonPropertyName("old_contract_assembly_version")]
    public required string OldContractAssemblyVersion { get; init; }

    [JsonPropertyName("current_contract_assembly_version")]
    public required string CurrentContractAssemblyVersion { get; init; }

    [JsonPropertyName("runtime_game_status")]
    public string RuntimeGameStatus => "not_tested";

    [JsonPropertyName("results")]
    public required BuildResult[] Results { get; init; }
}

internal sealed class BuildResult
{
    [JsonPropertyName("build_id")]
    public required string BuildId { get; init; }

    [JsonPropertyName("capability_basis_id")]
    public required string CapabilityBasisId { get; init; }

    [JsonPropertyName("build_identity_basis_id")]
    public required string BuildIdentityBasisId { get; init; }

    [JsonPropertyName("module_sha256")]
    public required string ModuleSha256 { get; init; }

    [JsonPropertyName("module_count")]
    public int ModuleCount { get; init; }

    [JsonPropertyName("status")]
    public required string Status { get; init; }
}
