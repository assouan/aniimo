namespace GameModAPI.Contracts;

public enum CapabilityAvailability
{
    Compatible,
    RequiresValidation,
    Unavailable,
    Breaking,
}

public sealed class LuaModuleDescriptor
{
    public LuaModuleDescriptor(string moduleName, string scriptSha256, string parseStatus)
    {
        ModuleName = moduleName ?? throw new ArgumentNullException(nameof(moduleName));
        ScriptSha256 = scriptSha256 ?? throw new ArgumentNullException(nameof(scriptSha256));
        ParseStatus = parseStatus ?? throw new ArgumentNullException(nameof(parseStatus));
    }

    public string ModuleName { get; }

    public string ScriptSha256 { get; }

    public string ParseStatus { get; }
}

public interface ILuaModuleCatalog
{
    string ApiId { get; }

    string BuildId { get; }

    string CapabilityBasisId { get; }

    CapabilityAvailability Availability { get; }

    IReadOnlyCollection<LuaModuleDescriptor> Modules { get; }

    bool TryGetModule(string moduleName, out LuaModuleDescriptor? module);
}

public interface IBuildIdentity
{
    string ApiId { get; }

    string BuildId { get; }

    string SnapshotId { get; }

    string Backend { get; }

    string Architecture { get; }

    string CapabilityBasisId { get; }

    CapabilityAvailability Availability { get; }
}

public interface IModLogger
{
    void Info(string message);

    void Error(string message);
}

public interface IModContext
{
    IModLogger Logger { get; }

    TCapability? GetCapability<TCapability>() where TCapability : class;
}

public interface IGameMod
{
    string Id { get; }

    string Version { get; }

    void Initialize(IModContext context);
}
