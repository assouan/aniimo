using GameModAPI.Contracts;

namespace GameModAPI.Runtime;

public sealed class ModContext : IModContext
{
    private readonly IReadOnlyDictionary<Type, object> capabilities;

    public ModContext(IModLogger logger, params object[] capabilities)
    {
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Dictionary<Type, object> registered = new();
        foreach (object capability in capabilities)
        {
            foreach (Type contract in capability.GetType().GetInterfaces().Where(type =>
                type == typeof(ILuaModuleCatalog) || type == typeof(IBuildIdentity)))
            {
                if (!registered.TryAdd(contract, capability))
                {
                    throw new ArgumentException(
                        $"Duplicate capability contract: {contract.FullName}",
                        nameof(capabilities));
                }
            }
        }

        this.capabilities = registered;
    }

    public IModLogger Logger { get; }

    public TCapability? GetCapability<TCapability>() where TCapability : class
    {
        return capabilities.TryGetValue(typeof(TCapability), out object? value)
            ? (TCapability)value
            : null;
    }
}

public sealed class ListModLogger : IModLogger
{
    private readonly List<string> entries = new();

    public IReadOnlyList<string> Entries => entries;

    public void Info(string message)
    {
        entries.Add($"INFO:{message}");
    }

    public void Error(string message)
    {
        entries.Add($"ERROR:{message}");
    }
}
