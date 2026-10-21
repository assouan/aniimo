using GameModAPI.Contracts;

namespace LuaCatalogExample;

public sealed class LuaCatalogExampleMod : IGameMod
{
    public const string RequiredModule = "Common.Ability.AbilityManager";

    public string Id => "aniimo.lua-catalog-example";

    public string Version => "1.0.0";

    public string LastResult { get; private set; } = "not_initialized";

    public void Initialize(IModContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }
        ILuaModuleCatalog? catalog = context.GetCapability<ILuaModuleCatalog>();
        if (catalog is null)
        {
            LastResult = "capability_unavailable";
            context.Logger.Error("The Lua module catalog capability is unavailable.");
            return;
        }

        if (!catalog.TryGetModule(RequiredModule, out LuaModuleDescriptor? module)
            || module is null)
        {
            LastResult = "required_module_missing";
            context.Logger.Error($"Required module is absent: {RequiredModule}");
            return;
        }

        LastResult = $"found:{module.ScriptSha256}";
        context.Logger.Info(
            $"Observed {module.ModuleName} for {catalog.BuildId}; "
            + $"runtime status is {catalog.Availability}.");
    }
}
