# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:8.0.408-bookworm-slim@sha256:f02ec8dea350dd13da18c4e4705a603221b4089a5c5d36c31bac335e3b5fa837 AS build

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    NUGET_PACKAGES=/tmp/nuget

WORKDIR /src
COPY sdk ./sdk
COPY examples/mods/LuaCatalogExample ./examples/mods/LuaCatalogExample

RUN dotnet --info \
    && dotnet restore examples/mods/LuaCatalogExample/LuaCatalogExample.csproj \
        --configfile sdk/NuGet.Config \
    && dotnet restore sdk/tests/GameModAPI.Tests/GameModAPI.Tests.csproj \
        --configfile sdk/NuGet.Config \
    && dotnet build examples/mods/LuaCatalogExample/LuaCatalogExample.csproj \
        --configuration Release \
        --no-restore \
    && dotnet build sdk/tests/GameModAPI.Tests/GameModAPI.Tests.csproj \
        --configuration Release \
        --no-restore \
    && mkdir -p /export/compiled /export/tests \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/GameModAPI.Contracts.dll /export/compiled/ \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/GameModAPI.Runtime.dll /export/compiled/ \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/GameModAPI.Adapter.Aniimo.dll /export/compiled/ \
    && cp examples/mods/LuaCatalogExample/bin/Release/netstandard2.1/LuaCatalogExample.dll /export/compiled/ \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/GameModAPI.Tests* /export/tests/ \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/GameModAPI.Contracts.dll /export/tests/ \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/GameModAPI.Runtime.dll /export/tests/ \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/GameModAPI.Adapter.Aniimo.dll /export/tests/ \
    && cp examples/mods/LuaCatalogExample/bin/Release/netstandard2.1/LuaCatalogExample.dll /export/tests/ \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/*.deps.json /export/tests/ \
    && cp sdk/tests/GameModAPI.Tests/bin/Release/net8.0/*.runtimeconfig.json /export/tests/

FROM scratch AS export
COPY --from=build /export /
