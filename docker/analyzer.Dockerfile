# syntax=docker/dockerfile:1.7
FROM python:3.12.8-slim-bookworm@sha256:8859bd6ca943079262c27e38b7119cdacede77c463139a15651dd340087a6cc9

ARG MODKIT_UID=1000
ARG MODKIT_GID=1000
ARG MICROSOFT_JDK_URL=https://download.visualstudio.microsoft.com/download/pr/f0946540-b19e-4bab-8e58-a9d7735a713c/ad34fb62c40d6eee95addb0ee8c3243e/microsoft-jdk-25.0.4-linux-x64.tar.gz
ARG MICROSOFT_JDK_SHA256=75894d107e474ffb6c947ab050e3893e0a1d3d40d36f107d42936ac6088769c1
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
ARG GHIDRA_SHA256=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/modkit \
    JAVA_HOME=/opt/java \
    GHIDRA_HOME=/opt/ghidra \
    MODKIT_REQUIRE_TOOL_PRESENCE=1 \
    PATH=/opt/java/bin:/opt/ghidra/support:${PATH}

WORKDIR /opt/modkit
COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock

RUN python - "${MICROSOFT_JDK_URL}" "${MICROSOFT_JDK_SHA256}" /tmp/jdk.tar.gz <<'PY'
import hashlib
import pathlib
import shutil
import sys
import urllib.request

url, expected, destination = sys.argv[1:]
with urllib.request.urlopen(url) as response, open(destination, "wb") as output:
    digest = hashlib.sha256()
    while chunk := response.read(4 * 1024 * 1024):
        output.write(chunk)
        digest.update(chunk)
if digest.hexdigest() != expected:
    pathlib.Path(destination).unlink(missing_ok=True)
    raise SystemExit("Microsoft JDK checksum mismatch")
PY
RUN python - "${GHIDRA_URL}" "${GHIDRA_SHA256}" /tmp/ghidra.zip <<'PY'
import hashlib
import pathlib
import sys
import urllib.request

url, expected, destination = sys.argv[1:]
with urllib.request.urlopen(url) as response, open(destination, "wb") as output:
    digest = hashlib.sha256()
    while chunk := response.read(4 * 1024 * 1024):
        output.write(chunk)
        digest.update(chunk)
if digest.hexdigest() != expected:
    pathlib.Path(destination).unlink(missing_ok=True)
    raise SystemExit("Ghidra checksum mismatch")
PY
RUN mkdir -p /opt/java /opt/ghidra \
    && python - <<'PY'
import pathlib
import shutil
import tarfile
import zipfile

with tarfile.open("/tmp/jdk.tar.gz", "r:gz") as archive:
    members = archive.getmembers()
    roots = set()
    for member in members:
        parts = pathlib.PurePosixPath(member.name).parts
        if not parts:
            continue
        if member.name.startswith("/") or ".." in parts:
            raise SystemExit("Unexpected JDK archive layout")
        roots.add(parts[0])
    if len(roots) != 1:
        raise SystemExit("Unexpected JDK archive roots")
    root = roots.pop()
    for member in members:
        parts = pathlib.PurePosixPath(member.name).parts
        if not parts:
            continue
        if parts[0] != root:
            raise SystemExit("Unexpected JDK archive root")
        relative = pathlib.PurePosixPath(*parts[1:])
        if relative.parts:
            member.name = relative.as_posix()
            archive.extract(member, "/opt/java", filter="data")
with zipfile.ZipFile("/tmp/ghidra.zip") as archive:
    for member in archive.infolist():
        parts = pathlib.PurePosixPath(member.filename).parts
        if not parts or parts[0] != "ghidra_12.1.4_PUBLIC" or ".." in parts:
            raise SystemExit("Unexpected Ghidra archive layout")
        relative = pathlib.Path(*parts[1:])
        if not relative.parts:
            continue
        destination = pathlib.Path("/opt/ghidra") / relative
        if member.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output, length=4 * 1024 * 1024)
PY
RUN set -eu; \
    rm -f /tmp/jdk.tar.gz /tmp/ghidra.zip; \
    find /opt/ghidra -type f -path '*/os/linux_x86_64/*' -exec chmod 0555 {} +; \
    chmod +x /opt/ghidra/support/analyzeHeadless /opt/ghidra/support/bsim /opt/ghidra/support/launch.sh; \
    java -version; \
    set +e; \
    /opt/ghidra/support/analyzeHeadless > /tmp/analyze-headless-smoke.log 2>&1; \
    analyze_status=$?; \
    /opt/ghidra/support/bsim > /tmp/bsim-smoke.log 2>&1; \
    bsim_status=$?; \
    set -e; \
    cat /tmp/analyze-headless-smoke.log; \
    cat /tmp/bsim-smoke.log; \
    echo "analyzeHeadless status: $analyze_status"; \
    echo "bsim status: $bsim_status"; \
    grep -F "Headless Analyzer Usage" /tmp/analyze-headless-smoke.log >/dev/null; \
    grep -F "USAGE: bsim" /tmp/bsim-smoke.log >/dev/null; \
    rm -f /tmp/analyze-headless-smoke.log /tmp/bsim-smoke.log

COPY modkit ./modkit
COPY migrations ./migrations
COPY ghidra ./ghidra
COPY docker/modkit-entrypoint /usr/local/bin/modkit

RUN groupadd --gid "${MODKIT_GID}" modkit \
    && useradd --uid "${MODKIT_UID}" --gid "${MODKIT_GID}" --no-create-home --home-dir /state/home --shell /usr/sbin/nologin modkit \
    && mkdir -p /inputs /handoff /state/home /state/dotnet /artifacts /ghidra-state /cache /work/tmp/analyzer /output \
    && chown -R "${MODKIT_UID}:${MODKIT_GID}" /inputs /handoff /state /artifacts /ghidra-state /cache /work /output \
    && chmod 0555 /usr/local/bin/modkit \
    && python -m modkit --version

USER ${MODKIT_UID}:${MODKIT_GID}
ENTRYPOINT ["modkit"]

