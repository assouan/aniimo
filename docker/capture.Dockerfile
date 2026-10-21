# syntax=docker/dockerfile:1.7
FROM python:3.12.8-slim-bookworm@sha256:8859bd6ca943079262c27e38b7119cdacede77c463139a15651dd340087a6cc9

ARG MODKIT_UID=1000
ARG MODKIT_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/modkit

WORKDIR /opt/modkit
COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock

COPY modkit ./modkit
COPY migrations ./migrations
COPY docker/modkit-entrypoint /usr/local/bin/modkit

RUN groupadd --gid "${MODKIT_GID}" modkit \
    && useradd --uid "${MODKIT_UID}" --gid "${MODKIT_GID}" --no-create-home --home-dir /tmp/home --shell /usr/sbin/nologin modkit \
    && mkdir -p /inputs /handoff /tmp/home \
    && chown -R "${MODKIT_UID}:${MODKIT_GID}" /inputs /handoff /tmp/home \
    && chmod 0555 /usr/local/bin/modkit \
    && python -m modkit --version

USER ${MODKIT_UID}:${MODKIT_GID}
ENTRYPOINT ["modkit"]

