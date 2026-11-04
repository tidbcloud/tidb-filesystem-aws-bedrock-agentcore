FROM --platform=linux/arm64 python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    HOME=/home/agent \
    DRIVE9_CLI_LOG_ENABLED=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    fuse3 \
    git \
    jq \
    libcap2-bin \
    procps \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

# The runtime process and every child command run without root privileges.
RUN groupadd --gid 10000 agent \
    && useradd --uid 10000 --gid 10000 --create-home --home-dir /home/agent \
        --shell /usr/sbin/nologin agent

# Drive9 currently publishes release identifiers as Git revisions. The
# checksum is deliberately fixed: if the vendor's `latest` object changes,
# the build fails instead of silently installing different code.
ARG DRIVE9_VERSION=ddd651e
ARG DRIVE9_LINUX_ARM64_SHA256=ae33bf03723a2bcd48a736c574beb4fc85430dd06ca473d608a0c34f97dd69fa
RUN curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        https://releases.drive9.ai/latest/drive9-linux-arm64 \
        -o /tmp/drive9-linux-arm64 \
    && curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        https://releases.drive9.ai/latest/version -o /tmp/drive9-version \
    && test "$(tr -d '\r\n' < /tmp/drive9-version)" = "${DRIVE9_VERSION}" \
    && echo "${DRIVE9_LINUX_ARM64_SHA256}  /tmp/drive9-linux-arm64" | sha256sum --check --strict \
    && install -o root -g root -m 0755 /tmp/drive9-linux-arm64 /usr/local/bin/drive9 \
    && rm -f /tmp/drive9-linux-arm64 /tmp/drive9-version \
    && printf '%s\n' "${DRIVE9_VERSION}" > /usr/local/share/drive9-version

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=agent:agent app.py path_safety.py ./

RUN mkdir -p /home/agent/.drive9 /home/agent/.cache/drive9 /mnt/drive9 /mnt/scratch /tmp/drive9-test \
    && chown -R agent:agent /home/agent /mnt/drive9 /mnt/scratch /tmp/drive9-test \
    && chmod -R 0700 /home/agent /mnt/drive9 /mnt/scratch /tmp/drive9-test

EXPOSE 8080
USER 10000:10000
CMD ["python", "app.py"]
