FROM mcr.microsoft.com/vscode/devcontainers/go:0-1.19

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    pre-commit \
    vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /go/pkg \
    && chmod -R a+w /go/pkg

WORKDIR /workspace
