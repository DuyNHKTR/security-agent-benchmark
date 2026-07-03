FROM node:22-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git jq ripgrep build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global @openai/codex@0.142.4

WORKDIR /workspace/target
ENV CI=1
ENTRYPOINT []
CMD ["bash"]
