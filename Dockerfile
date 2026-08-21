# Ronin-Mini orchestrator image. Packages the harness itself (run.py/main.py
# + ronin_mini/) so setup collapses to `docker-compose up -d mongo` +
# `docker-compose run --rm ronin ...` instead of a manual Python venv +
# ripgrep + Docker Desktop walkthrough.
#
# The harness's own tools (execute_python, network_exploit's Kali box) spawn
# SIBLING containers on the host via the `docker` CLI -- this image ships
# that CLI binary, and docker-compose.yml mounts the host's Docker socket in
# at runtime so those calls keep working exactly as they do when run.py runs
# directly on a host. That socket mount gives this container effectively
# root-equivalent access to the host's Docker daemon -- a real, standard
# tradeoff for "a container that manages sibling containers" (the same
# pattern most CI runners use), worth being aware of, not just accepting
# silently.
FROM python:3.11-slim

# Real docker CLI binary, not the whole daemon -- multi-stage COPY from the
# official docker:cli image keeps this image small. It talks to the host's
# daemon over the socket mounted in at `docker run`/`docker-compose run`
# time, not a daemon running inside this container.
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker

# ripgrep: the fileops category's code_search tool shells out to `rg`
# directly (categories/fileops.py) -- not a Python dependency, has to be a
# real binary on PATH.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ripgrep \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ronin_mini ./ronin_mini
COPY run.py main.py ./

# WORKDIR switches to /workspace (docker-compose.yml mounts the host's
# project directory there) so relative paths the CLI already uses by
# default -- --scope-dir ., --log-path's default logs/run_<...>.jsonl --
# resolve inside that mount and land back on the host, unchanged from how
# they behave when run.py runs directly on a host.
WORKDIR /workspace
ENTRYPOINT ["python"]
CMD ["/app/run.py", "--help"]
