# Keywarden in a container: an SSH client and the CLI, run as a non-root user.
#   docker build -t keywarden .
#   docker run --rm -v "$PWD:/work" -v "$HOME/.ssh:/home/keywarden/.ssh:ro" keywarden \
#     check --inventory hosts.ini --allow team.pub --sarif keywarden.sarif
# Add --build-arg ANSIBLE=1 to include ansible-core for YAML and dynamic inventories.
FROM python:3.13-slim

ARG ANSIBLE=0
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 keywarden

COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
RUN pip install --no-cache-dir /src \
 && if [ "$ANSIBLE" = "1" ]; then pip install --no-cache-dir ansible-core; fi \
 && rm -rf /src

USER keywarden
WORKDIR /work
ENTRYPOINT ["keywarden"]
CMD ["--help"]
