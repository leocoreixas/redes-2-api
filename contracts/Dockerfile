# syntax=docker.io/docker/dockerfile:1.4

FROM node:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends jq\
    && rm -rf /var/apt/lists/*

WORKDIR /opt/contracts
COPY . .

RUN npm install

# copy foundry's commands binaries
COPY --from=ghcr.io/foundry-rs/foundry:latest /usr/local/bin /usr/local/bin

# compile contracts
RUN forge build

ENTRYPOINT [ "./deploy.sh" ]