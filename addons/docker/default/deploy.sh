#!/usr/bin/env bash

# Look for docker compose
if docker compose version 2> /dev/null ; then
    DOCKER_COMPOSE="docker compose"
elif docker-compose version 2> /dev/null ; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "Docker compose not found :("
    exit 1
fi

# Is docker running?
set -e
${DOCKER_COMPOSE} ps > /dev/null
set +e

if [ ! "$(${DOCKER_COMPOSE} ls --format json)" == "[]" ]; then
    echo -e "Already deployed.\n
    ${DOCKER_COMPOSE} build                # rebuild image
    ${DOCKER_COMPOSE} build --no-cache     # force rebuild image
    ${DOCKER_COMPOSE} down                 # stop and remove
    ${DOCKER_COMPOSE} up -d               # start again"
    echo -e "\n${DOCKER_COMPOSE} ps" && ${DOCKER_COMPOSE} ps
    exit 0
elif [ -e Dockerfile ] && [ -e docker-compose.yml ]; then
    ${DOCKER_COMPOSE} up -d
    ${DOCKER_COMPOSE} ps
    exit 0
else
    echo "Dockerfile or docker-compose.yml not found here $PWD"
    exit 1
fi
