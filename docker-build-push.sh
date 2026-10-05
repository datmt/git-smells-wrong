#!/usr/bin/env bash
# Build the git-smells-wrong image and push it to GHCR.
# Usage: ./docker-build-push.sh [tag]   (defaults to git describe, else "latest")
#
# Env overrides:
#   IMAGE    image repository (default ghcr.io/yourorg/git-smells-wrong)
#   VERSION  version stamped into the binary (default: the tag)
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="${IMAGE:-ghcr.io/yourorg/git-smells-wrong}"
TAG="${1:-$(git describe --tags --always 2>/dev/null || echo latest)}"
VERSION="${VERSION:-$TAG}"

echo "building ${IMAGE}:${TAG} (version=${VERSION})..."
docker build --build-arg "VERSION=${VERSION}" -t "${IMAGE}:${TAG}" .

echo "pushing ${IMAGE}:${TAG}..."
docker push "${IMAGE}:${TAG}"

echo "pushed ${IMAGE}:${TAG}"
