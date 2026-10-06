#!/usr/bin/env bash
# Regenerates the Go code under authpb/ and examples/grpcdemo/inventorypb/ from
# proto/, with pinned tools installed into .bin/ so that nothing on the
# machine's PATH decides the output. Run after changing a proto; the generated
# code is checked in, and scripts/check-generated.sh (at the repository root)
# fails when it drifts.
#
#   bash scripts/generate.sh           # lint and regenerate
#   bash scripts/generate.sh --check   # lint, and fail if the checked-in code differs
set -euo pipefail
cd "$(dirname "$0")/.."

BUF_VERSION=1.73.0
PROTOC_GEN_GO_VERSION=v1.36.12
PROTOC_GEN_GO_GRPC_VERSION=1.6.2

export GOBIN="$PWD/.bin"
mkdir -p "$GOBIN"

# Install (or reinstall) a tool when it is missing or at another version.
need() { # binary, version it must print, go install target
  if ! "$GOBIN/$1" --version 2>/dev/null | grep -q -- "$2"; then
    echo "==> installing $3"
    go install "$3"
  fi
}
need buf "$BUF_VERSION" "github.com/bufbuild/buf/cmd/buf@v$BUF_VERSION"
need protoc-gen-go "$PROTOC_GEN_GO_VERSION" "google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO_VERSION"
need protoc-gen-go-grpc "$PROTOC_GEN_GO_GRPC_VERSION" "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v$PROTOC_GEN_GO_GRPC_VERSION"

export PATH="$GOBIN:$PATH"
buf lint

if [ "${1:-}" != "--check" ]; then
  buf generate
  echo "==> authpb and the demo's inventorypb regenerated"
  exit 0
fi

# --check: generate elsewhere and compare, both ways — no file may differ, and
# no generated file may be checked in that the protos no longer produce.
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
buf generate --output "$out"
status=0
while IFS= read -r f; do
  rel="${f#"$out"/}"
  if ! cmp -s "$f" "$rel"; then
    echo "drift: $rel differs from what its proto produces"
    status=1
  fi
done < <(find "$out" -type f)
while IFS= read -r f; do
  [ -f "$out/$f" ] || { echo "stray: $f is not produced by any proto"; status=1; }
done < <(find authpb examples -name '*.pb.go')
[ "$status" -eq 0 ] && echo "==> generated Go code matches the protos"
exit "$status"
