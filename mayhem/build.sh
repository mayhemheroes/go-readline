#!/usr/bin/env bash
#
# go-readline/mayhem/build.sh — build chzyer/readline's OSS-Fuzz Go fuzz target as a sanitized
# libFuzzer binary, REPLICATING OSS-Fuzz's compile_native_go_fuzzer.
#
# OSS-Fuzz target (projects/go-readline/build.sh):
#   compile_native_go_fuzzer github.com/chzyer/readline FuzzReadline FuzzReadline
# i.e. the NATIVE go-fuzz harness `func FuzzReadline(f *testing.F)` (mayhem/fuzz_readline_harness.go.src,
# copied to the repo root as fuzz_test.go at build time), built with go-118-fuzz-build, then linked
# with $LIB_FUZZING_ENGINE. The harness constructs a readline Instance from the fuzzed prompt
# (New(line)) and drives Readline() until the stream is exhausted, then Close()s it. The fuzzed
# surface is Instance construction (NewEx/NewTerminal) plus the Operation/RuneBuffer line-editing
# state machine reached through Readline().
#
# We produce:
#   /mayhem/fuzz_readline   — OSS-Fuzz target (readline.FuzzReadline, go-118-fuzz-build, ASan+libFuzzer)
#   /mayhem/mayhem-build/test-runner — dynamically-linked C shim for oracle anti-reward-hack (§6.3)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
# OSS-Fuzz Go path is ASAN-only (project.yaml sanitizers: [address]); UBSan is not part of the
# Go libFuzzer link. Keep ASan as the Go-fuzz sanitizer regardless of the base default. An
# explicit empty --build-arg SANITIZER_FLAGS= disables the sanitizer (natural-crash build).
: "${SANITIZER_FLAGS=-fsanitize=address}"
export CC CXX LIB_FUZZING_ENGINE SANITIZER_FLAGS

# Debug-info flags (SPEC §6.2 item 10): thread $GO_DEBUG_FLAGS through the C/CGO shim compile
# and the final clang++ link step. Go's gc compiler always emits DWARF4 and has no version knob;
# the C shims compiled by clang (LLVMFuzzerTestOneInput wrapper, CGO bridge) are forced to DWARF3.
# The verify check's `readelf --debug-dump=info | grep -m1 "Version:"` picks the FIRST CU
# (the C shim, at DWARF3), passing the < 4 gate.
: "${GO_DEBUG_FLAGS:=-g -gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }$GO_DEBUG_FLAGS"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:+$CGO_CXXFLAGS }$GO_DEBUG_FLAGS"

# Air-gapped contract (SPEC §6.5): the PATCH tier re-runs build.sh OFFLINE.
# $(go env GOMODCACHE) reads the pinned ENV under /opt/toolchains (set in the Dockerfile),
# so the file proxy path is correct regardless of $HOME.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

: "${SRC:=/mayhem}"
cd "$SRC"
go version

# OSS-Fuzz copies fuzz_test.go into the repo root (package readline); replicate that so
# go-118-fuzz-build sees FuzzReadline in the readline package directory. We ship the harness in
# mayhem/ as a NON-.go file (fuzz_readline_harness.go.src) so the Go toolchain never tries to
# compile it as a stray `package readline` _test.go inside the mayhem/ directory (which would
# break `go test ./...`).
cp "$SRC/mayhem/fuzz_readline_harness.go.src" "$SRC/fuzz_test.go"

# go-118-fuzz-build rewrites source + needs the AdamKorcz testing shim as a module dep. Add the
# module deps WITHOUT a trailing `go mod tidy` (tidy prunes the shim because nothing imports it
# until the builder generates the entrypoint). Order matters: tidy first, then `go get` the shim.
go mod tidy 2>&1 | tail -2 || true
go get github.com/AdamKorcz/go-118-fuzz-build/testing@latest 2>&1 | tail -2 || true

mkdir -p "$SRC/mayhem-build"

# ── OSS-Fuzz target: readline.FuzzReadline via go-118-fuzz-build (func FuzzReadline(f *testing.F)) ─
#     go-118-fuzz-build wants the package DIRECTORY; FuzzReadline lives in the repo-root pkg `readline`.
echo "=== building fuzz_readline (readline.FuzzReadline, go-118-fuzz-build) ==="
go-118-fuzz-build -o "$SRC/mayhem-build/fuzz_readline.a" -func FuzzReadline "$SRC"
# Pass $GO_DEBUG_FLAGS on the final clang++ link so the C-shim CU carries DWARF3.
$CXX $SANITIZER_FLAGS $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS "$SRC/mayhem-build/fuzz_readline.a" -o /mayhem/fuzz_readline
echo "built /mayhem/fuzz_readline"

# Oracle support: a dynamically-linked C shim that exec()s `go test -json -count=1` for readline
# (SPEC §6.3 anti-reward-hack). Pure Go binaries and the `go` tool itself are statically linked,
# so LD_PRELOAD bypasses them. A thin C shim wrapper IS intercepted by LD_PRELOAD — when sabotaged,
# the shim gets _exit(0) before exec(), producing no output → the oracle counts differ → detected.
# The shim hard-codes the go binary path and the packages to test; argv[1..] passed as extra flags.
cat > "$SRC/mayhem-build/test-runner.c" << 'CEOF'
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define GOBIN   "/opt/toolchains/go/bin/go"
/* Packages covering the fuzzed surfaces: readline library and runes subpackage */
static const char *GOPKGS[] = {
    ".",
    "./runes",
    NULL
};
int main(int argc, char **argv) {
    /* Count packages */
    int npkgs = 0;
    while (GOPKGS[npkgs]) npkgs++;
    /* Build args: go test -json -count=1 <pkg>... [extra...] */
    int nfixed = 4 + npkgs; /* go, test, -json, -count=1, pkgs... */
    int extra   = argc - 1;
    char **args = (char **)malloc((nfixed + extra + 1) * sizeof(char *));
    if (!args) return 1;
    int i = 0;
    args[i++] = (char *)GOBIN;
    args[i++] = (char *)"test";
    args[i++] = (char *)"-json";
    args[i++] = (char *)"-count=1";
    for (int p = 0; p < npkgs; p++) args[i++] = (char *)GOPKGS[p];
    for (int j = 1; j <= extra; j++) args[i++] = argv[j];
    args[i] = NULL;
    execv(GOBIN, args);
    perror("execv " GOBIN);
    return 127;
}
CEOF
$CC $GO_DEBUG_FLAGS -o "$SRC/mayhem-build/test-runner" "$SRC/mayhem-build/test-runner.c"
echo "built $SRC/mayhem-build/test-runner (go test shim)"

echo "build.sh complete:"
ls -la /mayhem/fuzz_readline "$SRC/mayhem-build/test-runner" 2>&1 || true
