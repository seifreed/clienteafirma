#!/usr/bin/env bash
#
# scripts/run-fuzz.sh — runs a Jazzer fuzz harness from afirma-fuzz.
#
# Usage:
#   scripts/run-fuzz.sh DerValueFuzzer        [duration_seconds]
#   scripts/run-fuzz.sh TriphaseDataFuzzer    [duration_seconds]
#   scripts/run-fuzz.sh ProtocolUriFuzzer     [duration_seconds]
#
# Defaults to 60 s. Corpora and crashes land in afirma-fuzz/target/fuzz/<harness>/.
# Requires JDK 21+ and a Linux/macOS host (Jazzer's native lib is per-platform).
#
# CI usage: pass `--max_total_time=<seconds>` via $JAZZER_OPTS for headless runs.

set -euo pipefail

HARNESS="${1:?harness class name (e.g. DerValueFuzzer)}"
DURATION="${2:-60}"
PKG="es.gob.afirma.fuzz"
MODULE_DIR="$(cd "$(dirname "$0")/.." && pwd)/afirma-fuzz"
TARGET_DIR="$MODULE_DIR/target"
CORPUS_DIR="$TARGET_DIR/fuzz/$HARNESS/corpus"
CRASH_DIR="$TARGET_DIR/fuzz/$HARNESS/crashes"

mkdir -p "$CORPUS_DIR" "$CRASH_DIR"

# Build the module + collect runtime classpath.
(cd "$MODULE_DIR/.." && mvn -B -q -P fuzz,env-dev -pl afirma-fuzz -am \
	-DskipTests -Ddependency-check.skip=true install)

CP=$(cd "$MODULE_DIR/.." && mvn -q -P fuzz,env-dev -pl afirma-fuzz \
	dependency:build-classpath -DincludeScope=runtime -Dmdep.outputFile=/dev/stdout 2>/dev/null |
	tail -1)
CP="$MODULE_DIR/target/classes:$CP"

# Resolve jazzer driver from local Maven repo (downloaded by the dependency above).
JAZZER_VERSION="${JAZZER_VERSION:-0.24.0}"
JAZZER_HOME="${HOME}/.m2/repository/com/code-intelligence/jazzer/${JAZZER_VERSION}"
if [[ ! -f "$JAZZER_HOME/jazzer-${JAZZER_VERSION}.jar" ]]; then
	(cd "$MODULE_DIR/.." && mvn -q dependency:get \
		-Dartifact="com.code-intelligence:jazzer:${JAZZER_VERSION}")
fi

JAVA_OPTS=(
	--add-opens=java.base/sun.security.x509=ALL-UNNAMED
	--add-opens=java.base/sun.security.util=ALL-UNNAMED
	--enable-native-access=ALL-UNNAMED
)

JAZZER_EXTRA_OPTS=()
if [[ -n "${JAZZER_OPTS:-}" ]]; then
	read -r -a JAZZER_EXTRA_OPTS <<<"$JAZZER_OPTS"
fi

JAZZER_ARGS=(
	--target_class="${PKG}.${HARNESS}"
	--reproducer_path="$CRASH_DIR"
	-max_total_time="$DURATION"
)
if ((${#JAZZER_EXTRA_OPTS[@]} > 0)); then
	JAZZER_ARGS+=("${JAZZER_EXTRA_OPTS[@]}")
fi
JAZZER_ARGS+=("$CORPUS_DIR")

exec java "${JAVA_OPTS[@]}" \
	-cp "$JAZZER_HOME/jazzer-${JAZZER_VERSION}.jar:$CP" \
	com.code_intelligence.jazzer.Jazzer \
	"${JAZZER_ARGS[@]}"
