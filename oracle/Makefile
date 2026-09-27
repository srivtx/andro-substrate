# oracle/Makefile -- ground-truth oracle tooling.
#
# Targets:
#   make schema-check   validate both example recordings against the schema
#   make test           negative tests: prove the validator actually rejects
#                       bad input, so a green schema-check is not vacuous
#   make capture APKDIR=<dir> [DURATION=<s> [OUT=<file>]] [PACKAGE=<name>]
#                       run the recorder against an attached Android device
#
# Nothing here needs a device except `capture`.

SHELL       := /bin/sh
NODE        ?= node
HERE        := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
SCHEMA      := $(HERE)/schema/ground-truth.schema.json
EX_DIR      := $(HERE)/schema/examples
VALIDATOR   := $(HERE)/recorder/validate.mjs
RECORDER    := $(HERE)/recorder/adb-recorder.sh
MINIMAL     := $(EX_DIR)/minimal.recording.json
FULL        := $(EX_DIR)/full.recording.json
TMP         := $(HERE)/.tmp-test

DURATION    ?= 90
OUT         ?= $(HERE)/recordings/$(notdir $(APKDIR)).recording.json
PACKAGE     ?=
ACTIVITY    ?=
SERIAL      ?=

export DURATION

.PHONY: all schema-check test capture help clean lint-shell

all: schema-check test

help:
	@sed -n 's/^# \{0,4\}//p' $(lastword $(MAKEFILE_LIST)) | sed -n '1,20p'

# ---------------------------------------------------------------------------
# schema-check: both fixtures must validate, and the fixtures must be
# self-consistent. This is the gate the whole oracle hangs off.
# ---------------------------------------------------------------------------
schema-check:
	@echo "== schema-check: $(SCHEMA)"
	@$(NODE) -e 'JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))' $(SCHEMA) \
		|| { echo "schema is not valid JSON"; exit 1; }
	@$(NODE) $(VALIDATOR) $(MINIMAL) $(FULL)
	@echo "== schema-check: PASS (both example recordings are SYNTHETIC FIXTURES, not captures)"

# ---------------------------------------------------------------------------
# test: negative tests. A validator that cannot fail is not a validator, and a
# schema-check that only ever sees good input proves nothing. Each case below
# takes a known-good fixture, breaks exactly one thing, and asserts that the
# validator rejects it.
# ---------------------------------------------------------------------------
test: schema-check
	@sh $(HERE)/recorder/negative-tests.sh

lint-shell:
	@sh -n $(RECORDER) && echo "sh -n: OK"
	@command -v shellcheck >/dev/null 2>&1 && shellcheck -s sh $(RECORDER) || echo "shellcheck not installed; skipped"

# ---------------------------------------------------------------------------
# capture: run the recorder. Requires a reachable Android reference device.
#   make capture APKDIR=corpus/apks/org.fdroid.fdroid DURATION=90
# ---------------------------------------------------------------------------
capture:
	@if [ -z "$(APKDIR)" ]; then \
		echo "usage: make capture APKDIR=<dir containing the .apk> [DURATION=90] [OUT=path] [PACKAGE=name] [ACTIVITY=component] [SERIAL=...]"; \
		exit 2; \
	fi
	@if [ ! -d "$(APKDIR)" ]; then \
		echo "no such directory: $(APKDIR)"; exit 2; \
	fi
	@mkdir -p $(dir $(OUT))
	@echo "capturing $(APKDIR) for $(DURATION)s -> $(OUT)"
	sh $(RECORDER) \
		--apk-dir "$(APKDIR)" \
		--out "$(OUT)" \
		--duration "$(DURATION)" \
		$(if $(PACKAGE),--package "$(PACKAGE)") \
		$(if $(ACTIVITY),--activity "$(ACTIVITY)") \
		$(if $(SERIAL),--serial "$(SERIAL)")

clean:
	rm -rf $(TMP) $(HERE)/recordings
