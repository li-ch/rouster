#!/bin/sh
# Minimal entrypoint for the frr-testbed image.
#
# The smoke suite never relies on it: every docker run in scripts/
# overrides the entrypoint (--entrypoint sleep ... infinity, or
# --entrypoint sh). This stub just execs the command so a bare
# `docker run frr-testbed …` behaves sanely (PID 1 = the command).
set -eu
exec "$@"
