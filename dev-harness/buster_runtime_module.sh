#!/bin/bash
# Buster's console scripts are CRLF, so their command words arrive with a
# trailing CR. Reach the same entry point the scripts name, without the
# corrupted argument, to establish whether Buster's runtime itself works.

run() {
  echo "--- python3 -m buster.cli $* ---"
  timeout 420 python3 -m buster.cli "$@" 2>&1 | head -35
  echo "exit=${PIPESTATUS[0]}"
  echo
}

run version
run status
run doctor
run bootstrap
run start
sleep 5
run status
run caps
run stop
