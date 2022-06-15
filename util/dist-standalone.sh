#!/usr/bin/env bash

# Get path to output
DIST_ARCHIVE=./dist/standalone/little-log-scan.zip

# Delete if it already exists
if [[ -f "$DIST_ARCHIVE" ]]; then
  rm -f "$DIST_ARCHIVE"
fi

# Zip up current build
7z a -tZIP "$DIST_ARCHIVE" \
  dist/package/ \
  bin/ \
  LICENSE \
  CHANGES.md \
  README.md \
  little-log-scan.sh \
  little-log-scan.bat