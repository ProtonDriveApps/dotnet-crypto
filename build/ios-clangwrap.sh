#!/usr/bin/env bash

CLANG=$(xcrun --sdk "$SDK" --find clang)

exec "$CLANG" -target "$TARGET" -isysroot "$SDK_PATH" "$@"
