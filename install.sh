#!/bin/bash
set -e

TARGET_DIR="target/release"
PROCESS_MANAGER="$TARGET_DIR/process_manager"

if [ -z "$1" ]; then
    echo "Usage: $0 <output_directory>"
    exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: $TARGET_DIR does not exist. Have you built the project with 'cargo build --release'?"
    exit 1
fi

OUTPUT_DIR="$1"
mkdir -p "$OUTPUT_DIR"

echo "Copying Process Manager to $OUTPUT_DIR/"
cp "$PROCESS_MANAGER" "$OUTPUT_DIR/"

echo "Process Manager Installed to $OUTPUT_DIR/"
