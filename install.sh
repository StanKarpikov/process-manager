#!/bin/bash
set -e

TARGET_DIR="target/release"
PROCESS_MANAGER="$TARGET_DIR/process_manager"

# Parse named parameters
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-release-folder=*)
            OUTPUT_DIR="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown parameter: $1"
            echo "Usage: $0 --bin-release-folder=PATH"
            exit 1
            ;;
    esac
done

if [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 --bin-release-folder=PATH"
    exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: $TARGET_DIR does not exist. Have you built the project with 'cargo build --release'?"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "Copying Process Manager to $OUTPUT_DIR/"
cp "$PROCESS_MANAGER" "$OUTPUT_DIR/"

echo "Process Manager Installed to $OUTPUT_DIR/"
