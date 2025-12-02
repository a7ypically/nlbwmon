#!/bin/sh

# Directory paths
ERROR_DIR="/tmp/ttt/errors"
CURRENT_FILE="/tmp/ttt/current"
CURRENT_ERROR_FILE="$ERROR_DIR/current"

# Check if the current error file exists
if [ -e "$CURRENT_ERROR_FILE" ]; then
    echo "Current error file exists. Doing nothing."
    exit 0
fi

# Ensure the error directory exists
mkdir -p "$ERROR_DIR"

# Get the current date in seconds since 1970
DATE_SECONDS=$(busybox date +%s)

# Grep for errors and save to a new error file
ERROR_FILE="$ERROR_DIR/$DATE_SECONDS"
grep -i error "$CURRENT_FILE" > "$ERROR_FILE"

# Count the number of lines in the grep output
LINE_COUNT=$(wc -l < "$ERROR_FILE")

# If the line count is greater than 100, copy the current file to errors/current
if [ "$LINE_COUNT" -gt 100 ]; then
    cp "$CURRENT_FILE" "$CURRENT_ERROR_FILE"
fi
