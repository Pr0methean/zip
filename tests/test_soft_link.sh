#!/bin/bash

# Check if a zip file is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_zip_file>"
    exit 1
fi

ZIP_FILE=$1
TEMP_DIR=$(mktemp -d)

# Unpack the zip file to the temporary directory
unzip "$ZIP_FILE" -d "$TEMP_DIR"

# Define the path to the symbolic link
SYMLINK_PATH="$TEMP_DIR/pandoc-3.2-arm64/bin/pandoc-lua"

# Check if the symbolic link exists
if [ -L "$SYMLINK_PATH" ]; then
    # Read the target of the symbolic link
    TARGET=$(readlink "$SYMLINK_PATH")
    echo "The symbolic link $SYMLINK_PATH points to: $TARGET"
    
    # Assert that it links to 'pandoc'
    if [ "$TARGET" == "pandoc" ]; then
        echo "Assertion passed: The symbolic link points to 'pandoc'."
    else
        echo "Assertion failed: The symbolic link does not point to 'pandoc'."
        exit 1
    fi
else
    echo "The file $SYMLINK_PATH is not a symbolic link or does not exist."
    exit 1
fi

# Clean up the temporary directory
rm -rf "$TEMP_DIR"
