#!/usr/bin/env bash
set -euo pipefail
# Fail if any non-test source file in cmd/mcpserver (recursively) uses
# bare mcp.NewToolResultError, bypassing mcpToolError.
#
# Uses find + grep instead of a shell glob so this works if the package
# is later reorganized into subdirectories.

VIOLATIONS=$(find cmd/mcpserver -name '*.go' \
    ! -name '*_test.go' \
    ! -name 'mcperror.go' \
    -exec grep -Hn 'mcp\.NewToolResultError(' {} + 2>/dev/null \
    | grep -v 'mcpToolError' || true)

if [ -n "$VIOLATIONS" ]; then
    echo "ERROR: Found bare mcp.NewToolResultError() outside mcpToolError helper:"
    echo "$VIOLATIONS"
    echo ""
    echo "Use mcpToolError(code, message, details) instead."
    exit 1
fi

echo "OK: all MCP error call sites use mcpToolError"
