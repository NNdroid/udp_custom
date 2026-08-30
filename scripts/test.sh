#!/bin/bash
set -e

echo "=== Running udp_custom Unit & E2E Tests ==="
go test -v -race ./...
echo "=== All Tests Passed! ==="
