#!/bin/bash

GOOS=linux GOARCH=amd64 go build -o dist/cyphernode_terminal_server.linux-amd64 -ldflags="-s -w"
GOOS=darwin GOARCH=amd64 go build -o dist/cyphernode_terminal_server.darwin-amd64 -ldflags="-s -w"
