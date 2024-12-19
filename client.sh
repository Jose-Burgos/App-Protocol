#!/bin/bash

if [ $# -ne 3 ]; then
  echo "Usage: $0 <host> <port> <commands_file>"
  exit 1
fi

HOST="$1"
PORT="$2"
COMMANDS_FILE="$3"

echo "Compiling the client program..."
gcc -W -fsanitize=address -std=c11 -o ./src/client.o ./src/client.c
if [ $? -ne 0 ]; then
  echo "Error: Compilation failed."
  exit 1
fi

echo "Running the client program..."
./src/client.o "$HOST" "$PORT" "$COMMANDS_FILE"
