#!/usr/bin/env bash
set -euo pipefail

mkdir -p keys

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/private.pem
openssl rsa -pubout -in keys/private.pem -out keys/public.pem

echo "✓ keys/private.pem y keys/public.pem generadas"
