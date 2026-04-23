#!/bin/bash
set -e

# Load environment variables robustly
if [ -f .env ]; then
  # Use allexport to export all variables from the sourced file
  set -a
  source .env
  set +a
fi

if [ -z "$KONG_LICENSE_PATH" ] || [ -z "$OPENROUTER_API_KEY" ]; then
  echo "Error: KONG_LICENSE_PATH and OPENROUTER_API_KEY must be set in .env"
  exit 1
fi

echo "Waiting for Kong Admin API to be ready..."
until curl -s http://localhost:8001 > /dev/null; do
  echo "Kong is unavailable - sleeping 2 seconds"
  sleep 2
done
echo "Kong Admin API is up!"

echo "Applying Kong Enterprise License..."
LICENSE_CONTENT=$(cat "$KONG_LICENSE_PATH" | jq -c .)
curl -i -X POST http://localhost:8001/licenses/ \
  --header "Content-Type: application/json" \
  -d "{\"payload\": $(jq -Rs . <<< "$LICENSE_CONTENT")}"

echo "Creating AI Service..."
curl -i -X POST http://localhost:8001/services \
  --data name=openrouter-service \
  --data url=https://openrouter.ai/api/v1/chat/completions

echo "Creating AI Route..."
curl -i -X POST http://localhost:8001/services/openrouter-service/routes \
  --data "paths[]=/ai" \
  --data name=openrouter-route \
  --data "protocols[]=http" \
  --data "protocols[]=https"

echo "Adding Request Transformer Plugin..."
curl -i -X POST http://localhost:8001/services/openrouter-service/plugins \
  --data name=request-transformer \
  --data "config.add.headers[]=Authorization:Bearer $OPENROUTER_API_KEY" \
  --data "config.add.headers[]=Content-Type:application/json"

echo "Adding AI Prompt Decorator Plugin (PII Sanitizer)..."
curl -i -X POST http://localhost:8001/services/openrouter-service/plugins \
  --data name=ai-prompt-decorator \
  --data "config.prompts.prepend[1].role=system" \
  --data "config.prompts.prepend[1].content=You are a highly capable and friendly Enterprise AI assistant for Volvo Cars team members. You can help with code, analysis, general chat, and answering questions. You maintain a helpful, conversational tone while always keeping Volvo's enterprise security in mind."

echo "Adding Prompt Injection & DLP Guard Plugin (Strict PII/Confidentiality Blocking)..."
curl -i -X POST http://localhost:8001/services/openrouter-service/plugins \
  --data name=ai-prompt-guard \
  --data "config.match_all_roles=true" \
  --data "config.deny_patterns[1]=ignore previous instructions|you are now|forget your rules|act as|jailbreak|bypass security" \
  --data-urlencode "config.deny_patterns[2]=\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35[0-9]{3})[0-9]{11})\b|\b(?:\d[ -]*?){13,16}\b|\b\d{6}[-+]\d{4}\b|\b\d{8}-\d{4}\b|\b[A-HJ-NPR-Z0-9]{17}\b" \
  --data-urlencode "config.deny_patterns[3]=\bsk-(?:live|test|or-v1)-[a-zA-Z0-9]{20,}\b|\b[a-zA-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{7}([a-zA-Z0-9]?){0,16}\b|password is|password=" \
  --data-urlencode "config.deny_patterns[4]=passport number|driver's license|fingerprint|iris scan|gps location|salary details|tax record|financial statement|private key|telematics|can bus|ecu data dump|medical record|diagnosis|prescription|source code|proprietary algorithm|security vulnerability|penetration testing report|non-disclosure agreement|nda "

echo "Adding Rate Limiting Plugin..."
curl -i -X POST http://localhost:8001/services/openrouter-service/plugins \
  --data name=rate-limiting \
  --data config.minute=5 \
  --data config.policy=local

echo "Adding Audit Logging Plugin..."
curl -i -X POST http://localhost:8001/services/openrouter-service/plugins \
  --data name=file-log \
  --data config.path=/tmp/kong-dns-tapir.log \
  --data config.reopen=true

echo "==========================================="
echo "Kong AI Gateway is fully configured!"
echo "==========================================="
