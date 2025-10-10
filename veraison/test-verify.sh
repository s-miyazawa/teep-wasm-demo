#!/bin/bash

### vvv EDIT HERE vvv
MEDIA_TYPE='application/eat-cwt; profile="urn:ietf:rfc:rfc9711"'
BINARY=../testvector/prebuilt/eat_evidence.attester.es256.cose
### ^^^ EDIT HERE ^^^

if [[ -z "$NONCE" ]]; then
  NONCE=$(cbor2diag.rb -e ${BINARY} | grep -oP "10: h'\K[0-9a-fA-F]+" | base64)
fi
echo $NONCE


if [[ -z "$NONCE" ]]; then
  NONCE_QUERY=
else
  NONCE_QUERY="?nonce=${NONCE}"
fi

SESSION=$(curl -X POST -v --insecure https://localhost:8443/challenge-response/v1/newSession${NONCE_QUERY} 2>&1 | grep -oP '< location: session/\K[0-9a-fA-F-]+')
echo session is: $SESSION

VERIFICATION_RESULT=$(curl -H "Content-Type: ${MEDIA_TYPE}" --data-binary "@${BINARY}" --insecure https://localhost:8443/challenge-response/v1/session/${SESSION})
echo "response from VERAISON: ${VERIFICATION_RESULT}"
RESULT_PAYLOAD_BASE64=$(echo ${VERIFICATION_RESULT} | jq -r '.result' | cut -d '.' -f2) # | base64 -d)
RESULT_PAYLOAD=$(echo ${RESULT_PAYLOAD_BASE64} | awk '{ l=length($0)%4; print $0 (l==2?"==":(l==3?"=":"")) }' | base64 -d)
echo "result: ${RESULT_PAYLOAD}"
