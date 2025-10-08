#!/bin/bash
echo -ne "\nRun TAM Server.\n"
DIR=`dirname "${0}"`

QUERY_REQUEST_FILE="${DIR}/query_request_cose.cbor"
UPDATE_FILE="${DIR}/update_cose.cbor"

function send_teep_cbor {
    # send_teep_cbor PATH_TO_CBOR_FILE
    CBOR_FILE=$1
    if [ ! -e "${CBOR_FILE}" ]; then
        echo "ERROR: File \"${CBOR_FILE}\" does not exist"
        exit
    fi
    CBOR_FILE_SIZE=`du -b "${CBOR_FILE}" | cut -f1`
    ( \
    echo "HTTP/1.1 200 OK"; \
    echo "Content-Type: application/teep+cbor"; \
    echo "Content-Length: ${CBOR_FILE_SIZE}"; \
    echo "Server: Bar/2.2"; \
    echo "Cache-Control: no-store"; \
    echo "X-Content-Type-Options: nosniff"; \
    echo "Content-Security-Policy: default-src 'none'"; \
    echo "Referrer-Policy: no-referrer"; \
    echo; \
    cat ${CBOR_FILE} \
    ) | nc -l 8080
}

echo -ne "\nSend TEEP/HTTP QueryRequest.\n"
send_teep_cbor $QUERY_REQUEST_FILE

echo -ne "\nSend TEEP/HTTP Update.\n"
send_teep_cbor $UPDATE_FILE

( \
echo "HTTP/1.1 204 No Content"; \
echo "Server: Bar/2.2"; \
echo; \
) | nc -l 8080

echo -ne "\nSend TEEP/HTTP successful response.\n"
