# Detailed Sequence Diagram of this Demo

![]()

```mermaid
sequenceDiagram
actor User
participant Broker as TEEP Broker
participant Agent as TEEP Agent
participant SMProcessor as SUIT Manifest Processor
participant TAM
actor Developer as TC Developer
participant Verifier
actor Endorser
actor PVProvider as Reference Value Provider

par Verifier Provisioning 
Endorser ->> Verifier: Certificate for verifying Evidence
PVProvider ->> Verifier: Valid {HWMODEL, MEASUREMENT, ...}
and TAM Provisioning
Developer ->> TAM: SUIT Manifest with `CONDITION`
end

User ->> Broker: request ['app.wasm']
Broker ->> Agent: RequestTA(['app.wasm'])
note over Agent: search for the TA but not found
Agent ->> Broker: getQueryRequest()
Broker ->> TAM: send("tam.example.com", "POST /init ")
TAM -->> Broker: SignedQueryRequest = COSE_Sign1(tamPrivKey, QueryRequest)
Broker ->> Agent: ProcessTeepMessage(SignedQueryRequest)
note over Agent: verify QueryRequest with tamPubKey<br/>generate EAT = COSE_Sign1(attesterPrivKey, claims)<br/>generate SignedQueryResponse = COSE_Sign1(agentKey, QueryResponse)
Agent ->> Broker: getUpdate(SignedQueryResponse)
Broker ->> TAM: send("tam.example.com", "POST /query_response {SignedQueryResponse}")
note over TAM: failed to verify the SignedQueryResponse<br/>because no trusted agentPubKey is found<br/>(pending on trusting the SignedQueryResponse)<br/>extract EAT Evidence from attestation-payload in untrusted SignedQueryResponse
TAM ->> Verifier: EAT Evidence
note over Verifier: Appraise Evidence
Verifier -->> TAM: EAT Attestation Results
note over TAM: verify Attestation Results<br/>retrieve agentPubKey from cnf claim<br/>verify SignedQueryResponse with agentPubKey<br/>determine which SUIT Manifest should be sent<br/>generate SignedUpdate = COSE_Sign1(tamPrivKey, Update)
TAM ->> Broker: SignedUpdate
Broker ->> Agent: ProcessTeepMessage(SignedUpdate)
note over Agent: verify SignedUpdate<br/>retrieve manifest
Agent ->> SMProcessor: ProcessSuitManifest(manifest)
SMProcessor ->> Broker: store(['app.wasm'], h'{content of app.wasm}')
Broker -->> SMProcessor: OK
SMProcessor -->> Agent: OK
Agent -->> Broker: OK
Broker -->> User: OK
note over User: iwasm ['app.wasm']
```

- Pre-shared Configurations (hardly coded or stored in each components)
    - The TEEP Agent in the Attester holds public keys of the TAM's and the Trusted Component Signer
    - The TAM holds the public key of Verifier, VERAISON
- Provisioning
    - The Endorser and the Reference Value Provider creates CoRIM using public key of the Attester, golden value of measurements, etc.
    - The Trusted Component Signer creates a SUIT Manifest with `['app.wasm']` binary
- The User wants to run `app.wasm`, which will be provided by a TAM (Trusted Application Manager)
    - executes a request command triggering the TEEP Broker and the TEEP Agent
- The TEEP Agent POSTs an empty message to the TAM HTTP endpoint (defined [here](https://datatracker.ietf.org/doc/html/draft-ietf-teep-otrp-over-http-09#section-6.2))
    - indicating that the TEEP Agent wants get QueryRequest from the TAM
- The TAM sends TEEP QueryRequest as HTTP POST response
    - The value of `challenge` should be used generate EAT Evidence, stored in the `eat_nonce` claim
    - The QueryRequest message is signed by the TAM usign `COSE_Sign1` (see [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) for detail), `ESP256` (ECDSA with SHA-256 and P-256 curve, see [IANA](https://www.iana.org/assignments/cose/cose.xhtml))
- The TEEP Agent handles the QueryRequest
    - Verifying the `COSE_Sign1` message with the TAM's public key
    - 
- Finish
    - Now the User 