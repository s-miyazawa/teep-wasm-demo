# Adding a Scheme for your Profile

> [!NOTE]
> You can try the generic-eat scheme with https://github.com/kentakayama/services which is forked from https://github.com/veraison/services .
> In this article, some of the essence are described.

## Step1: Register your Scheme to VERAISON

item | example definition 
--|--
SchemeName | `generic-eat`
Profile | [`The Constrained Device Standard Profile`](https://www.rfc-editor.org/rfc/rfc9711.html#name-the-constrained-device-stan)
its identifier | `urn:ietf:rfc:rfc9711`
Media Type for your Evidence Profile | `application/eat+cwt`


Then, make a directory for your profile (`scheme/generic-eat`) and

```go
/* scheme/generic-eat/scheme.go */

const SchemeName = "generic-eat"

var EvidenceMediaTypes = []string{
	`application/eat+cwt; eat_profile="urn:ietf:rfc:rfc9711"`,
}
```

```makefile
.DEFAULT_GOAL := test

GOPKG := github.com/veraison/services/scheme/generic-eat
SRCS := $(wildcard *.go)

include ../../mk/common.mk
include ../../mk/lint.mk
include ../../mk/pkg.mk
include ../../mk/test.mk
```

```go
/* scheme/evidence_handler.go */

package generic_eat

import (
	"github.com/veraison/ear"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
)

type EvidenceHandler struct {
}

func (s EvidenceHandler) GetName() string {
	return "generic-eat-evidence-handler"
}

func (s EvidenceHandler) GetAttestationScheme() string {
	return SchemeName
}

func (s EvidenceHandler) GetSupportedMediaTypes() []string {
	return EvidenceMediaTypes
}

func (s EvidenceHandler) ExtractClaims(
	token *proto.AttestationToken,
	trustAnchors []string,
) (map[string]interface{}, error) {
	claims := make(map[string]interface{})

	return claims, nil
}

func (s EvidenceHandler) ValidateEvidenceIntegrity(
	token *proto.AttestationToken,
	trustAnchors []string,
	endorsements []string,
) error {
	return nil
}

func (s EvidenceHandler) AppraiseEvidence(
	ec *proto.EvidenceContext,
	endorsementsString []string,
) (*ear.AttestationResult, error) {
	result := handler.CreateAttestationResult(SchemeName)

	// always "affirming"
	appraisal := result.Submods[SchemeName]
	*appraisal.Status = ear.TrustTierAffirming

	return result, nil
}
```

Add your scheme to be built
```diff
diff --git a/scheme/Makefile b/scheme/Makefile
index c3336e1..19c5164 100644
--- a/scheme/Makefile
+++ b/scheme/Makefile
@@ -4,6 +4,7 @@
 SUBDIR := common
 SUBDIR += arm-cca
 SUBDIR += riot
+SUBDIR += generic-eat
 SUBDIR += psa-iot
 SUBDIR += tpm-enacttrust
 SUBDIR += parsec-tpm
```

```sh
$ make native-deploy
```

It will display like this on success.

```text
=============================================================================
Veraison has been deployed natively on the local system. If you're using
bash, you can access to the frontend via the following command:

        source /home/ken/veraison-deployment/env/env.bash

(there is an equivalent env.zsh for zsh). You can then view frontend help via

        veraison -h

In addition to the veraison frontend, env.bash will also set up aliases for
cocli, evcli, and polcli utilities.

=============================================================================
```

References
- [RFC 9711: The Entity Attestation Token (EAT)](https://www.rfc-editor.org/rfc/rfc9711.html) for the profile
- [RFC 9782: Entity Attestation Token (EAT) Media Types](https://www.rfc-editor.org/rfc/rfc9782.html)
- [draft-ietf-rats-ar4si: Attestation Results for Secure Interactions](https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si)

## Step2: Post Evidence

Since we do not provide any Trust Anchors nor Endorsements, the verification should fail.
However, let's check that our shceme is regiested.

```sh
$ tail -n 30 -f ~/veraison-deployment/logs/vts-stdout.log 
INFO    policy  agent created   {"agent": "opa"}
INFO    loading attestation schemes
INFO    Evidence media types:
INFO            application/eat-collection; profile="http://arm.com/CCA-SSD/1.0.0"
INFO            application/psa-attestation-token
INFO            application/eat+cwt; eat_profile="tag:psacertified.org,2023:psa#tfm"
INFO            application/vnd.enacttrust.tpm-evidence
INFO            application/vnd.parallaxsecond.key-attestation.cca
INFO            application/eat+cwt; eat_profile="tag:psacertified.org,2019:psa#legacy"
INFO            application/eat-cwt; profile="urn:ietf:rfc:rfc9711"
INFO            application/vnd.parallaxsecond.key-attestation.tpm
INFO            application/eat-cwt; profile="http://arm.com/psa/2.0.0"
INFO            application/pem-certificate-chain
INFO    Endorsement media types:
INFO            application/rim+cose; profile="http://arm.com/cca/ssd/1"
INFO            application/corim-unsigned+cbor; profile="tag:github.com/parallaxsecond,2023-03-03:cca"
INFO            application/rim+cose; profile="http://arm.com/cca/realm/1"
INFO            application/corim-unsigned+cbor; profile="tag:github.com/parallaxsecond,2023-03-03:tpm"
INFO            application/corim-unsigned+cbor; profile="http://arm.com/psa/iot/1"
INFO            application/rim+cose; profile="http://arm.com/psa/iot/1"
INFO            application/corim-unsigned+cbor; profile="http://enacttrust.com/veraison/1.0.0"
INFO            application/rim+cose; profile="http://enacttrust.com/veraison/1.0.0"
INFO            application/rim+cose; profile="tag:github.com/parallaxsecond,2023-03-03:tpm"
INFO            application/rim+cose; profile="tag:github.com/parallaxsecond,2023-03-03:cca"
INFO            application/corim-unsigned+cbor; profile="http://arm.com/cca/ssd/1"
INFO            application/corim-unsigned+cbor; profile="http://arm.com/cca/realm/1"
INFO    loading EAR signer
INFO    initializing service
INFO    vts     loading TLS credentials
INFO    vts     listening for GRPC requests     {"address": ":50051"}
```

You will find the line `application/eat-cwt; profile="urn:ietf:rfc:rfc9711"` with other media types.

Then, let's post a verification request.
Edit [`test_verify.sh`](./test-verify.sh) with content:

```sh
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

```

To run this script, we use [cbor-diag](https://rubygems.org/gems/cbor-diag/) to extract `/ eat_evidence / 10: h'NONCE'` from CBOR/COSE evidence.
Instead, you can pass the `NONCE` variable like `NONCE=OTQ4Rjg4NjBEMTNBNDYzRThFCg== ./test-verify.sh` .

You will see a result

```sh
$ ./test-verify.sh
result: {"ear.verifier-id":{"build":"0.0.2510+b8cd07b","developer":"Veraison Project"},"eat_nonce":"OTQ4Rjg4NjBEMTNBNDYzRThFCg==","eat_profile":"tag:github.com,2023:veraison/ear","iat":1760106976,"submods":{"generic-eat":{"ear.appraisal-policy-id":"policy:generic-eat","ear.status":"contraindicated","ear.trustworthiness-vector":{"configuration":99,"executables":99,"file-system":99,"hardware":99,"instance-identity":99,"runtime-opaque":99,"sourced-data":99,"storage-opaque":99},"ear.veraison.policy-claims":{"problem":"no trust anchor for evidence"}}}}
```

## Step 3: Register Handlers for Endorsements and Reference Values

You need to provide important handlers:
- `Decode()` to `endorsement_handler.go`
  - `RefValExtractor` and `TaExtractor` for scheme-specific callback functions for `UnsignedCorimDecoder()` and `SignedCorimDecoder()`
- `SynthKeysFromRefValue()` and `SynthKeysFromTrustAnchor()` to `store_handler.go`
  - the extracted Reference Value and Trust Anchor will be stored into the key-value store

```sh
$ curl -X POST --data-binary "@../testvector/prebuilt/corim-generic-eat.cbor" -H 'Content-Type: application/corim-unsigned+cbor; profile="http://example.com/corim/profile"' --insecure https://localhost:9443/endorsement-provisioning/v1/submit
{"status":"success","expiry":"2025-10-20T14:30:11Z"}

$ veraison show-stores
TRUST ANCHORS:
--------------
{
  "scheme": "GENERIC_EAT",
  "type": "trust anchor",
  "subType": "",
  "attributes": {
    "ak-pub": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\niTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n-----END PUBLIC KEY-----",
    "instance-id": "0198f50a-4ff6-c058-61c8-860d13a638ea"
  }
}

ENDORSEMENTS:
-------------
{
  "scheme": "GENERIC_EAT",
  "type": "reference value",
  "subType": "",
  "attributes": {
    "instance-id": "0198f50a-4ff6-c058-61c8-860d13a638ea",
    "version": {
      "value": "1.3.4",
      "scheme": "multipartnumeric"
    }
  }
}

POLICIES:
-------------


$ ./test-verify.sh
result: {"ear.verifier-id":{"build":"N/A","developer":"Veraison Project"},"eat_nonce":"OTQ4Rjg4NjBEMTNBNDYzRThFCg==","eat_profile":"tag:github.com,2023:veraison/ear","iat":1761181365,"submods":{"GENERIC_EAT":{"ear.appraisal-policy-id":"policy:GENERIC_EAT","ear.status":"affirming","ear.trustworthiness-vector":{"configuration":0,"executables":0,"file-system":0,"hardware":0,"instance-identity":0,"runtime-opaque":0,"sourced-data":0,"storage-opaque":0}}}}
evidence: 18([<< {1: -7} >>, {}, << {8: {1: {1: 2, -1: 1, -2: h'5886CD61DD875862E5AAA820E7A15274C968A9BC96048DDCACE32F50C3651BA3', -3: h'9EED8125E932CD60C0EAD3650D0A485CF726D378D1B016ED4298B2961E258F1B'}, 3: h'E96788B10B1610ABE478F9CE8DCFE2304C0911DD8CFEADDE25EC30CCB5A7B5AF'}, 10: h'948F8860D13A463E8E', 256: h'0198F50A4FF6C05861C8860D13A638EA', 258: h'894823', 259: h'549DCECC8B987C737B44E40F7C635CE8', 260: ["1.3.4", 1], 265: "urn:ietf:rfc:rfc9711"} >>, h'316C3C092BEDF27520CBAD7791E13C6F5F5D94CDB997C3EA3A90F1FBAABA8FE3B930D8D4B6B4434AF577A75A128806FAC94F0054D9AB6F5629E261F6A75CEF6F'])
```

