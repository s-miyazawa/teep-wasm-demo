package resources

import _ "embed"

var (
	//go:embed query_request_cose.cbor
	QueryRequestCOSE []byte

	//go:embed query_request.cbor
	QueryRequestPlain []byte

	//go:embed update.tam.esp256.cose
	UpdateCOSE []byte

	//go:embed update.cbor
	UpdatePlain []byte
)
