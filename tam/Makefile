.PHONY: run-server run-client clean

run-tam-server:
	go run ./cmd/tam4wasm-mock

run-client:
	./libteep/bin/teep_wasm_get

clean:
	rm -f app.wasm manifest.app.wasm.0.suit
