.PHONY: test external-vector-gate coverage-gate release-gate

test:
	go test ./internal/protocol/ccsds ./internal/securitystate \
		./internal/crypto/aead ./internal/crypto/suite ./internal/domain/policy
	$(MAKE) -C embedded/tc_security test

external-vector-gate:
	bash scripts/external_vector_gate.sh

coverage-gate:
	bash scripts/coverage_gate.sh

release-gate:
	bash scripts/release_gate.sh
