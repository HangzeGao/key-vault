.PHONY: test coverage-gate

test:
	go test ./internal/protocol/ccsds ./internal/securitystate \
		./internal/crypto/aead ./internal/crypto/suite ./internal/domain/policy
	$(MAKE) -C embedded/tc_security test

coverage-gate:
	bash scripts/coverage_gate.sh
