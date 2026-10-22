.PHONY: test go-security-gate c-hardening-gate external-vector-gate downlink-gate coverage-gate release-gate

test:
	go test ./internal/protocol/ccsds ./internal/securitystate \
		./internal/crypto/aead ./internal/crypto/suite ./internal/domain/policy
	$(MAKE) -C embedded/tc_security test
	go test ./internal/downlink
	$(MAKE) -C embedded/downlink_security test

go-security-gate:
	bash scripts/go_security_gate.sh

c-hardening-gate:
	bash scripts/c_hardening_gate.sh

external-vector-gate:
	bash scripts/external_vector_gate.sh

coverage-gate:
	bash scripts/coverage_gate.sh

downlink-gate:
	bash scripts/downlink_gate.sh

release-gate:
	bash scripts/release_gate.sh
