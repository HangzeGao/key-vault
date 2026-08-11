package main

import "testing"

func TestActivationRequiresExplicitApprovalContext(t *testing.T) {
	for _, value := range []options{{}, {tenantID: "tenant"}, {tenantID: "tenant", reason: "rotate"}} {
		if value.validate() == nil {
			t.Fatalf("incomplete options accepted: %+v", value)
		}
	}
	if err := (options{tenantID: "tenant", reason: "rotate", ticketID: "CHG-1"}).validate(); err != nil {
		t.Fatal(err)
	}
}
