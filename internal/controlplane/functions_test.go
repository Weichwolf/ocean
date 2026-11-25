package controlplane

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Weichwolf/ocean/internal/arm"
)

func TestFunctionOperationsRoundTrip(t *testing.T) {
	for _, kind := range []string{updateFunction, integrateFunction} {
		t.Run(kind, func(t *testing.T) {
			id := operationID()
			pending := arm.Operation{ID: id, Group: "test", Actor: "principal", Kind: kind,
				Status: arm.OperationInProgress, StartedAt: time.Now().UTC()}
			data, err := json.Marshal(pending)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := decodeOperation(data, id)
			if err != nil || actual.Kind != pending.Kind || actual.Status != arm.OperationInProgress {
				t.Fatalf("decode %s operation: %v", kind, err)
			}
		})
	}
}
