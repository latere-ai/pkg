package otel

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
)

// attrValue returns the value of key on res, and whether it was present.
func attrValue(res *resource.Resource, key string) (string, bool) {
	for _, kv := range res.Attributes() {
		if string(kv.Key) == key {
			return kv.Value.Emit(), true
		}
	}
	return "", false
}

func TestServiceResource_HonoursResourceAttributesEnv(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "team=infra,tier=edge")

	res, err := serviceResource(context.Background(), "svc", "1.0")
	if err != nil {
		t.Fatalf("serviceResource: %v", err)
	}

	for key, want := range map[string]string{"team": "infra", "tier": "edge"} {
		got, ok := attrValue(res, key)
		if !ok {
			t.Errorf("attribute %q missing; OTEL_RESOURCE_ATTRIBUTES was dropped", key)
			continue
		}
		if got != want {
			t.Errorf("attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestServiceResource_ExplicitNameBeatsServiceNameEnv(t *testing.T) {
	// A deployment that sets OTEL_SERVICE_NAME must not be able to relabel a
	// service out from under the name its code passed to Bootstrap, or two
	// services could collide on one identity in the backend.
	t.Setenv("OTEL_SERVICE_NAME", "from-env")

	res, err := serviceResource(context.Background(), "from-code", "1.0")
	if err != nil {
		t.Fatalf("serviceResource: %v", err)
	}

	got, ok := attrValue(res, "service.name")
	if !ok {
		t.Fatal("service.name missing")
	}
	if got != "from-code" {
		t.Errorf("service.name = %q, want %q", got, "from-code")
	}
}

func TestServiceResource_UsesCurrentEnvironmentKey(t *testing.T) {
	t.Setenv("LATERE_ENV", "staging")

	res, err := serviceResource(context.Background(), "svc", "1.0")
	if err != nil {
		t.Fatalf("serviceResource: %v", err)
	}

	got, ok := attrValue(res, "deployment.environment.name")
	if !ok {
		t.Fatal("deployment.environment.name missing")
	}
	if got != "staging" {
		t.Errorf("deployment.environment.name = %q, want %q", got, "staging")
	}
	// semconv renamed this key at v1.27. Emitting the old one too would split
	// every environment filter across two attributes.
	if _, ok := attrValue(res, "deployment.environment"); ok {
		t.Error("deprecated deployment.environment is still emitted")
	}
}

func TestServiceResource_DefaultsEnvironmentToProduction(t *testing.T) {
	t.Setenv("LATERE_ENV", "")

	res, err := serviceResource(context.Background(), "svc", "1.0")
	if err != nil {
		t.Fatalf("serviceResource: %v", err)
	}

	got, _ := attrValue(res, "deployment.environment.name")
	if got != "production" {
		t.Errorf("deployment.environment.name = %q, want %q", got, "production")
	}
}

func TestServiceResource_CarriesSDKIdentityAndSchema(t *testing.T) {
	res, err := serviceResource(context.Background(), "svc", "1.0")
	if err != nil {
		t.Fatalf("serviceResource: %v", err)
	}

	if _, ok := attrValue(res, string(attribute.Key("telemetry.sdk.name"))); !ok {
		t.Error("telemetry.sdk.name missing; the SDK detector did not run")
	}
	if res.SchemaURL() == "" {
		t.Error("schema URL is empty; the backend cannot version-resolve these attributes")
	}
}

func TestServiceResource_SetsNameAndVersion(t *testing.T) {
	res, err := serviceResource(context.Background(), "svc", "2.3.4")
	if err != nil {
		t.Fatalf("serviceResource: %v", err)
	}

	if got, _ := attrValue(res, "service.name"); got != "svc" {
		t.Errorf("service.name = %q, want %q", got, "svc")
	}
	if got, _ := attrValue(res, "service.version"); got != "2.3.4" {
		t.Errorf("service.version = %q, want %q", got, "2.3.4")
	}
}
