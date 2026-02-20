package cmd

import (
	"testing"

	"github.com/apernet/OpenGFW/ruleset"
)

func TestNormalizeTrafficPolicyDefaults(t *testing.T) {
	cfg := normalizeTrafficPolicy(cliConfigTrafficPolicy{})
	if !cfg.Enabled {
		t.Fatal("expected enabled by default")
	}
}

func TestNormalizeTrafficPolicyDisabled(t *testing.T) {
	enabled := false
	cfg := normalizeTrafficPolicy(cliConfigTrafficPolicy{Enabled: &enabled})
	if cfg.Enabled {
		t.Fatal("expected disabled")
	}
}

func TestWithTrafficPolicyRulesPrepends(t *testing.T) {
	raw := []ruleset.ExprRule{
		{Name: "user_rule", Log: true, Expr: "true"},
	}
	out := withTrafficPolicyRules(raw, trafficPolicyConfig{Enabled: true})
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if out[0].Name != "traffic_classification_log" {
		t.Fatalf("first rule = %s", out[0].Name)
	}
	if out[1].Name != "user_rule" {
		t.Fatalf("second rule = %s", out[1].Name)
	}
}

func TestWithTrafficPolicyRulesDisabled(t *testing.T) {
	raw := []ruleset.ExprRule{
		{Name: "user_rule", Log: true, Expr: "true"},
	}
	out := withTrafficPolicyRules(raw, trafficPolicyConfig{Enabled: false})
	if len(out) != 1 {
		t.Fatalf("len = %d, want 1", len(out))
	}
	if out[0].Name != "user_rule" {
		t.Fatalf("first rule = %s", out[0].Name)
	}
}
