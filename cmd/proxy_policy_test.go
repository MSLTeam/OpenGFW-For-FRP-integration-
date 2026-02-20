package cmd

import (
	"testing"

	"github.com/apernet/OpenGFW/ruleset"
)

func TestNormalizeProxyPolicyDefaults(t *testing.T) {
	cfg := normalizeProxyPolicy(cliConfigProxyPolicy{})
	if !cfg.Enabled {
		t.Fatal("expected enabled by default")
	}
	if cfg.HighThreshold != 85 {
		t.Fatalf("high = %d, want 85", cfg.HighThreshold)
	}
	if cfg.MediumThreshold != 70 {
		t.Fatalf("medium = %d, want 70", cfg.MediumThreshold)
	}
}

func TestNormalizeProxyPolicyBounds(t *testing.T) {
	enabled := false
	cfg := normalizeProxyPolicy(cliConfigProxyPolicy{
		Enabled:         &enabled,
		HighThreshold:   65,
		MediumThreshold: 80,
	})
	if cfg.Enabled {
		t.Fatal("expected disabled")
	}
	if cfg.HighThreshold != 65 {
		t.Fatalf("high = %d, want 65", cfg.HighThreshold)
	}
	if cfg.MediumThreshold != 64 {
		t.Fatalf("medium = %d, want 64", cfg.MediumThreshold)
	}
}

func TestWithProxyPolicyRulesPrepends(t *testing.T) {
	cfg := proxyPolicyConfig{
		Enabled:         true,
		HighThreshold:   85,
		MediumThreshold: 70,
	}
	raw := []ruleset.ExprRule{
		{Name: "user_rule", Log: true, Expr: "true"},
	}
	out := withProxyPolicyRules(raw, cfg)
	if len(out) != 5 {
		t.Fatalf("len = %d, want 5", len(out))
	}
	if out[0].Name != "proxy_policy_block_source_penalty" {
		t.Fatalf("first rule = %s", out[0].Name)
	}
	if out[1].Name != "proxy_policy_block_high" {
		t.Fatalf("second rule = %s", out[1].Name)
	}
	if out[4].Name != "user_rule" {
		t.Fatalf("last rule = %s", out[4].Name)
	}
}
