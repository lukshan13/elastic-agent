// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"go.opentelemetry.io/collector/confmap"
)

func TestCheckAdditionsOnlyCollision(t *testing.T) {
	merged := map[string]any{
		"exporters": map[string]any{
			"elasticsearch/default": map[string]any{},
		},
	}
	t.Run("collision", func(t *testing.T) {
		additional := map[string]any{
			"exporters": map[string]any{
				"elasticsearch/default": map[string]any{},
			},
		}
		err := checkAdditionsOnlyCollision(merged, additional)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exporters")
		assert.Contains(t, err.Error(), "elasticsearch/default")
	})
	t.Run("new exporter ok", func(t *testing.T) {
		additional := map[string]any{
			"exporters": map[string]any{
				"otlp/mydest": map[string]any{"endpoint": "localhost:4317"},
			},
		}
		assert.NoError(t, checkAdditionsOnlyCollision(merged, additional))
	})
	t.Run("service pipeline name collision", func(t *testing.T) {
		merged := map[string]any{
			"service": map[string]any{
				"pipelines": map[string]any{
					"logs/existing": map[string]any{
						"receivers": []any{"r"},
						"exporters": []any{"e"},
					},
				},
			},
		}
		additional := map[string]any{
			"service": map[string]any{
				"pipelines": map[string]any{
					"logs/existing": map[string]any{
						"receivers": []any{"r2"},
						"exporters": []any{"e2"},
					},
				},
			},
		}
		err := checkAdditionsOnlyCollision(merged, additional)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service.pipelines reuses")
	})
	t.Run("unknown top-level", func(t *testing.T) {
		additional := map[string]any{
			"providers": map[string]any{},
		}
		err := checkAdditionsOnlyCollision(merged, additional)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "providers")
	})
}

func TestLoadAndValidateCustomOTelYAML(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := loadAndValidateCustomOTelYAML(filepath.Join(t.TempDir(), "nope.yml"))
		require.Error(t, err)
		assert.ErrorIs(t, err, errCustomOTelFileNotExist)
	})
	t.Run("invalid yaml", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bad.yml")
		require.NoError(t, os.WriteFile(p, []byte("[unclosed"), 0o600))
		_, err := loadAndValidateCustomOTelYAML(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse custom otel config")
	})
	t.Run("disallowed top-level", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.yml")
		require.NoError(t, os.WriteFile(p, []byte("unknown_top_level: {}\n"), 0o600))
		_, err := loadAndValidateCustomOTelYAML(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed top-level keys")
	})
	t.Run("service empty map rejected", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.yml")
		require.NoError(t, os.WriteFile(p, []byte("service: {}\n"), 0o600))
		_, err := loadAndValidateCustomOTelYAML(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service must not be empty")
	})
	t.Run("service rejects unknown keys", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.yml")
		yml := "" +
			"receivers:\n  otlp/in:\n    protocols:\n      grpc:\n        endpoint: 0.0.0.0:4317\n" +
			"exporters:\n  otlp/out:\n    endpoint: 127.0.0.1:4317\n    tls:\n      insecure: true\n" +
			"service:\n  pipelines:\n    custom/x:\n      receivers: [otlp/in]\n      exporters: [otlp/out]\n  foo: {}\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		_, err := loadAndValidateCustomOTelYAML(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pipelines, extensions, and telemetry")
		assert.Contains(t, err.Error(), "foo")
	})
	t.Run("service requires non-empty workload", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.yml")
		yml := "service:\n  pipelines: {}\n  extensions: []\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		_, err := loadAndValidateCustomOTelYAML(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one non-empty")
	})
	t.Run("valid service extensions only", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.yml")
		yml := "" +
			"extensions:\n  health_check/custom:\n    endpoint: 0.0.0.0:13134\n" +
			"service:\n  extensions: [health_check/custom]\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		_, err := loadAndValidateCustomOTelYAML(p)
		require.NoError(t, err)
	})
	t.Run("service pipeline references undefined receiver", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.yml")
		yml := "" +
			"receivers:\n  otlp/in:\n    protocols:\n      grpc:\n        endpoint: 0.0.0.0:4317\n" +
			"exporters:\n  otlp/out:\n    endpoint: 127.0.0.1:4317\n    tls:\n      insecure: true\n" +
			"service:\n  pipelines:\n    custom/ingest:\n      receivers: [otlp/wrong]\n      exporters: [otlp/out]\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		_, err := loadAndValidateCustomOTelYAML(p)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not defined under receivers")
	})
	t.Run("valid service pipelines with custom components", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.yml")
		yml := "" +
			"receivers:\n  otlp/in:\n    protocols:\n      grpc:\n        endpoint: 0.0.0.0:4317\n" +
			"exporters:\n  otlp/out:\n    endpoint: 127.0.0.1:4317\n    tls:\n      insecure: true\n" +
			"service:\n  pipelines:\n    custom/ingest:\n      receivers: [otlp/in]\n      exporters: [otlp/out]\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		m, err := loadAndValidateCustomOTelYAML(p)
		require.NoError(t, err)
		svc := m["service"].(map[string]any)
		pipes := svc["pipelines"].(map[string]any)
		assert.Contains(t, pipes, "custom/ingest")
	})
	t.Run("valid", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "x.yml")
		require.NoError(t, os.WriteFile(p, []byte("exporters:\n  otlp/foo:\n    endpoint: h:4317\n"), 0o600))
		m, err := loadAndValidateCustomOTelYAML(p)
		require.NoError(t, err)
		assert.Contains(t, m["exporters"].(map[string]any), "otlp/foo")
	})
}

func TestMergeFleetCustomAdditionalConfig(t *testing.T) {
	topPath := paths.Top()
	tempTop := t.TempDir()
	paths.SetTop(tempTop)
	t.Cleanup(func() { paths.SetTop(topPath) })

	log := logp.NewNopLogger()
	merged := confmap.New()
	require.NoError(t, injectDiagnosticsExtension(merged))
	require.NoError(t, maybeInjectLogLevel(merged, logp.InfoLevel))

	t.Run("standalone skips", func(t *testing.T) {
		settings := &configuration.SettingsConfig{
			Collector: &configuration.CollectorConfig{
				CustomConfig: configuration.CustomOTelConfig{Enabled: true, Path: "/no/such"},
			},
		}
		require.NoError(t, mergeFleetCustomAdditionalConfig(log, merged, false, settings))
	})
	t.Run("collision strict", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "add.yml")
		require.NoError(t, os.WriteFile(p, []byte("extensions:\n  elastic_diagnostics: {}\n"), 0o600))
		settings := &configuration.SettingsConfig{
			Collector: &configuration.CollectorConfig{
				CustomConfig: configuration.CustomOTelConfig{Enabled: true, Path: p},
			},
		}
		err := mergeFleetCustomAdditionalConfig(log, merged, true, settings)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "collides")
	})
	t.Run("merges new exporter", func(t *testing.T) {
		m := confmap.New()
		require.NoError(t, injectDiagnosticsExtension(m))
		require.NoError(t, maybeInjectLogLevel(m, logp.InfoLevel))
		p := filepath.Join(t.TempDir(), "add.yml")
		require.NoError(t, os.WriteFile(p, []byte("exporters:\n  otlp/extra:\n    endpoint: localhost:4317\n"), 0o600))
		settings := &configuration.SettingsConfig{
			Collector: &configuration.CollectorConfig{
				CustomConfig: configuration.CustomOTelConfig{Enabled: true, Path: p},
			},
		}
		require.NoError(t, mergeFleetCustomAdditionalConfig(log, m, true, settings))
		assert.True(t, m.IsSet("exporters::otlp/extra"))
	})
	t.Run("merges from internal agent collector config", func(t *testing.T) {
		m := confmap.New()
		require.NoError(t, injectDiagnosticsExtension(m))
		require.NoError(t, maybeInjectLogLevel(m, logp.InfoLevel))
		p := filepath.Join(t.TempDir(), "add.yml")
		require.NoError(t, os.WriteFile(p, []byte("exporters:\n  otlp/internal:\n    endpoint: localhost:4317\n"), 0o600))
		settings := &configuration.SettingsConfig{
			Collector: &configuration.CollectorConfig{
				CustomConfig: configuration.CustomOTelConfig{Enabled: false, Path: ""},
			},
			Internal: &configuration.InternalConfig{
				Agent: &configuration.InternalAgentConfig{
					Collector: &configuration.CollectorConfig{
						CustomConfig: configuration.CustomOTelConfig{Enabled: true, Path: p},
					},
				},
			},
		}
		require.NoError(t, mergeFleetCustomAdditionalConfig(log, m, true, settings))
		assert.True(t, m.IsSet("exporters::otlp/internal"))
	})
	t.Run("merges service pipelines", func(t *testing.T) {
		m := confmap.New()
		require.NoError(t, injectDiagnosticsExtension(m))
		require.NoError(t, maybeInjectLogLevel(m, logp.InfoLevel))
		p := filepath.Join(t.TempDir(), "add.yml")
		yml := "" +
			"receivers:\n  otlp/in:\n    protocols:\n      grpc:\n        endpoint: 0.0.0.0:14317\n" +
			"exporters:\n  otlp/out:\n    endpoint: 127.0.0.1:14317\n    tls:\n      insecure: true\n" +
			"service:\n  pipelines:\n    custom/ingest:\n      receivers: [otlp/in]\n      exporters: [otlp/out]\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		settings := &configuration.SettingsConfig{
			Collector: &configuration.CollectorConfig{
				CustomConfig: configuration.CustomOTelConfig{Enabled: true, Path: p},
			},
		}
		require.NoError(t, mergeFleetCustomAdditionalConfig(log, m, true, settings))
		tm := m.ToStringMap()
		svc := tm["service"].(map[string]any)
		pl := svc["pipelines"].(map[string]any)
		assert.Contains(t, pl, "custom/ingest")
	})
	t.Run("unions service extensions with merged", func(t *testing.T) {
		m := confmap.New()
		require.NoError(t, injectDiagnosticsExtension(m))
		require.NoError(t, maybeInjectLogLevel(m, logp.InfoLevel))
		p := filepath.Join(t.TempDir(), "add.yml")
		yml := "" +
			"extensions:\n  health_check/custom:\n    endpoint: 0.0.0.0:13134\n" +
			"service:\n  extensions: [health_check/custom]\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		settings := &configuration.SettingsConfig{
			Collector: &configuration.CollectorConfig{
				CustomConfig: configuration.CustomOTelConfig{Enabled: true, Path: p},
			},
		}
		require.NoError(t, mergeFleetCustomAdditionalConfig(log, m, true, settings))
		raw := m.Get("service::extensions")
		list, ok := raw.([]any)
		require.True(t, ok)
		var ids []string
		for _, e := range list {
			ids = append(ids, e.(string))
		}
		assert.Contains(t, ids, "elastic_diagnostics")
		assert.Contains(t, ids, "health_check/custom")
	})
	t.Run("telemetry add-only merges new keys", func(t *testing.T) {
		m := confmap.New()
		require.NoError(t, injectDiagnosticsExtension(m))
		require.NoError(t, maybeInjectLogLevel(m, logp.InfoLevel))
		p := filepath.Join(t.TempDir(), "add.yml")
		yml := "service:\n  telemetry:\n    metrics:\n      level: none\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		settings := &configuration.SettingsConfig{
			Collector: &configuration.CollectorConfig{
				CustomConfig: configuration.CustomOTelConfig{Enabled: true, Path: p},
			},
		}
		require.NoError(t, mergeFleetCustomAdditionalConfig(log, m, true, settings))
		assert.Equal(t, "INFO", m.Get("service::telemetry::logs::level"))
		assert.Equal(t, "none", m.Get("service::telemetry::metrics::level"))
	})
	t.Run("telemetry cannot override existing leaf", func(t *testing.T) {
		m := confmap.New()
		require.NoError(t, injectDiagnosticsExtension(m))
		require.NoError(t, maybeInjectLogLevel(m, logp.InfoLevel))
		p := filepath.Join(t.TempDir(), "add.yml")
		yml := "service:\n  telemetry:\n    logs:\n      level: DEBUG\n"
		require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
		settings := &configuration.SettingsConfig{
			Collector: &configuration.CollectorConfig{
				CustomConfig: configuration.CustomOTelConfig{Enabled: true, Path: p},
			},
		}
		err := mergeFleetCustomAdditionalConfig(log, m, true, settings)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot override")
	})
}
