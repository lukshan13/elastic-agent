// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"fmt"
	"net/url"
	"strconv"
)

type CollectorConfig struct {
	HealthCheckConfig CollectorHealthCheckConfig `yaml:"healthcheck" config:"healthcheck" json:"healthcheck"`
	TelemetryConfig   CollectorTelemetryConfig   `yaml:"telemetry" config:"telemetry" json:"telemetry"`
	CustomConfig      CustomOTelConfig           `yaml:"custom_config" config:"custom_config" json:"custom_config"`
}

// CustomOTelConfig selects an optional YAML file merged into the Fleet-built
// OTel collector configuration (Fleet-managed mode only).
type CustomOTelConfig struct {
	Enabled bool   `yaml:"enabled" config:"enabled" json:"enabled"`
	Path    string `yaml:"path" config:"path" json:"path"`
}

type CollectorHealthCheckConfig struct {
	Endpoint string `yaml:"endpoint" config:"endpoint" json:"endpoint"`
}

func (c *CollectorHealthCheckConfig) Validate() error {
	return validateEndpoint(c.Endpoint)
}

func (c *CollectorHealthCheckConfig) Port() (int, error) {
	return getPort(c.Endpoint)
}

type CollectorTelemetryConfig struct {
	Endpoint string `yaml:"endpoint" config:"endpoint" json:"endpoint"`
}

func (c *CollectorTelemetryConfig) Validate() error {
	return validateEndpoint(c.Endpoint)
}

func (c *CollectorTelemetryConfig) Port() (int, error) {
	return getPort(c.Endpoint)
}

func DefaultCollectorConfig() *CollectorConfig {
	return &CollectorConfig{
		HealthCheckConfig: CollectorHealthCheckConfig{},
		TelemetryConfig:   CollectorTelemetryConfig{},
		CustomConfig:      CustomOTelConfig{},
	}
}

// Validate checks collector settings including custom OTel file options.
func (c *CollectorConfig) Validate() error {
	if err := c.HealthCheckConfig.Validate(); err != nil {
		return err
	}
	if err := c.TelemetryConfig.Validate(); err != nil {
		return err
	}
	if c.CustomConfig.Enabled && c.CustomConfig.Path == "" {
		return fmt.Errorf("agent.collector.custom_config.enabled is true but agent.collector.custom_config.path is empty")
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" { // the otel metrics prometheus exporter only supports http right now
		return fmt.Errorf("invalid endpoint '%s': must use http", endpoint)
	}

	if parsed.Port() == "" {
		return fmt.Errorf("invalid endpoint '%s': port must be specified", endpoint)
	}

	return nil
}

func getPort(endpoint string) (int, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(parsed.Port())
}
