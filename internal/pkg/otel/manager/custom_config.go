// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
)

// customOTelComponentSections are top-level keys that hold named OTel components.
var customOTelComponentSections = map[string]struct{}{
	"receivers":  {},
	"processors": {},
	"exporters":  {},
	"extensions": {},
	"connectors": {},
}

// customOTelAllowedTopLevel is the full set of top-level keys permitted in the
// Fleet custom additional YAML file.
var customOTelAllowedTopLevel = func() map[string]struct{} {
	m := make(map[string]struct{}, len(customOTelComponentSections)+1)
	for k := range customOTelComponentSections {
		m[k] = struct{}{}
	}
	m["service"] = struct{}{}
	return m
}()

var errCustomOTelFileNotExist = errors.New("custom otel config file does not exist")

func yamlStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, false
			}
			out[ks] = val
		}
		return out, true
	default:
		return nil, false
	}
}

func sortedComponentSectionNames() []string {
	out := make([]string, 0, len(customOTelComponentSections))
	for k := range customOTelComponentSections {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loadAndValidateCustomOTelYAML reads path, parses YAML, and enforces the v1
// allowlist and section shapes. Returns errCustomOTelFileNotExist when the
// file is missing (caller may warn and skip).
func loadAndValidateCustomOTelYAML(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errCustomOTelFileNotExist
		}
		return nil, fmt.Errorf("read custom otel config %q: %w", path, err)
	}

	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse custom otel config %q: %w", path, err)
	}
	if root == nil {
		return map[string]any{}, nil
	}

	var disallowed []string
	for k := range root {
		if _, ok := customOTelAllowedTopLevel[k]; !ok {
			disallowed = append(disallowed, k)
		}
	}
	if len(disallowed) > 0 {
		sort.Strings(disallowed)
		return nil, fmt.Errorf("custom otel config %q: disallowed top-level keys: %s", path, strings.Join(disallowed, ", "))
	}

	for _, section := range sortedComponentSectionNames() {
		v, ok := root[section]
		if !ok || v == nil {
			continue
		}
		secMap, err := asNamedComponentMap(v, fmt.Sprintf("custom otel config %q", path), section)
		if err != nil {
			return nil, err
		}
		root[section] = secMap
	}

	if err := validateCustomOTelService(path, root); err != nil {
		return nil, err
	}

	return root, nil
}

var allowedCustomServiceKeys = map[string]struct{}{
	"pipelines":  {},
	"extensions": {},
	"telemetry":  {},
}

func validateCustomOTelService(path string, root map[string]any) error {
	raw, ok := root["service"]
	if !ok || raw == nil {
		return nil
	}
	svc, ok := yamlStringMap(raw)
	if !ok {
		return fmt.Errorf("custom otel config %q: service must be a map", path)
	}
	if len(svc) == 0 {
		return fmt.Errorf("custom otel config %q: service must not be empty (omit service entirely)", path)
	}
	var bad []string
	for k := range svc {
		if _, ok := allowedCustomServiceKeys[k]; !ok {
			bad = append(bad, k)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("custom otel config %q: service may only contain keys pipelines, extensions, and telemetry; also had: %s", path, strings.Join(bad, ", "))
	}

	if !customOTelServiceHasWorkload(svc) {
		return fmt.Errorf("custom otel config %q: service must define at least one non-empty pipelines entry, a non-empty service.extensions list, or a non-empty service.telemetry map", path)
	}

	if err := validateServiceExtensionsList(path, root, svc); err != nil {
		return err
	}

	if err := validateServiceTelemetryShape(path, svc); err != nil {
		return err
	}

	pipesRaw := svc["pipelines"]
	if pipesRaw == nil {
		return nil
	}
	pipelines, ok := yamlStringMap(pipesRaw)
	if !ok {
		return fmt.Errorf("custom otel config %q: service.pipelines must be a map", path)
	}
	if len(pipelines) == 0 {
		return nil
	}

	receiverNames, err := componentNamesInSection(root, "receivers")
	if err != nil {
		return fmt.Errorf("custom otel config %q: %w", path, err)
	}
	exporterNames, err := componentNamesInSection(root, "exporters")
	if err != nil {
		return fmt.Errorf("custom otel config %q: %w", path, err)
	}
	connectorNames, err := componentNamesInSection(root, "connectors")
	if err != nil {
		return fmt.Errorf("custom otel config %q: %w", path, err)
	}
	processorNames, err := componentNamesInSection(root, "processors")
	if err != nil {
		return fmt.Errorf("custom otel config %q: %w", path, err)
	}

	for pname, pval := range pipelines {
		pipe, ok := yamlStringMap(pval)
		if !ok {
			return fmt.Errorf("custom otel config %q: service.pipelines.%q must be a map", path, pname)
		}
		for pk := range pipe {
			if pk != "receivers" && pk != "processors" && pk != "exporters" {
				return fmt.Errorf("custom otel config %q: service.pipelines.%q: unknown key %q (only receivers, processors, exporters allowed)", path, pname, pk)
			}
		}
		recvs, err := stringIDsFromPipelineList(pipe["receivers"], path, pname, "receivers")
		if err != nil {
			return err
		}
		exps, err := stringIDsFromPipelineList(pipe["exporters"], path, pname, "exporters")
		if err != nil {
			return err
		}
		procs, err := stringIDsFromPipelineList(pipe["processors"], path, pname, "processors")
		if err != nil {
			return err
		}
		if len(recvs) == 0 || len(exps) == 0 {
			return fmt.Errorf("custom otel config %q: service.pipelines.%q must set non-empty receivers and exporters", path, pname)
		}
		for _, id := range recvs {
			if !receiverNames[id] {
				return fmt.Errorf("custom otel config %q: service.pipelines.%q references receiver %q which is not defined under receivers in this file", path, pname, id)
			}
		}
		for _, id := range procs {
			if !processorNames[id] {
				return fmt.Errorf("custom otel config %q: service.pipelines.%q references processor %q which is not defined under processors in this file", path, pname, id)
			}
		}
		for _, id := range exps {
			if !exporterNames[id] && !connectorNames[id] {
				return fmt.Errorf("custom otel config %q: service.pipelines.%q references exporter %q which is not defined under exporters or connectors in this file", path, pname, id)
			}
		}
	}

	return nil
}

func customOTelServiceHasWorkload(svc map[string]any) bool {
	if p, ok := yamlStringMap(svc["pipelines"]); ok && len(p) > 0 {
		return true
	}
	if ex, ok := svc["extensions"].([]any); ok && len(ex) > 0 {
		return true
	}
	if tel, ok := yamlStringMap(svc["telemetry"]); ok && len(tel) > 0 {
		return true
	}
	return false
}

func validateServiceExtensionsList(path string, root map[string]any, svc map[string]any) error {
	raw, ok := svc["extensions"]
	if !ok || raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("custom otel config %q: service.extensions must be a list of extension component ids", path)
	}
	extNames, err := componentNamesInSection(root, "extensions")
	if err != nil {
		return fmt.Errorf("custom otel config %q: %w", path, err)
	}
	for i, elem := range list {
		id, ok := elem.(string)
		if !ok {
			return fmt.Errorf("custom otel config %q: service.extensions[%d] must be a string component id", path, i)
		}
		if !extNames[id] {
			return fmt.Errorf("custom otel config %q: service.extensions references %q which is not defined under extensions in this file", path, id)
		}
	}
	return nil
}

func validateServiceTelemetryShape(path string, svc map[string]any) error {
	raw, ok := svc["telemetry"]
	if !ok || raw == nil {
		return nil
	}
	if _, ok := yamlStringMap(raw); !ok {
		return fmt.Errorf("custom otel config %q: service.telemetry must be a map", path)
	}
	return nil
}

func componentNamesInSection(root map[string]any, section string) (map[string]bool, error) {
	raw, ok := root[section]
	if !ok || raw == nil {
		return map[string]bool{}, nil
	}
	m, err := asNamedComponentMap(raw, "custom otel config", section)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out, nil
}

func stringIDsFromPipelineList(raw any, path, pipelineName, field string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("custom otel config %q: service.pipelines.%q: %s must be a list", path, pipelineName, field)
	}
	out := make([]string, 0, len(list))
	for i, elem := range list {
		s, ok := elem.(string)
		if !ok {
			return nil, fmt.Errorf("custom otel config %q: service.pipelines.%q: %s[%d] must be a string component id", path, pipelineName, field, i)
		}
		out = append(out, s)
	}
	return out, nil
}

func asNamedComponentMap(v any, errCtx, section string) (map[string]any, error) {
	switch m := v.(type) {
	case map[string]any:
		return m, nil
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%s: %s section has non-string key %v", errCtx, section, k)
			}
			out[ks] = val
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s: %s must be a map of component names to config, got %T", errCtx, section, v)
	}
}

// checkAdditionsOnlyCollision returns an error if additional defines a
// top-level key outside the allowlist, reuses a component name present
// in merged under receivers, processors, exporters, extensions, or connectors,
// or defines a service pipeline id that already exists in merged config.
func checkAdditionsOnlyCollision(merged, additional map[string]any) error {
	var disallowed []string
	for k := range additional {
		if _, ok := customOTelAllowedTopLevel[k]; !ok {
			disallowed = append(disallowed, k)
		}
	}
	if len(disallowed) > 0 {
		sort.Strings(disallowed)
		return fmt.Errorf("custom otel config: disallowed top-level keys: %s", strings.Join(disallowed, ", "))
	}

	type collision struct {
		section string
		names   []string
	}
	var hits []collision

	for section := range customOTelComponentSections {
		addSec, addOK, err := sectionKeys(additional, section)
		if err != nil {
			return err
		}
		if !addOK || len(addSec) == 0 {
			continue
		}
		mergedSec, _, err := sectionKeysMerged(merged, section)
		if err != nil {
			return err
		}
		var names []string
		for name := range addSec {
			if mergedSec[name] {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			sort.Strings(names)
			hits = append(hits, collision{section: section, names: names})
		}
	}
	if len(hits) > 0 {
		sort.Slice(hits, func(i, j int) bool { return hits[i].section < hits[j].section })
		var b strings.Builder
		b.WriteString("custom otel config collides with existing component names: ")
		for i, h := range hits {
			if i > 0 {
				b.WriteString("; ")
			}
			b.WriteString(h.section)
			b.WriteString(": [")
			b.WriteString(strings.Join(h.names, ", "))
			b.WriteString("]")
		}
		return errors.New(b.String())
	}

	if err := checkServicePipelineNameCollisions(merged, additional); err != nil {
		return err
	}

	return nil
}

func pipelineNamesFromRoot(root map[string]any) (map[string]bool, error) {
	svcRaw, ok := root["service"]
	if !ok || svcRaw == nil {
		return map[string]bool{}, nil
	}
	svc, ok := yamlStringMap(svcRaw)
	if !ok {
		return nil, fmt.Errorf("merged collector configuration: service must be a map")
	}
	pipesRaw, ok := svc["pipelines"]
	if !ok || pipesRaw == nil {
		return map[string]bool{}, nil
	}
	pipelines, ok := yamlStringMap(pipesRaw)
	if !ok {
		return nil, fmt.Errorf("merged collector configuration: service.pipelines must be a map")
	}
	out := make(map[string]bool, len(pipelines))
	for name := range pipelines {
		out[name] = true
	}
	return out, nil
}

func checkServicePipelineNameCollisions(merged, additional map[string]any) error {
	addNames, err := pipelineNamesFromRoot(additional)
	if err != nil {
		return err
	}
	if len(addNames) == 0 {
		return nil
	}
	mergedNames, err := pipelineNamesFromRoot(merged)
	if err != nil {
		return err
	}
	var hits []string
	for name := range addNames {
		if mergedNames[name] {
			hits = append(hits, name)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Strings(hits)
	return fmt.Errorf("custom otel config: service.pipelines reuses existing pipeline names: [%s]", strings.Join(hits, ", "))
}

func sectionKeys(root map[string]any, section string) (map[string]bool, bool, error) {
	raw, ok := root[section]
	if !ok || raw == nil {
		return nil, false, nil
	}
	m, err := asNamedComponentMap(raw, "custom otel config", section)
	if err != nil {
		return nil, false, err
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out, true, nil
}

func sectionKeysMerged(root map[string]any, section string) (map[string]bool, bool, error) {
	raw, ok := root[section]
	if !ok || raw == nil {
		return nil, false, nil
	}
	m, err := asNamedComponentMap(raw, "merged collector configuration", section)
	if err != nil {
		return nil, false, err
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out, true, nil
}

func mergeFleetCustomAdditionalConfig(
	logger *logp.Logger,
	mergedOtelCfg *confmap.Conf,
	fleetManaged bool,
	settings *configuration.SettingsConfig,
) error {
	// Custom collector YAML merge is supported only for Fleet-managed policies.
	if !fleetManaged || settings == nil {
		return nil
	}
	var cc configuration.CustomOTelConfig
	// Prefer user-facing settings and fall back to internal wiring for
	// backwards compatibility with Fleet-shaped policy translation.
	if settings.Collector != nil {
		cc = settings.Collector.CustomConfig
	}
	if !cc.Enabled && settings.Internal != nil && settings.Internal.Agent != nil && settings.Internal.Agent.Collector != nil {
		cc = settings.Internal.Agent.Collector.CustomConfig
	}
	if !cc.Enabled {
		return nil
	}
	if cc.Path == "" {
		return fmt.Errorf("agent.collector.custom_config.enabled is true but agent.collector.custom_config.path is empty")
	}

	additionalRoot, err := loadAndValidateCustomOTelYAML(cc.Path)
	if errors.Is(err, errCustomOTelFileNotExist) {
		// Missing file is intentionally non-fatal: keep the Fleet-generated
		// collector config and continue running.
		logger.Warnf("custom otel config enabled but file not found; skipping merge path=%s", cc.Path)
		return nil
	}
	if err != nil {
		return err
	}
	if len(additionalRoot) == 0 {
		return nil
	}

	mergedMap := mergedOtelCfg.ToStringMap()
	if err := checkAdditionsOnlyCollision(mergedMap, additionalRoot); err != nil {
		return err
	}

	svc, ok := yamlStringMap(additionalRoot["service"])
	if ok && svc != nil {
		if err := applyAdditionalServiceExtensions(mergedOtelCfg, svc); err != nil {
			return fmt.Errorf("merge custom otel config from %q: %w", cc.Path, err)
		}
		if err := applyAdditionalServiceTelemetry(mergedOtelCfg, svc); err != nil {
			return fmt.Errorf("merge custom otel config from %q: %w", cc.Path, err)
		}
		// service.extensions and service.telemetry are consumed by specialized
		// merge logic above and removed to avoid overwrite behavior in Conf.Merge.
		pruneEmptyServiceSubkeys(svc)
		if len(svc) == 0 {
			delete(additionalRoot, "service")
		}
	}

	additionalConf := confmap.NewFromStringMap(additionalRoot)
	if err := mergedOtelCfg.Merge(additionalConf); err != nil {
		return fmt.Errorf("merge custom otel config from %q: %w", cc.Path, err)
	}
	return nil
}

func applyAdditionalServiceExtensions(merged *confmap.Conf, svc map[string]any) error {
	raw, ok := svc["extensions"]
	if !ok || raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("service.extensions must be a list of extension component ids")
	}
	if len(list) == 0 {
		delete(svc, "extensions")
		return nil
	}
	patch := confmap.NewFromStringMap(map[string]any{
		"service": map[string]any{"extensions": list},
	})
	if err := mergeWithExtensions(merged, patch); err != nil {
		return fmt.Errorf("union service.extensions: %w", err)
	}
	delete(svc, "extensions")
	return nil
}

func applyAdditionalServiceTelemetry(merged *confmap.Conf, svc map[string]any) error {
	raw, ok := svc["telemetry"]
	if !ok || raw == nil {
		return nil
	}
	srcTel, ok := yamlStringMap(raw)
	if !ok {
		return fmt.Errorf("service.telemetry must be a map")
	}
	if len(srcTel) == 0 {
		delete(svc, "telemetry")
		return nil
	}

	mm := merged.ToStringMap()
	svcMerged, _ := yamlStringMap(mm["service"])
	var dstTel map[string]any
	if svcMerged != nil {
		if t, ok := yamlStringMap(svcMerged["telemetry"]); ok && t != nil {
			dstTel = deepCopyTelemetryMap(t)
		}
	}
	if dstTel == nil {
		dstTel = map[string]any{}
	}
	if err := mergeTelemetryAddOnly(dstTel, srcTel, "service.telemetry"); err != nil {
		return err
	}
	patch := confmap.NewFromStringMap(map[string]any{
		"service": map[string]any{"telemetry": dstTel},
	})
	if err := merged.Merge(patch); err != nil {
		return fmt.Errorf("merge service.telemetry: %w", err)
	}
	delete(svc, "telemetry")
	return nil
}

func pruneEmptyServiceSubkeys(svc map[string]any) {
	if p, ok := yamlStringMap(svc["pipelines"]); ok && len(p) == 0 {
		delete(svc, "pipelines")
	}
	if ex, ok := svc["extensions"].([]any); ok && len(ex) == 0 {
		delete(svc, "extensions")
	}
	if tel, ok := yamlStringMap(svc["telemetry"]); ok && len(tel) == 0 {
		delete(svc, "telemetry")
	}
}

func deepCopyTelemetryMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if vm, ok := yamlStringMap(v); ok {
			out[k] = deepCopyTelemetryMap(vm)
		} else {
			out[k] = v
		}
	}
	return out
}

// mergeTelemetryAddOnly merges src into dst without overwriting existing keys
// at any depth. Leaf values that already exist must be deeply equal to src or
// an error is returned.
func mergeTelemetryAddOnly(dst, src map[string]any, path string) error {
	for k, v := range src {
		curPath := path + "." + k
		existing, exists := dst[k]
		if !exists {
			dst[k] = v
			continue
		}
		existingMap, eOk := yamlStringMap(existing)
		vMap, vOk := yamlStringMap(v)
		if eOk && vOk {
			if err := mergeTelemetryAddOnly(existingMap, vMap, curPath); err != nil {
				return err
			}
			dst[k] = existingMap
			continue
		}
		if reflect.DeepEqual(existing, v) {
			continue
		}
		return fmt.Errorf("custom otel config: cannot override %s (already set in collector config)", curPath)
	}
	return nil
}
