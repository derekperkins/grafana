package config

import (
	"fmt"
	"strings"

	pCfg "github.com/grafana/grafana/pkg/plugins/config"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/setting"
)

func ProvideConfig(settingProvider setting.Provider, grafanaCfg *setting.Cfg, features featuremgmt.FeatureToggles) (*pCfg.Cfg, error) {
	plugins := settingProvider.Section("plugins")
	allowedUnsigned := grafanaCfg.PluginsAllowUnsigned
	if len(plugins.KeyValue("allow_loading_unsigned_plugins").Value()) > 0 {
		allowedUnsigned = strings.Split(plugins.KeyValue("allow_loading_unsigned_plugins").Value(), ",")
	}

	tracingCfg, err := newTracingCfg(grafanaCfg)
	if err != nil {
		return nil, fmt.Errorf("new opentelemetry cfg: %w", err)
	}

	return pCfg.NewCfg(
		settingProvider.KeyValue("", "app_mode").MustBool(grafanaCfg.Env == setting.Dev),
		grafanaCfg.PluginsPath,
		extractPluginSettings(settingProvider),
		allowedUnsigned,
		grafanaCfg.PluginsCDNURLTemplate,
		grafanaCfg.AppURL,
		grafanaCfg.AppSubURL,
		tracingCfg,
		features,
		grafanaCfg.AngularSupportEnabled,
		grafanaCfg.GrafanaComURL,
		grafanaCfg.DisablePlugins,
		grafanaCfg.HideAngularDeprecation,
		grafanaCfg.ForwardHostEnvVars,
	), nil
}

func extractPluginSettings(settingProvider setting.Provider) setting.PluginSettings {
	ps := setting.PluginSettings{}
	for sectionName, sectionCopy := range settingProvider.Current() {
		if !strings.HasPrefix(sectionName, "plugin.") {
			continue
		}
		// Calling Current() returns a redacted version of section. We need to replace the map values with the unredacted values.
		section := settingProvider.Section(sectionName)
		for k := range sectionCopy {
			sectionCopy[k] = section.KeyValue(k).MustString("")
		}
		pluginID := strings.Replace(sectionName, "plugin.", "", 1)
		ps[pluginID] = sectionCopy
	}

	return ps
}
