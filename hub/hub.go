package hub

import (
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

type Option func(*config.Config)

func WithExternalUI(externalUI string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalUI = externalUI
	}
}

func WithExternalController(externalController string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalController = externalController
	}
}

func WithExternalControllerTLS(externalControllerTLS string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerTLS = externalControllerTLS
	}
}

func WithExternalControllerUnix(externalControllerUnix string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerUnix = externalControllerUnix
	}
}

func WithExternalControllerPipe(externalControllerPipe string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerPipe = externalControllerPipe
	}
}

func WithExternalControllerRoutingMark(externalControllerRoutingMark int) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerRoutingMark = externalControllerRoutingMark
	}
}

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.Secret = secret
	}
}

// ApplyConfig dispatch configure to all parts include ExternalController
func ApplyConfig(cfg *config.Config) {
	applyRoute(cfg)
	executor.ApplyConfig(cfg, true)
}

func applyRoute(cfg *config.Config) {
	if cfg.Controller.ExternalUI != "" {
		route.SetUIPath(cfg.Controller.ExternalUI)
	}
	route.ReCreateServer(&route.Config{
		Addr:           cfg.Controller.ExternalController,
		TLSAddr:        cfg.Controller.ExternalControllerTLS,
		UnixAddr:       cfg.Controller.ExternalControllerUnix,
		PipeAddr:       cfg.Controller.ExternalControllerPipe,
		RoutingMark:    cfg.Controller.ExternalControllerRoutingMark,
		Secret:         cfg.Controller.Secret,
		Certificate:    cfg.TLS.Certificate,
		PrivateKey:     cfg.TLS.PrivateKey,
		ClientAuthType: cfg.TLS.ClientAuthType,
		ClientAuthCert: cfg.TLS.ClientAuthCert,
		EchKey:         cfg.TLS.EchKey,
		DohServer:      cfg.Controller.ExternalDohServer,
		IsDebug:        cfg.General.LogLevel == log.DEBUG,
		Cors: route.Cors{
			AllowOrigins:        cfg.Controller.Cors.AllowOrigins,
			AllowPrivateNetwork: cfg.Controller.Cors.AllowPrivateNetwork,
		},
	})
}

// Parse call at the beginning of mihomo
func Parse(configBytes []byte, options ...Option) (*config.Config, error) {
	var cfg *config.Config
	var err error

	if len(configBytes) != 0 {
		cfg, err = executor.ParseWithBytes(configBytes)
	} else {
		cfg, err = executor.Parse()
	}

	if err != nil {
		return nil, err
	}

	for _, option := range options {
		option(cfg)
	}

	ApplyConfig(cfg)
	return cfg, nil
}

// StartInbound opens the incoming listeners the configuration names.
//
// The app starts them itself, once it has brought its own tunnel up, so
// applying a configuration leaves them closed. A core run from the command
// line has no app behind it: without this its mixed-port would be read and
// then ignored, and a client that was told the port is there would find
// nothing listening on it.
//
// The tunnel is not started here. Its device belongs to the app that opens
// it, and a configuration that asks for the tunnel from the command line is
// a thing this fork does not do.
func StartInbound(cfg *config.Config) {
	if cfg == nil {
		return
	}
	general := cfg.General
	listener.PatchInboundListeners(cfg.Listeners, tunnel.Tunnel, true)

	listener.SetAllowLan(general.AllowLan)
	inbound.SetSkipAuthPrefixes(general.SkipAuthPrefixes)
	inbound.SetAllowedIPs(general.LanAllowedIPs)
	inbound.SetDisAllowedIPs(general.LanDisAllowedIPs)

	listener.SetBindAddress(general.BindAddress)
	listener.ReCreateHTTP(general.Port, tunnel.Tunnel)
	listener.ReCreateSocks(general.SocksPort, tunnel.Tunnel)
	listener.ReCreateRedir(general.RedirPort, tunnel.Tunnel)
	listener.ReCreateTProxy(general.TProxyPort, tunnel.Tunnel)
	listener.ReCreateMixed(general.MixedPort, tunnel.Tunnel)
	listener.ReCreateShadowSocks(general.ShadowSocksConfig, tunnel.Tunnel)
	listener.ReCreateVmess(general.VmessConfig, tunnel.Tunnel)
	listener.ReCreateTuic(general.TuicServer, tunnel.Tunnel)
}
