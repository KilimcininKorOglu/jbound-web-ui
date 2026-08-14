// Package settings holds the panel values an operator can change at runtime.
//
// The environment still carries everything that is read once at startup or
// that decides a privilege: the listen address, the data directory, the PAM
// service, the admin group, the helper path. Those cannot move here, because a
// write to the settings table would then be a way to widen access.
//
// What lives here is the rest: timeouts, intervals, limits and two interface
// defaults. Each one is read through an accessor, so a change takes effect on
// the next use rather than on the next restart.
package settings

import (
	"time"

	"unbound-web/internal/paging"
)

// Kinds of setting. The kind decides how a value is parsed, how it is
// validated and which control the settings page renders for it.
const (
	KindDuration = "duration"
	KindInt      = "int"
	KindBool     = "bool"
	KindEnum     = "enum"

	// KindText is free text the operator types, such as the panel name.
	KindText = "text"

	// KindServer holds the identifier of a managed server, or nothing at all.
	// The registry cannot check that the server exists, because this package
	// does not know about servers, so the page that offers the choices does.
	KindServer = "server"
)

// Groups. They are the cards of the settings page, in this order.
const (
	GroupTiming    = "timing"
	GroupLimits    = "limits"
	GroupSIEM      = "siem"
	GroupFleet     = "fleet"
	GroupInterface = "interface"
)

// Keys. They are constants so a typo cannot create a second spelling that the
// registry then answers with a default.
const (
	SessionIdleTimeout   = "session_idle_timeout"
	SessionLifetime      = "session_lifetime"
	CacheRefreshInterval = "cache_refresh_interval"
	CacheStaleAfter      = "cache_stale_after"
	SSHConnectTimeout    = "ssh_connect_timeout"
	SSHCommandTimeout    = "ssh_command_timeout"
	SSHIdleTimeout       = "ssh_idle_timeout"
	DNSQueryTimeout      = "dns_query_timeout"

	// FleetOperationTimeout bounds one whole fan-out request. Its maximum has
	// to stay well under the server's WriteTimeout in cmd/unbound-web, because
	// a request that outlives that deadline loses its per-server report.
	FleetOperationTimeout = "fleet_operation_timeout"

	LoginRateWindow      = "login_rate_window"
	LoginRateMaxAttempts = "login_rate_max_attempts"
	FleetMaxConcurrent   = "fleet_max_concurrent"
	RecordsPerPage       = "records_per_page"

	SIEMForwardingEnabled = "siem_forwarding_enabled"

	SourceServerID = "source_server_id"

	PanelName = "panel_name"

	DefaultLanguage = "default_language"
	DefaultTheme    = "default_theme"
)

// Definition describes one setting.
type Definition struct {
	Key   string
	Group string
	Kind  string

	// Default is what the panel uses while the table holds no row for this
	// key, written in the same form an operator would type.
	Default string

	// Min and Max bound a duration setting, and MinInt and MaxInt bound an
	// integer one. They are separate fields rather than one pair, because a
	// count of four and a duration of four nanoseconds are not the same value.
	Min time.Duration
	Max time.Duration

	MinInt int
	MaxInt int

	// Options lists the accepted values of an enum.
	Options []string

	// MaxLen bounds a text setting.
	MaxLen int
}

// registry is every setting the panel has, in the order the page shows them.
//
// The label and the help text are not here. They live in the message
// catalogues under setting.<key>.label and setting.<key>.help, so a setting
// reads in the language of the page rather than in the language of the code.
var registry = []Definition{
	{
		Key: SessionIdleTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "30m", Min: time.Minute, Max: 24 * time.Hour,
	},
	{
		Key: SessionLifetime, Group: GroupTiming, Kind: KindDuration,
		Default: "24h", Min: 5 * time.Minute, Max: 30 * 24 * time.Hour,
	},
	{
		Key: CacheRefreshInterval, Group: GroupTiming, Kind: KindDuration,
		Default: "5m", Min: 30 * time.Second, Max: 24 * time.Hour,
	},
	{
		Key: CacheStaleAfter, Group: GroupTiming, Kind: KindDuration,
		Default: "15m", Min: time.Minute, Max: 7 * 24 * time.Hour,
	},
	{
		Key: SSHConnectTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "10s", Min: time.Second, Max: 5 * time.Minute,
	},
	{
		Key: SSHCommandTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "30s", Min: time.Second, Max: 30 * time.Minute,
	},
	{
		Key: SSHIdleTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "5m", Min: time.Minute, Max: 24 * time.Hour,
	},
	{
		Key: DNSQueryTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "10s", Min: time.Second, Max: 2 * time.Minute,
	},
	{
		// One operation reaches every server of a target, several SSH commands
		// each, in batches of fleet_max_concurrent. How long that may take
		// depends on the size of the fleet and the speed of the machines, so
		// it is a setting rather than a number chosen here.
		Key: FleetOperationTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "5m", Min: 30 * time.Second, Max: 10 * time.Minute,
	},

	{
		Key: LoginRateWindow, Group: GroupLimits, Kind: KindDuration,
		Default: "15m", Min: time.Minute, Max: 24 * time.Hour,
	},
	{
		Key: LoginRateMaxAttempts, Group: GroupLimits, Kind: KindInt,
		Default: "10", MinInt: 1, MaxInt: 1000,
	},
	{
		Key: FleetMaxConcurrent, Group: GroupLimits, Kind: KindInt,
		Default: "4", MinInt: 1, MaxInt: 64,
	},
	{
		// The bounds are the ones every listing clamps to anyway, so a value
		// the operator saves outside them would be stored and then ignored.
		Key: RecordsPerPage, Group: GroupLimits, Kind: KindInt,
		Default: "25", MinInt: paging.Min, MaxInt: paging.Max,
	},

	{
		Key: SIEMForwardingEnabled, Group: GroupSIEM, Kind: KindBool,
		Default: "true",
	},

	{
		Key: SourceServerID, Group: GroupFleet, Kind: KindServer,
		Default: "",
	},

	{
		Key: PanelName, Group: GroupInterface, Kind: KindText,
		Default: "JanBound DNS Panel", MaxLen: 60,
	},
	{
		Key: DefaultLanguage, Group: GroupInterface, Kind: KindEnum,
		Default: "en", Options: []string{"en", "tr"},
	},
	{
		Key: DefaultTheme, Group: GroupInterface, Kind: KindEnum,
		Default: "system", Options: []string{"system", "light", "dark"},
	},
}

// Definitions returns every setting in page order.
func Definitions() []Definition {
	out := make([]Definition, len(registry))
	copy(out, registry)
	return out
}

// Groups returns the group names in page order.
func Groups() []string {
	return []string{GroupTiming, GroupLimits, GroupSIEM, GroupFleet, GroupInterface}
}

// Lookup returns the definition of one key.
func Lookup(key string) (Definition, bool) {
	for _, definition := range registry {
		if definition.Key == key {
			return definition, true
		}
	}
	return Definition{}, false
}
