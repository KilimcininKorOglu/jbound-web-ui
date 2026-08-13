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

import "time"

// Kinds of setting. The kind decides how a value is parsed, how it is
// validated and which control the settings page renders for it.
const (
	KindDuration = "duration"
	KindInt      = "int"
	KindBool     = "bool"
	KindEnum     = "enum"
)

// Groups. They are the cards of the settings page, in this order.
const (
	GroupTiming    = "timing"
	GroupLimits    = "limits"
	GroupSIEM      = "siem"
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

	LoginRateWindow      = "login_rate_window"
	LoginRateMaxAttempts = "login_rate_max_attempts"
	FleetMaxConcurrent   = "fleet_max_concurrent"
	RecordsPerPage       = "records_per_page"

	SIEMForwardingEnabled = "siem_forwarding_enabled"

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

	// Label and Help are the English texts of the settings page. The
	// translated versions are looked up by key, and these are the fallback.
	Label string
	Help  string
}

// registry is every setting the panel has, in the order the page shows them.
var registry = []Definition{
	{
		Key: SessionIdleTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "30m", Min: time.Minute, Max: 24 * time.Hour,
		Label: "Session idle timeout",
		Help:  "How long a signed in browser may sit unused before it is signed out.",
	},
	{
		Key: SessionLifetime, Group: GroupTiming, Kind: KindDuration,
		Default: "24h", Min: 5 * time.Minute, Max: 30 * 24 * time.Hour,
		Label: "Session lifetime",
		Help:  "The longest a session may live, however active it is.",
	},
	{
		Key: CacheRefreshInterval, Group: GroupTiming, Kind: KindDuration,
		Default: "5m", Min: 30 * time.Second, Max: 24 * time.Hour,
		Label: "Cache refresh interval",
		Help:  "How often the panel reads the file of every enabled server.",
	},
	{
		Key: CacheStaleAfter, Group: GroupTiming, Kind: KindDuration,
		Default: "15m", Min: time.Minute, Max: 7 * 24 * time.Hour,
		Label: "Cache stale after",
		Help:  "When a cached record set starts being shown with a stale marker.",
	},
	{
		Key: SSHConnectTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "10s", Min: time.Second, Max: 5 * time.Minute,
		Label: "SSH connect timeout",
		Help:  "How long the panel waits for a managed server to answer.",
	},
	{
		Key: SSHCommandTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "30s", Min: time.Second, Max: 30 * time.Minute,
		Label: "SSH command timeout",
		Help:  "How long one remote command may run before it is given up on.",
	},
	{
		Key: SSHIdleTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "5m", Min: time.Minute, Max: 24 * time.Hour,
		Label: "SSH idle timeout",
		Help:  "How long an unused connection is kept open in the pool.",
	},
	{
		Key: DNSQueryTimeout, Group: GroupTiming, Kind: KindDuration,
		Default: "10s", Min: time.Second, Max: 2 * time.Minute,
		Label: "DNS query timeout",
		Help:  "How long a name query against one resolver may take.",
	},

	{
		Key: LoginRateWindow, Group: GroupLimits, Kind: KindDuration,
		Default: "15m", Min: time.Minute, Max: 24 * time.Hour,
		Label: "Login rate window",
		Help:  "The period the failed login attempts of one address are counted over.",
	},
	{
		Key: LoginRateMaxAttempts, Group: GroupLimits, Kind: KindInt,
		Default: "10", MinInt: 1, MaxInt: 1000,
		Label: "Login attempts per window",
		Help:  "How many attempts one address may make before it is refused.",
	},
	{
		Key: FleetMaxConcurrent, Group: GroupLimits, Kind: KindInt,
		Default: "4", MinInt: 1, MaxInt: 64,
		Label: "Concurrent server operations",
		Help:  "How many servers the panel works on at once during a fleet operation.",
	},
	{
		Key: RecordsPerPage, Group: GroupLimits, Kind: KindInt,
		Default: "25", MinInt: 10, MaxInt: 100,
		Label: "Records per page",
		Help:  "The page size the record table starts with.",
	},

	{
		Key: SIEMForwardingEnabled, Group: GroupSIEM, Kind: KindBool,
		Default: "true",
		Label:   "Forward audit events to syslog",
		Help: "When this is off the panel writes its audit trail to the database " +
			"only. The forwarding rules stay where they are.",
	},

	{
		Key: DefaultLanguage, Group: GroupInterface, Kind: KindEnum,
		Default: "en", Options: []string{"en", "tr"},
		Label: "Default language",
		Help:  "The language a browser gets before anybody picks one.",
	},
	{
		Key: DefaultTheme, Group: GroupInterface, Kind: KindEnum,
		Default: "system", Options: []string{"system", "light", "dark"},
		Label: "Default theme",
		Help:  "The theme a browser gets before anybody picks one.",
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
	return []string{GroupTiming, GroupLimits, GroupSIEM, GroupInterface}
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
