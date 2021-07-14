package aghnet

import (
	"time"

	"github.com/AdguardTeam/golibs/log"
)

// DefaultRefreshIvl is the default period of time between refreshing cached
// addresses.
// const DefaultRefreshIvl = 5 * time.Minute

// HostGenFunc is the signature for functions generating fake hostnames.  The
// implementation must be safe for concurrent use.
type HostGenFunc func() (host string)

// SystemResolvers helps to work with local resolvers' addresses provided by OS.
type SystemResolvers interface {
	// Get returns the slice of local resolvers' addresses.  It should be
	// safe for concurrent use.
	Get() (rs []string)
	// refresh refreshes the local resolvers' addresses cache.  It should be
	// safe for concurrent use.
	refresh() (err error)
}

// refreshWithTicker refreshes the cache of sr after each tick form tickCh.
func refreshWithTicker(sr SystemResolvers, tickCh <-chan time.Time) {
	defer log.OnPanic("systemResolvers")

	// TODO(e.burkov): Implement a functionality to stop ticker.
	for range tickCh {
		err := sr.refresh()
		if err != nil {
			log.Error("systemResolvers: error in refreshing goroutine: %s", err)

			continue
		}

		log.Debug("systemResolvers: local addresses cache is refreshed")
	}
}

// NewSystemResolvers returns a SystemResolvers with the cache refresh rate
// defined by refreshIvl. It disables auto-resfreshing if refreshIvl is 0.  If
// nil is passed for hostGenFunc, the default generator will be used.
func NewSystemResolvers(
	refreshIvl time.Duration,
	hostGenFunc HostGenFunc,
) (sr SystemResolvers, err error) {
	sr = newSystemResolvers(refreshIvl, hostGenFunc)

	// Fill cache.
	err = sr.refresh()
	if err != nil {
		return nil, err
	}

	if refreshIvl > 0 {
		ticker := time.NewTicker(refreshIvl)

		go refreshWithTicker(sr, ticker.C)
	}

	return sr, nil
}
