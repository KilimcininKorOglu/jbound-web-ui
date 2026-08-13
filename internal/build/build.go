// Package build carries what the panel knows about its own binary.
package build

// Version is the release the binary was built from.
//
// It is set at link time:
//
//	go build -ldflags "-X unbound-web/internal/build.Version=1.2.0"
//
// A build without that flag reports dev, which is what a working tree is.
var Version = "dev"
