package sp1

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	// Get log level from environment variable
	logLevel := strings.ToLower(os.Getenv("SP1_GO_LOG"))

	// Configure the global log level based on the environment variable
	switch logLevel {
	case "disabled", "false", "none", "off":
		zerolog.SetGlobalLevel(zerolog.Disabled)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "warn", "warning":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	default: // Including "info" and empty string
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Configure zerolog to use a console writer
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}
