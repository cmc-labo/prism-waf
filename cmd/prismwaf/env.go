package main

import (
	"flag"
	"fmt"
	"strings"
)

// envPrefix starts the environment variables that set flags, e.g.
// PRISMWAF_RATE_LIMIT for -rate-limit. Containers and orchestrators such
// as Kubernetes are usually configured with environment variables.
const envPrefix = "PRISMWAF_"

// envName returns the environment variable of a flag.
func envName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// applyEnv sets the flags of fs that were not given on the command line
// from environ, a list of "NAME=value" entries as from os.Environ. A
// repeatable flag takes one value per line. Empty variables are ignored.
// Unknown PRISMWAF_ variables are an error, so that a misspelled option is
// not silently ignored.
func applyEnv(fs *flag.FlagSet, environ []string) error {
	onCommandLine := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { onCommandLine[f.Name] = true })
	flags := map[string]*flag.Flag{}
	fs.VisitAll(func(f *flag.Flag) { flags[envName(f.Name)] = f })
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, envPrefix) {
			continue
		}
		f, ok := flags[name]
		if !ok {
			return fmt.Errorf("unknown environment variable %s: no such option", name)
		}
		if onCommandLine[f.Name] || strings.TrimSpace(value) == "" {
			continue
		}
		values := []string{value}
		if _, ok := f.Value.(*stringList); ok {
			values = nil
			for _, line := range strings.Split(value, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					values = append(values, line)
				}
			}
		}
		for _, v := range values {
			if err := fs.Set(f.Name, v); err != nil {
				return fmt.Errorf("invalid %s: %w", name, err)
			}
		}
	}
	return nil
}
