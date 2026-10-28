// `codemeld config check` validates settings layers without starting a session: it reads,
// applies the layer rules a launch would apply, and reports each layer's state. It writes
// nothing and changes no approval state.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"codemeld.dev/codemeld/internal/bootstrap"
	"codemeld.dev/codemeld/internal/config"
	"codemeld.dev/codemeld/internal/fsutil"
	"codemeld.dev/codemeld/internal/paths"
	"codemeld.dev/codemeld/internal/trust"
	ucli "github.com/urfave/cli/v3"
)

const (
	globalLayerRules  = "global layer rules"
	projectLayerRules = "project layer rules"
	localLayerRules   = "local layer rules"
)

const (
	statusOK         = "ok"
	statusAbsent     = "not present"
	statusUnapproved = "present, not approved"
	statusFailed     = "failed to load"
)

// checkConsequence replaces the launch-abort consequence bootstrap passes: this command
// reports on a file rather than starting anything.
const checkConsequence config.LoadConsequence = "codemeld would not start with this file in place"

// errUnsafeSettingsRead names no distinguishing detail on purpose: the refused path is
// attacker-influenced, so the reason must not report which check rejected it.
var errUnsafeSettingsRead = errors.New("settings file could not be read safely")

func newConfigCommand(stdout io.Writer) *ucli.Command {
	return &ucli.Command{
		Name:      "config",
		Usage:     "inspect settings files: check (read-only validation)",
		UsageText: "codemeld config check [path]",
		Description: "Inspect codemeld settings files without starting a session.\n\n" +
			"A launch composes up to three settings layers, nearest last: the global file\n" +
			"~/.codemeld/global/settings.yaml, then the project's shared\n" +
			".codemeld/settings.yaml, then the project's .codemeld/settings.local.yaml,\n" +
			"which holds this machine's own settings and wins over the other two.\n\n" +
			"Running 'codemeld config' without a subcommand is an error.",
		Commands: []*ucli.Command{
			{
				Name:      "check",
				Usage:     "validate settings files without starting a session",
				UsageText: "codemeld config check [path]",
				ArgsUsage: "[path]",
				Description: "Validate settings files against the same rules a launch applies, and report\n" +
					"each layer on its own line as 'path (rules): state'.\n\n" +
					"A launch composes three layers, nearest last: the global file\n" +
					"~/.codemeld/global/settings.yaml, then the project's .codemeld/settings.yaml,\n" +
					"then the project's .codemeld/settings.local.yaml.\n\n" +
					"With no argument it reports three lines, in launch order: the global file,\n" +
					"the project's shared .codemeld/settings.yaml, and the project's\n" +
					".codemeld/settings.local.yaml, both in the project root located the way\n" +
					"discovery.boundary says.\n" +
					"With a path argument it checks exactly that file and performs no project\n" +
					"discovery. The global settings path is checked under 'global layer rules';\n" +
					"a file named settings.local.yaml directly inside a .codemeld directory under\n" +
					"'local layer rules'; any other path under 'project layer rules'. The line\n" +
					"names the rules applied.\n\n" +
					"A layer is reported as 'ok', 'not present', 'present, not approved', or\n" +
					"'failed to load' followed by the same what/consequence/fix message a launch\n" +
					"prints. An absent file is not a failure: no shared or local project settings\n" +
					"file is normal, and an absent global file is reported rather than generated.\n" +
					"A shared or local project layer in a directory you have not approved yet is\n" +
					"named as such and left unparsed; pass its path to check the file itself,\n" +
					"which does not approve the project.\n\n" +
					"It exits non-zero only when a checked layer fails to load. Nothing is\n" +
					"written, no settings are applied or cached, and checking a directory never\n" +
					"approves it.",
				Action: func(_ context.Context, c *ucli.Command) error {
					return runConfigCheck(c.Args().Slice(), stdout)
				},
			},
		},
		Action: func(_ context.Context, c *ucli.Command) error {
			if c.Args().Present() {
				return ucli.Exit(
					fmt.Sprintf("codemeld: unknown config subcommand %q; use 'codemeld config check'", c.Args().First()),
					2,
				)
			}
			return ucli.Exit("codemeld: config requires a subcommand; use 'codemeld config check'", 2)
		},
	}
}

type layerReport struct {
	path   string
	rules  string
	status string
	detail string
}

func runConfigCheck(args []string, stdout io.Writer) error {
	if len(args) > 1 {
		return ucli.Exit(
			fmt.Sprintf("codemeld: config check accepts at most one settings file path; got %d", len(args)),
			2,
		)
	}
	home, err := resolveHome()
	if err != nil {
		return ucli.Exit("codemeld: cannot resolve home directory: "+paths.FormatHomeError(err), 1)
	}

	var reports []layerReport
	if len(args) == 1 {
		reports = []layerReport{checkNamedFile(args[0], bootstrap.SettingsPath(home))}
	} else if reports, err = checkLaunchLayers(home); err != nil {
		return err
	}

	lines := make([]string, 0, 2*len(reports))
	failed := false
	for _, r := range reports {
		lines = append(lines, fmt.Sprintf("%s (%s): %s", r.path, r.rules, r.status))
		if r.detail != "" {
			lines = append(lines, r.detail)
		}
		if r.status == statusFailed {
			failed = true
		}
	}
	if _, err := io.WriteString(stdout, strings.Join(lines, "\n")+"\n"); err != nil {
		return ucli.Exit("codemeld: cannot write the report: "+err.Error(), 1)
	}
	if failed {
		// The failure message is already on stdout as part of the report.
		return ucli.Exit("", 1)
	}
	return nil
}

func checkNamedFile(path, globalPath string) layerReport {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	rules := projectLayerRules
	switch {
	case abs == globalPath:
		rules = globalLayerRules
	case filepath.Base(abs) == "settings.local.yaml" && filepath.Base(filepath.Dir(abs)) == ".codemeld":
		rules = localLayerRules
	}
	report, _ := validateLayer(abs, rules)
	return report
}

func checkLaunchLayers(home string) ([]layerReport, error) {
	globalReport, global := validateLayer(bootstrap.SettingsPath(home), globalLayerRules)
	reports := []layerReport{globalReport}

	cwd, err := osGetwd()
	if err != nil {
		return nil, ucli.Exit(fmt.Sprintf("codemeld: cannot determine working directory: %s", err), 1)
	}
	root, layers, _, err := config.LocateProjectRoot(cwd, discoveryBoundary(global))
	if err != nil {
		return nil, ucli.Exit("codemeld: cannot locate a project settings file: "+err.Error(), 1)
	}

	approved := trust.Lookup(home, root).Trusted
	shared := layerReport{path: filepath.Join(root, ".codemeld", "settings.yaml"), rules: projectLayerRules, status: statusAbsent}
	switch {
	case len(layers) == 0:
	case approved:
		shared, _ = validateLayer(layers[0], projectLayerRules)
	default:
		shared = unapprovedLayer(layers[0], projectLayerRules, root)
	}

	localPath := config.LocalSettingsPath(root)
	var local layerReport
	if approved {
		local, _ = validateLayer(localPath, localLayerRules)
	} else {
		local = unapprovedLocalLayer(localPath, root)
	}
	return append(reports, shared, local), nil
}

func unapprovedLayer(path, rules, root string) layerReport {
	return layerReport{
		path:   path,
		rules:  rules,
		status: statusUnapproved,
		detail: fmt.Sprintf("  a launch ignores this layer until you start codemeld in %s and approve the project;\n"+
			"  to validate the file now, run 'codemeld config check %s'", root, path),
	}
}

func unapprovedLocalLayer(path, root string) layerReport {
	_, err := osLstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return layerReport{path: path, rules: localLayerRules, status: statusAbsent}
	case err != nil:
		return layerReport{
			path:   path,
			rules:  localLayerRules,
			status: statusFailed,
			detail: config.FormatLoadError(path, config.UnreadableFile, errUnsafeSettingsRead, checkConsequence),
		}
	}
	return unapprovedLayer(path, localLayerRules, root)
}

// The decoded map is returned only so the global layer can supply discovery.boundary;
// nothing else acts on the settings this command reads.
func validateLayer(path, rules string) (layerReport, map[string]any) {
	report := layerReport{path: path, rules: rules}
	data, found, ok := fsutil.ReadSettingsBytes(path)
	switch {
	case !ok:
		report.status = statusFailed
		report.detail = config.FormatLoadError(path, config.UnreadableFile, errUnsafeSettingsRead, checkConsequence)
		return report, nil
	case !found:
		report.status = statusAbsent
		return report, nil
	}

	raw, cat, err := validateLayerBytes(data, path, rules)
	if cat != config.LoadOK {
		report.status = statusFailed
		report.detail = config.FormatLoadError(path, cat, err, checkConsequence)
		return report, nil
	}
	report.status = statusOK
	return report, raw
}

func validateLayerBytes(data []byte, path, rules string) (map[string]any, config.LoadFailure, error) {
	switch rules {
	case globalLayerRules:
		return config.ValidateGlobalSettingsBytes(data, path)
	case localLayerRules:
		return config.ValidateLocalSettingsBytes(data, path)
	}
	return config.ValidateProjectSettingsBytes(data, path)
}

// discoveryBoundary repeats the launch's boundary resolution so the project layer reported is
// the one a launch would look for.
func discoveryBoundary(global map[string]any) string {
	const fallback = "launch-dir-only"
	discovery, ok := global["discovery"].(map[string]any)
	if !ok {
		return fallback
	}
	boundary, ok := discovery["boundary"].(string)
	if !ok || boundary == "" {
		return fallback
	}
	return boundary
}
