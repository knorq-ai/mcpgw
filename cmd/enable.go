package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	enableConfigPath string
	enableAllProjects bool
)

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Wrap all MCP servers in Claude Code with mcpgw",
	Long: `Patches Claude Code's MCP server configuration so every server
is wrapped through mcpgw. Original configs are backed up to
~/.mcpgw/backup/ and can be restored with 'mcpgw disable'.

Supports both global (~/.claude.json) and scope-level (~/.claude/.mcp.json)
configurations.`,
	RunE: runEnable,
}

var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Remove mcpgw wrapping from Claude Code MCP servers",
	Long:  `Restores MCP server configurations from backup created by 'mcpgw enable'.`,
	RunE:  runDisable,
}

func init() {
	enableCmd.Flags().StringVar(&enableConfigPath, "config-path", "", "Path to Claude Code config (default: auto-detect)")
	enableCmd.Flags().BoolVar(&enableAllProjects, "all", false, "Also wrap project-level .mcp.json configs")
	rootCmd.AddCommand(enableCmd)
	rootCmd.AddCommand(disableCmd)
}

// mcpgwBinary returns the absolute path to the running mcpgw binary.
func mcpgwBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// mcpgwDir returns ~/.mcpgw, creating it if needed.
func mcpgwDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".mcpgw")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// defaultPolicyPath returns ~/.mcpgw/policy.yaml, creating a default if it doesn't exist.
func defaultPolicyPath() (string, error) {
	dir, err := mcpgwDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "policy.yaml")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		defaultPolicy := `version: v1
mode: audit
rules:
  # Block dangerous shell commands
  - name: block-dangerous-exec
    match:
      methods: ["tools/call"]
      tools: ["exec_*", "run_*", "execute_*"]
      arguments:
        command: ["*rm -rf*", "*sudo*", "*chmod 777*", "*mkfs*", "*/etc/shadow*"]
    action: deny
    mode: enforce

  # Block access to sensitive files
  - name: block-sensitive-files
    match:
      methods: ["tools/call"]
      tools: ["read_file", "read_*"]
      arguments:
        path: ["*.env", "*.pem", "*.key", "*credentials*", "*/etc/passwd*", "*/etc/shadow*"]
    action: deny
    mode: enforce

  # Allow everything else (audit mode — log but don't block)
  - name: default-allow
    match:
      methods: ["*"]
    action: allow
`
		if err := os.WriteFile(p, []byte(defaultPolicy), 0o644); err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "Created default policy: %s\n", p)
	}
	return p, nil
}

// claudeConfigPaths returns candidate paths for Claude Code config.
func claudeConfigPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, ".claude.json"),
	}
}

// claudeScopeConfigPath returns the scope-level MCP config.
func claudeScopeConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", ".mcp.json")
}

// readJSON reads and unmarshals a JSON file into a generic map.
func readJSON(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// writeJSON marshals and writes a map as indented JSON.
func writeJSON(path string, m map[string]any) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// backupPath returns the backup file path for a config.
func backupPath(configPath, label string) (string, error) {
	dir, err := mcpgwDir()
	if err != nil {
		return "", err
	}
	backupDir := filepath.Join(dir, "backup")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(backupDir, label+".json"), nil
}

const mcpgwMarker = "__mcpgw_original"

// wrapServers patches mcpServers in a config map. Returns the number of servers wrapped.
func wrapServers(servers map[string]any, binary, policyPath string) int {
	wrapped := 0
	for name, v := range servers {
		srv, ok := v.(map[string]any)
		if !ok {
			continue
		}
		// Skip if already wrapped
		if _, has := srv[mcpgwMarker]; has {
			continue
		}

		origCommand, _ := srv["command"].(string)
		origArgs, _ := toStringSlice(srv["args"])
		if origCommand == "" {
			continue
		}

		// Save original
		srv[mcpgwMarker] = map[string]any{
			"command": origCommand,
			"args":    origArgs,
		}

		// Build mcpgw wrap args
		wrapArgs := []string{"wrap", "--policy", policyPath, "--"}
		wrapArgs = append(wrapArgs, origCommand)
		wrapArgs = append(wrapArgs, origArgs...)

		srv["command"] = binary
		srv["args"] = wrapArgs

		servers[name] = srv
		wrapped++
	}
	return wrapped
}

// unwrapServers restores original commands. Returns the number of servers unwrapped.
func unwrapServers(servers map[string]any) int {
	unwrapped := 0
	for name, v := range servers {
		srv, ok := v.(map[string]any)
		if !ok {
			continue
		}
		orig, has := srv[mcpgwMarker]
		if !has {
			continue
		}
		origMap, ok := orig.(map[string]any)
		if !ok {
			continue
		}
		srv["command"] = origMap["command"]
		srv["args"] = origMap["args"]
		delete(srv, mcpgwMarker)
		servers[name] = srv
		unwrapped++
	}
	return unwrapped
}

func toStringSlice(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("not an array")
	}
	out := make([]string, len(arr))
	for i, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("element %d is not a string", i)
		}
		out[i] = s
	}
	return out, nil
}

func patchConfig(configPath, label, binary, policyPath string) (int, error) {
	m, err := readJSON(configPath)
	if err != nil {
		return 0, err
	}

	servers, ok := m["mcpServers"].(map[string]any)
	if !ok || len(servers) == 0 {
		return 0, nil
	}

	// Backup before modifying
	bp, err := backupPath(configPath, label)
	if err != nil {
		return 0, err
	}
	data, _ := os.ReadFile(configPath)
	if err := os.WriteFile(bp, data, 0o644); err != nil {
		return 0, fmt.Errorf("backup failed: %w", err)
	}

	n := wrapServers(servers, binary, policyPath)
	if n == 0 {
		return 0, nil
	}

	if err := writeJSON(configPath, m); err != nil {
		return 0, err
	}
	return n, nil
}

func unpatchConfig(configPath string) (int, error) {
	m, err := readJSON(configPath)
	if err != nil {
		return 0, err
	}

	servers, ok := m["mcpServers"].(map[string]any)
	if !ok || len(servers) == 0 {
		return 0, nil
	}

	n := unwrapServers(servers)
	if n == 0 {
		return 0, nil
	}

	if err := writeJSON(configPath, m); err != nil {
		return 0, err
	}
	return n, nil
}

func runEnable(cmd *cobra.Command, args []string) error {
	binary, err := mcpgwBinary()
	if err != nil {
		return fmt.Errorf("cannot resolve mcpgw binary path: %w", err)
	}

	policyPath, err := defaultPolicyPath()
	if err != nil {
		return fmt.Errorf("cannot create default policy: %w", err)
	}

	total := 0

	// Patch global config (~/.claude.json)
	for _, cp := range claudeConfigPaths() {
		if _, err := os.Stat(cp); os.IsNotExist(err) {
			continue
		}
		n, err := patchConfig(cp, "claude-global", binary, policyPath)
		if err != nil {
			return fmt.Errorf("%s: %w", cp, err)
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "Wrapped %d server(s) in %s\n", n, cp)
			total += n
		}
	}

	// Patch scope-level config (~/.claude/.mcp.json)
	scopePath := claudeScopeConfigPath()
	if _, err := os.Stat(scopePath); err == nil {
		n, err := patchConfig(scopePath, "claude-scope", binary, policyPath)
		if err != nil {
			return fmt.Errorf("%s: %w", scopePath, err)
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "Wrapped %d server(s) in %s\n", n, scopePath)
			total += n
		}
	}

	if total == 0 {
		fmt.Fprintln(os.Stderr, "No MCP servers found to wrap (already enabled or none configured).")
		return nil
	}

	fmt.Fprintf(os.Stderr, "\nDone! %d MCP server(s) now protected by mcpgw.\n", total)
	fmt.Fprintf(os.Stderr, "Policy: %s\n", policyPath)
	fmt.Fprintf(os.Stderr, "Audit log: ~/.mcpgw/audit.jsonl\n")
	fmt.Fprintf(os.Stderr, "\nRestart Claude Code to activate. Run 'mcpgw disable' to revert.\n")
	return nil
}

func runDisable(cmd *cobra.Command, args []string) error {
	total := 0

	for _, cp := range claudeConfigPaths() {
		if _, err := os.Stat(cp); os.IsNotExist(err) {
			continue
		}
		n, err := unpatchConfig(cp)
		if err != nil {
			return fmt.Errorf("%s: %w", cp, err)
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "Unwrapped %d server(s) in %s\n", n, cp)
			total += n
		}
	}

	scopePath := claudeScopeConfigPath()
	if _, err := os.Stat(scopePath); err == nil {
		n, err := unpatchConfig(scopePath)
		if err != nil {
			return fmt.Errorf("%s: %w", scopePath, err)
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "Unwrapped %d server(s) in %s\n", n, scopePath)
			total += n
		}
	}

	if total == 0 {
		fmt.Fprintln(os.Stderr, "No mcpgw-wrapped servers found (already disabled or none configured).")
		return nil
	}

	fmt.Fprintf(os.Stderr, "\nDone! %d MCP server(s) restored to original config.\n", total)
	fmt.Fprintf(os.Stderr, "Restart Claude Code to activate.\n")
	return nil
}
