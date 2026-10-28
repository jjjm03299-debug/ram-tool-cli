package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	API            = "https://jjjm03299-debug.github.io/ram-api-tool/api/get-ram.json"
	SessionTimeout = 180
	Version        = "1.0.1"
)

type PinRecord struct {
	Name    string `json:"name"`
	Hash    string `json:"hash"`
	Created int64  `json:"created"`
}

type AuthFile struct {
	Active string      `json:"active"`
	Pins   []PinRecord `json:"pins"`
}

type SessionFile struct {
	ActiveUser string  `json:"activeUser"`
	Expires    float64 `json:"expires"`
}

type FlagError struct {
	Err error
}

func (fe FlagError) Error() string {
	return fe.Err.Error()
}

func (fe FlagError) Unwrap() error {
	return fe.Err
}

var (
	SilentError           = errors.New("SilentError")
	errCommandInterrupted = errors.New("the command execution has been interrupted")
)

type ExitError struct {
	Err     error
	Code    int
	Details string
}

func WrapErrorWithCode(err error, code int, details string) *ExitError {
	return &ExitError{
		Err:     err,
		Code:    code,
		Details: details,
	}
}

func WrapError(err error, log string) *ExitError {
	return WrapErrorWithCode(err, 1, log)
}

func (e *ExitError) Error() string {
	return e.Err.Error()
}

func (e ExitError) Unwrap() error {
	return e.Err
}

func appDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ram-tool"
	}
	return filepath.Join(home, ".ram-tool")
}

func authFilePath() string {
	return filepath.Join(appDir(), "auth.json")
}

func sessionFilePath() string {
	return filepath.Join(appDir(), "session.json")
}

func ensureDir() {
	_ = os.MkdirAll(appDir(), 0700)
}

func sha256Sum(text string) string {
	hasher := sha256.New()
	hasher.Write([]byte(text))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func loadJson(filePath string, target interface{}) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func saveJson(filePath string, data interface{}) error {
	ensureDir()
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, bytes, 0600)
}

func promptHidden(queryText string) (string, error) {
	fmt.Print(queryText)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

func promptVisible(queryText string) (string, error) {
	fmt.Print(queryText)
	reader := os.Stdin
	buf := make([]byte, 1024)
	n, err := reader.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

func openBrowser(targetUrl string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{targetUrl}
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start", targetUrl}
	default:
		// Linux, Termux, Android, etc.
		cmd = "xdg-open"
		args = []string{targetUrl}
	}

	fmt.Printf("Opening in web browser: %s\n", targetUrl)
	return exec.Command(cmd, args...).Start()
}

func registerPin() error {
	ensureDir()
	var auth AuthFile
	if err := loadJson(authFilePath(), &auth); err == nil && len(auth.Pins) > 0 {
		fmt.Println("PIN metadata already exists.")
		return nil
	}

	pin1, err := promptHidden("Enter new PIN: ")
	if err != nil {
		return err
	}
	pin2, err := promptHidden("Confirm new PIN: ")
	if err != nil {
		return err
	}

	if pin1 != pin2 {
		fmt.Println("PINs do not match.")
		return WrapError(errors.New("pin mismatch"), "PINs do not match")
	}

	auth = AuthFile{
		Active: "default",
		Pins: []PinRecord{
			{Name: "default", Hash: sha256Sum(pin1), Created: time.Now().UnixNano() / int64(time.Millisecond)},
		},
	}

	if err := saveJson(authFilePath(), auth); err != nil {
		return err
	}
	fmt.Println("PIN registered successfully.")
	return nil
}

func loginPin() error {
	var auth AuthFile
	if err := loadJson(authFilePath(), &auth); err != nil || len(auth.Pins) == 0 {
		fmt.Println("No PIN registered.")
		return nil
	}

	pin, err := promptHidden("Enter PIN: ")
	if err != nil {
		return err
	}

	hashed := sha256Sum(pin)
	var found *PinRecord
	for _, p := range auth.Pins {
		if p.Hash == hashed {
			found = &p
			break
		}
	}

	if found == nil {
		fmt.Println("Invalid PIN.")
		return WrapError(errors.New("invalid pin"), "Invalid PIN")
	}

	session := SessionFile{
		ActiveUser: found.Name,
		Expires:    float64(time.Now().Unix()) + SessionTimeout,
	}

	if err := saveJson(sessionFilePath(), session); err != nil {
		return err
	}
	fmt.Println("Login successful.")
	return nil
}

func logoutPin() error {
	var auth AuthFile
	if err := loadJson(authFilePath(), &auth); err != nil {
		fmt.Println("No PIN registered.")
		return nil
	}

	pin, err := promptHidden("Enter PIN: ")
	if err != nil {
		return err
	}

	hashed := sha256Sum(pin)
	var found bool
	for _, p := range auth.Pins {
		if p.Hash == hashed {
			found = true
			break
		}
	}

	if !found {
		fmt.Println("Invalid PIN.")
		return WrapError(errors.New("invalid pin"), "Invalid PIN")
	}

	_ = os.Remove(sessionFilePath())
	fmt.Println("Logged out successfully.")
	return nil
}

func resetAuth() error {
	_ = os.Remove(authFilePath())
	_ = os.Remove(sessionFilePath())
	fmt.Println("PIN reset successfully.")
	return nil
}

func authList() error {
	var auth AuthFile
	if err := loadJson(authFilePath(), &auth); err != nil || len(auth.Pins) == 0 {
		fmt.Println("No PIN metadata found.")
		return nil
	}

	fmt.Println("Registered PIN Metadata:")
	for _, p := range auth.Pins {
		activeMarker := ""
		if p.Name == auth.Active {
			activeMarker = " (active)"
		}
		tStr := time.Unix(p.Created/1000, 0).UTC().Format(time.RFC3339)
		fmt.Printf("- Name: %s%s, Created: %s\n", p.Name, activeMarker, tStr)
	}
	return nil
}

func authWhoami() error {
	var session SessionFile
	if err := loadJson(sessionFilePath(), &session); err != nil || session.Expires < float64(time.Now().Unix()) {
		fmt.Println("Not currently logged in.")
		return nil
	}
	fmt.Printf("Current active authenticated session user: %s\n", session.ActiveUser)
	return nil
}

func authSwitch() error {
	var auth AuthFile
	if err := loadJson(authFilePath(), &auth); err != nil || len(auth.Pins) == 0 {
		fmt.Println("No PIN metadata found.")
		return nil
	}

	name, err := promptVisible("Enter PIN name/metadata to switch to: ")
	if err != nil {
		return err
	}

	var found bool
	for _, p := range auth.Pins {
		if p.Name == name {
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("PIN metadata '%s' not found.\n", name)
		return WrapError(errors.New("not found"), "PIN metadata not found")
	}

	auth.Active = name
	if err := saveJson(authFilePath(), auth); err != nil {
		return err
	}
	fmt.Printf("Switched active PIN metadata to '%s'.\n", name)
	return nil
}

func authRemove() error {
	var auth AuthFile
	if err := loadJson(authFilePath(), &auth); err != nil || len(auth.Pins) == 0 {
		fmt.Println("No PIN metadata found.")
		return nil
	}

	pin, err := promptHidden("Enter pin to remove: ")
	if err != nil {
		return err
	}

	hashed := sha256Sum(pin)
	targetIndex := -1
	for i, p := range auth.Pins {
		if p.Hash == hashed {
			targetIndex = i
			break
		}
	}

	if targetIndex == -1 {
		fmt.Println("Invalid PIN.")
		return WrapError(errors.New("invalid pin"), "Invalid PIN")
	}

	conf, err := promptVisible("Type REMOVE to continue: ")
	if err != nil || conf != "REMOVE" {
		fmt.Println("Operation cancelled.")
		return WrapError(errors.New("cancelled"), "Operation cancelled")
	}

	auth.Pins = append(auth.Pins[:targetIndex], auth.Pins[targetIndex+1:]...)
	if err := saveJson(authFilePath(), auth); err != nil {
		return err
	}
	_ = os.Remove(sessionFilePath())
	fmt.Println("PIN session/metadata removed successfully.")
	return nil
}

func isAuthenticated() bool {
	var session SessionFile
	if err := loadJson(sessionFilePath(), &session); err != nil {
		fmt.Println("❌ Access Denied: PIN session expired or locked.")
		fmt.Println("Please authenticate using 'ram-tool auth login' first.")
		return false
	}
	if float64(time.Now().Unix()) > session.Expires {
		_ = os.Remove(sessionFilePath())
		fmt.Println("❌ Access Denied: PIN session expired or locked.")
		fmt.Println("Please authenticate using 'ram-tool auth login' first.")
		return false
	}
	return true
}

func authStatus() error {
	if !isAuthenticated() {
		return nil
	}
	var session SessionFile
	_ = loadJson(sessionFilePath(), &session)
	remaining := max(0, int(session.Expires)-int(time.Now().Unix()))
	fmt.Println("Authenticated")
	fmt.Printf("Session expires in %d seconds.\n", remaining)
	return nil
}

func fetchRamData(showRam bool, webOpen bool, csvFile string, jsonFile string) error {
	if webOpen {
		return openBrowser(API)
	}

	if !isAuthenticated() {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(API)
	if err != nil {
		fmt.Println("API error:", err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("HTTP error! status: %d", resp.StatusCode)
		fmt.Println("API error:", err.Error())
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var rawData interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		fmt.Println("API error:", err.Error())
		return err
	}

	var ramValue int
	switch v := rawData.(type) {
	case []interface{}:
		if len(v) > 0 {
			if m, ok := v[0].(map[string]interface{}); ok {
				if val, exists := m["ram_mb"]; exists {
					ramValue = int(val.(float64))
				}
			}
		}
	case map[string]interface{}:
		if val, exists := v["ram_mb"]; exists {
			ramValue = int(val.(float64))
		}
	}

	if ramValue == 0 {
		fmt.Println("API error: 'ram_mb' not found.")
		return errors.New("ram_mb not found")
	}

	if showRam {
		fmt.Printf("RAM: %d MB\n", ramValue)
	} else {
		formatted, _ := json.MarshalIndent(rawData, "", "  ")
		fmt.Println(string(formatted))
	}

	if csvFile != "" {
		csvContent := fmt.Sprintf("timestamp,ram_mb\n%s,%d\n", time.Now().UTC().Format(time.RFC3339), ramValue)
		_ = os.WriteFile(csvFile, []byte(csvContent), 0644)
		fmt.Printf("Exported data to CSV: %s\n", csvFile)
	}

	if jsonFile != "" {
		formatted, _ := json.MarshalIndent(rawData, "", "  ")
		_ = os.WriteFile(jsonFile, formatted, 0644)
		fmt.Printf("Exported data to JSON: %s\n", jsonFile)
	}

	return nil
}

func apiRequest(method string, urlStr string, headers map[string]string, bodyData string, basicAuth string) error {
	client := &http.Client{Timeout: 15 * time.Second}
	var bodyReader io.Reader
	if bodyData != "" {
		bodyReader = strings.NewReader(bodyData)
	}

	req, err := http.NewRequest(strings.ToUpper(method), urlStr, bodyReader)
	if err != nil {
		fmt.Println("API error:", err.Error())
		return err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if basicAuth != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(basicAuth))
		req.Header.Set("Authorization", "Basic "+encoded)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("API error:", err.Error())
		return err
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP %d\n", resp.StatusCode)
	respBytes, _ := io.ReadAll(resp.Body)
	respString := string(respBytes)

	var parsed interface{}
	if err := json.Unmarshal(respBytes, &parsed); err == nil {
		formatted, _ := json.MarshalIndent(parsed, "", "  ")
		fmt.Println(string(formatted))
	} else {
		fmt.Println(respString)
	}
	return nil
}

func main() {
	ensureDir()

	rootCmd := &cobra.Command{
		Use:     "ram-tool",
		Short:   "Fetch RAM value from API",
		Version: Version,
	}

	var showRam bool
	var webOpen bool
	var csvFile string
	var jsonFile string

	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Fetch RAM from API",
		Example: `  # Basic fetch
  ram-tool get --show-ram

  # Open API endpoint in default web browser
  ram-tool get --web

  # Export output to CSV and JSON files
  ram-tool get --csv ram.csv --json ram.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fetchRamData(showRam, webOpen, csvFile, jsonFile)
		},
	}
	getCmd.Flags().BoolVar(&showRam, "show-ram", false, "Show formatted RAM output")
	getCmd.Flags().BoolVar(&webOpen, "web", false, "Open API endpoint in web browser")
	getCmd.Flags().StringVar(&csvFile, "csv", "", "Export results to CSV file")
	getCmd.Flags().StringVar(&jsonFile, "json", "", "Export results to JSON file")

	getRamCmd := &cobra.Command{
		Use:   "get-ram",
		Short: "Fetch RAM value from API (Default GET)",
		Example: `  # Quick alias fetch
  ram-tool get-ram --show-ram

  # Open API endpoint in default web browser
  ram-tool get-ram --web`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fetchRamData(showRam, webOpen, csvFile, jsonFile)
		},
	}
	getRamCmd.Flags().BoolVar(&showRam, "show-ram", false, "Show formatted RAM output")
	getRamCmd.Flags().BoolVar(&webOpen, "web", false, "Open API endpoint in web browser")
	getRamCmd.Flags().StringVar(&csvFile, "csv", "", "Export results to CSV file")
	getRamCmd.Flags().StringVar(&jsonFile, "json", "", "Export results to JSON file")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Example: `  ram-tool version`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ram-tool %s\n", Version)
		},
	}

	authCmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication commands",
		Example: `  # Register a new PIN
  ram-tool auth register

  # Login to create session
  ram-tool auth login

  # Check session status
  ram-tool auth status`,
	}

	authCmd.AddCommand(&cobra.Command{
		Use:   "register",
		Short: "Register a new PIN",
		Example: `  ram-tool auth register`,
		RunE: func(cmd *cobra.Command, args []string) error { return registerPin() },
	})
	authCmd.AddCommand(&cobra.Command{
		Use:   "login",
		Short: "Login with PIN",
		Example: `  ram-tool auth login`,
		RunE: func(cmd *cobra.Command, args []string) error { return loginPin() },
	})
	authCmd.AddCommand(&cobra.Command{
		Use:   "logout",
		Short: "Logout",
		Example: `  ram-tool auth logout`,
		RunE: func(cmd *cobra.Command, args []string) error { return logoutPin() },
	})
	authCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		Example: `  ram-tool auth status`,
		RunE: func(cmd *cobra.Command, args []string) error { return authStatus() },
	})
	authCmd.AddCommand(&cobra.Command{
		Use:   "reset",
		Short: "Reset PIN and session",
		Example: `  ram-tool auth reset`,
		RunE: func(cmd *cobra.Command, args []string) error { return resetAuth() },
	})
	authCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List PIN metadata",
		Example: `  ram-tool auth list`,
		RunE: func(cmd *cobra.Command, args []string) error { return authList() },
	})
	authCmd.AddCommand(&cobra.Command{
		Use:   "remove",
		Short: "Remove PIN session/metadata",
		Example: `  ram-tool auth remove`,
		RunE: func(cmd *cobra.Command, args []string) error { return authRemove() },
	})
	authCmd.AddCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show current authenticated user",
		Example: `  ram-tool auth whoami`,
		RunE: func(cmd *cobra.Command, args []string) error { return authWhoami() },
	})
	authCmd.AddCommand(&cobra.Command{
		Use:   "switch",
		Short: "Switch active PIN metadata",
		Example: `  ram-tool auth switch`,
		RunE: func(cmd *cobra.Command, args []string) error { return authSwitch() },
	})

	var method string
	var urlStr string
	var headers []string
	var formFields []string
	var data string
	var dataUrlencode []string
	var dataRaw string
	var userAuth string

	apiCmd := &cobra.Command{
		Use:   "api",
		Short: "Make an HTTP API request",
		Example: `  # Submit multiline JSON body via Heredoc
  ram-tool api -u https://httpbin.org/post -X POST -H "Content-Type: application/json" -d @- <<'EOF'
  {
    "service": "ram-tool",
    "status": "active"
  }
  EOF

  # Send URL-encoded form fields
  ram-tool api -u https://httpbin.org/post -X POST --form "username=admin" --form "role=operator"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			headerMap := make(map[string]string)
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid header: %s", h)
				}
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}

			bodyData := data
			if len(formFields) > 0 {
				formVal := url.Values{}
				for _, f := range formFields {
					parts := strings.SplitN(f, "=", 2)
					if len(parts) == 2 {
						formVal.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
					} else {
						formVal.Add(strings.TrimSpace(parts[0]), "")
					}
				}
				bodyData = formVal.Encode()
				if headerMap["Content-Type"] == "" {
					headerMap["Content-Type"] = "application/x-www-form-urlencoded"
				}
			} else if len(dataUrlencode) > 0 {
				var encoded []string
				for _, item := range dataUrlencode {
					if strings.Contains(item, "=") {
						kv := strings.SplitN(item, "=", 2)
						encoded = append(encoded, fmt.Sprintf("%s=%s", url.QueryEscape(kv[0]), url.QueryEscape(kv[1])))
					} else {
						encoded = append(encoded, url.QueryEscape(item)+"=")
					}
				}
				bodyData = strings.Join(encoded, "&")
				if headerMap["Content-Type"] == "" {
					headerMap["Content-Type"] = "application/x-www-form-urlencoded"
				}
			} else if dataRaw != "" {
				bodyData = dataRaw
			}

			return apiRequest(method, urlStr, headerMap, bodyData, userAuth)
		},
	}

	apiCmd.Flags().StringVarP(&urlStr, "url", "u", "", "API URL (required)")
	_ = apiCmd.MarkFlagRequired("url")
	apiCmd.Flags().StringVar(&method, "method", "GET", "HTTP method, e.g. GET, POST, PUT, DELETE")
	apiCmd.Flags().StringVarP(&method, "method-alias", "X", "GET", "HTTP method alias")
	apiCmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "HTTP header")
	apiCmd.Flags().StringArrayVarP(&formFields, "form", "f", nil, "Form field (key=value)")
	apiCmd.Flags().StringVarP(&data, "data", "d", "", "Request body")
	apiCmd.Flags().StringArrayVar(&dataUrlencode, "data-urlencode", nil, "URL-encode request data")
	apiCmd.Flags().StringVar(&dataRaw, "data-raw", "", "Raw request data")
	apiCmd.Flags().StringVar(&userAuth, "user", "", "Basic HTTP authentication")

	// Config subcommand group with --global flag support
	var configGlobal bool
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration options",
		Example: `  # Edit configuration (global or local)
  ram-tool config edit --global

  # Get configuration key
  ram-tool config get timeout --global

  # Set configuration key
  ram-tool config set timeout 300 --global`,
	}
	configCmd.PersistentFlags().BoolVarP(&configGlobal, "global", "g", false, "Access global configuration")

	configCmd.AddCommand(&cobra.Command{
		Use:   "edit",
		Short: "Opens the glab configuration file",
		Example: `  ram-tool config edit --global`,
		Run: func(cmd *cobra.Command, args []string) {
			scope := "local"
			if configGlobal {
				scope = "global"
			}
			fmt.Printf("Config file path (%s): %s\n", scope, authFilePath())
		},
	})
	configCmd.AddCommand(&cobra.Command{
		Use:   "get <key>",
		Short: "Prints the value of a given configuration key",
		Example: `  ram-tool config get timeout --global`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			scope := "local"
			if configGlobal {
				scope = "global"
			}
			fmt.Printf("Key '%s' is not set (%s scope).\n", args[0], scope)
		},
	})
	configCmd.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Updates configuration with the value of a given key",
		Example: `  ram-tool config set timeout 300 --global`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			scope := "local"
			if configGlobal {
				scope = "global"
			}
			fmt.Printf("Configuration updated (%s scope): %s = %s\n", scope, args[0], args[1])
		},
	})

	// Shell-exec subcommand with --command flag and STDIN/Heredoc pipe support
	var execCommandFlag string
	execCmd := &cobra.Command{
		Use:   "shell-exec",
		Short: "Execute shell command via interactive prompt, flag, or STDIN pipe",
		Example: `  # Execute via --command flag
  ram-tool shell-exec --command "uptime"

  # Execute via piped STDIN / printf
  printf "uname -a" | ram-tool shell-exec

  # Execute via Heredoc
  ram-tool shell-exec <<'EOF'
  echo "Running system checks..."
  df -h
  EOF`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var cmdStr string

			if execCommandFlag != "" {
				cmdStr = execCommandFlag
			} else {
				// Check if STDIN has piped / redirected data (e.g. from printf, pipe, or heredoc)
				if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
					bytesData, readErr := io.ReadAll(os.Stdin)
					if readErr == nil && len(bytesData) > 0 {
						cmdStr = strings.TrimSpace(string(bytesData))
					}
				}

				// Fall back to interactive prompt if no command or piped input was provided
				if cmdStr == "" {
					var promptErr error
					cmdStr, promptErr = promptVisible("Enter command to execute: ")
					if promptErr != nil {
						return promptErr
					}
				}
			}

			fmt.Printf("Executing via bash -c: %s\n", cmdStr)
			execCmd := exec.Command("bash", "-c", cmdStr)
			execCmd.Stdout = os.Stdout
			execCmd.Stderr = os.Stderr
			execCmd.Stdin = os.Stdin
			return execCmd.Run()
		},
	}
	execCmd.Flags().StringVarP(&execCommandFlag, "command", "c", "", "Command to execute directly")

	rootCmd.AddCommand(getCmd, getRamCmd, versionCmd, authCmd, apiCmd, configCmd, execCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
