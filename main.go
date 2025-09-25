package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const appName = "FirewallSmartReset"

var targetIPs = []string{
	"195.18.27.50",
	"82.117.87.77",
	"77.110.105.127",
	"77.110.105.204",
	"77.110.105.203",
	"77.110.105.205",
	"77.110.105.206",
	"5.42.211.37",
}

var (
	flagRemoveAutostart bool
	flagQuietStart      bool
	flagDebugRules      bool
)

var (
	shell32                 = syscall.NewLazyDLL("shell32.dll")
	procShellExecW          = shell32.NewProc("ShellExecuteW")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procShowWindow          = user32.NewProc("ShowWindow")
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleWnd       = kernel32.NewProc("GetConsoleWindow")
	SW_HIDE           int32 = 0
)

func init() {
	flag.BoolVar(&flagRemoveAutostart, "remove-autostart", false, "Удалить автозапуск")
	flag.BoolVar(&flagQuietStart, "quiet-start", false, "Тихий запуск (без консоли/вывода)")
	flag.BoolVar(&flagDebugRules, "debug-rules", false, "Показать источники правил и их RemoteAddress (диагностика)")
}

func main() {
	flag.Parse()
	if flagQuietStart {
		hideConsoleWindow()
	}

	if flagRemoveAutostart {
		if !flagQuietStart {
			fmt.Println("[*] Удаляю автозапуск...")
		}
		removeAutostart(appName)
		if !flagQuietStart {
			fmt.Println("[✔] Автозапуск удалён.")
			waitExit()
		}
		return
	}

	if !flagQuietStart {
		fmt.Println("=== Исправление сетевых проблем ===")
	}

	if !isAdmin() {
		if !flagQuietStart {
			fmt.Println("[!] Нет прав администратора. Перезапуск с UAC...")
		}
		if err := runAsAdminWithSameArgs(); err != nil {
			if !flagQuietStart {
				fmt.Println("Не удалось запросить права администратора:", err)
				waitExit()
			}
			os.Exit(1)
		}
		return
	}

	if exists, _ := autostartExists(appName); !exists {
		_ = ensureAutostart(appName, true, "--quiet-start")
	}

	comRules, _ := getBlockedFirewallRules_COM()
	psRules, _ := getBlockedFirewallRules_PS() // если модуль недоступен — просто пусто

	merged := mergeRules(comRules, psRules)

	if flagDebugRules && !flagQuietStart {
		fmt.Printf("\n[DEBUG] Источники правил:\n  COM: %d шт.\n  PS : %d шт.\n  MER: %d шт.\n", len(comRules), len(psRules), len(merged))
		for _, r := range merged {
			fmt.Printf("  - %s (dir=%s) -> %v\n", r.Name, strings.ToLower(normDirection(r.Direction)), r.RemoteAddress)
		}
		fmt.Println()
	}

	matches := matchRulesForIPs(merged, targetIPs)

	if len(matches) == 0 {
		if !flagQuietStart {
			fmt.Println("[i] Все проверки прошло успешно - проблем не обнаруженно")
		}
	} else {
		if !flagQuietStart {
			fmt.Println("[+] Найдены проблемы:")
			for ip, rs := range matches {
				fmt.Printf("   IP %s:\n", ip)
				for _, r := range rs {
					fmt.Printf("     - %s (dir=%s)\n", r.Name, strings.ToLower(normDirection(r.Direction)))
				}
			}
			fmt.Println("[*] Выполнем исправленеи сетевых настроек...")
		}
		_ = runNetshReset(flagQuietStart)
		if !flagQuietStart {
			fmt.Println("[✔] Готово. Все сетевые проблемы были устранены.")
		}
	}

	if !flagQuietStart {
		fmt.Println("\n[?] Введите «Да» в течение 5 секунд, чтобы удалить автозапуск.")
		if inputYesWithin(5 * time.Second) {
			removeAutostart(appName)
			fmt.Println("[✔] Автозапуск удалён по запросу пользователя.")
		} else {
			fmt.Println("[i] Перезапустите приложение, если захотите убрать его из авто-загрузки.")
		}
		waitExit()
	}
}

func isAdmin() bool {
	cmd := exec.Command("net", "session")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

func runAsAdminWithSameArgs() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	args := ""
	if len(os.Args) > 1 {
		args = joinArgs(os.Args[1:])
	}
	verb := utf16FromString("runas")
	lpFile := utf16FromString(exe)
	lpParameters := utf16FromString(args)
	hInstance, _, errShell := procShellExecW.Call(
		0,
		uintptr(unsafe.Pointer(&verb[0])),
		uintptr(unsafe.Pointer(&lpFile[0])),
		uintptr(unsafe.Pointer(&lpParameters[0])),
		0,
		uintptr(int32(1)),
	)
	if hInstance <= 32 {
		return fmt.Errorf("ShellExecuteW вернул код %d (ошибка: %v)", hInstance, errShell)
	}
	return nil
}

func hideConsoleWindow() {
	hwnd, _, _ := procGetConsoleWnd.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, uintptr(SW_HIDE))
	}
}

func utf16FromString(s string) []uint16 {
	u := utf16.Encode([]rune(s))
	return append(u, 0)
}

func ensureAutostart(appName string, useTaskIfAdmin bool, extraArgs ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	fullCmd := quote(exe)
	if len(extraArgs) > 0 {
		fullCmd += " " + joinArgs(extraArgs)
	}
	if useTaskIfAdmin && isAdmin() {
		cmd := exec.Command("schtasks", "/Create", "/TN", appName,
			"/TR", fullCmd, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
		_ = cmd.Run()
		return nil
	}
	cmd := exec.Command("reg", "add",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", appName, "/t", "REG_SZ", "/d", fullCmd, "/f")
	_ = cmd.Run()
	return nil
}

func autostartExists(appName string) (bool, error) {
	if exec.Command("schtasks", "/Query", "/TN", appName).Run() == nil {
		return true, nil
	}
	if out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", appName).CombinedOutput(); err == nil && strings.Contains(string(out), appName) {
		return true, nil
	}
	return false, nil
}

func removeAutostart(appName string) {
	_ = exec.Command("schtasks", "/Delete", "/TN", appName, "/F").Run()
	_ = exec.Command("reg", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", appName, "/f").Run()
}

func runNetshReset(quiet bool) error {
	cmd := exec.Command("netsh", "advfirewall", "reset")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: quiet}
	_, err := cmd.CombinedOutput()
	return err
}

type fwRule struct {
	Name          string      `json:"Name"`
	Direction     interface{} `json:"Direction"`     // 1/2 или "Inbound/Outbound"
	RemoteAddress interface{} `json:"RemoteAddress"` // string | []string | nil
	_src          string      // "COM" или "PS"
}

func normDirection(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if int(t) == 1 {
			return "Inbound"
		}
		if int(t) == 2 {
			return "Outbound"
		}
		return fmt.Sprintf("%v", int(t))
	default:
		if t == nil {
			return ""
		}
		return fmt.Sprintf("%v", t)
	}
}

func getBlockedFirewallRules_COM() ([]fwRule, error) {
	ps := `
$ErrorActionPreference="Stop"
$fw = New-Object -ComObject HNetCfg.FwPolicy2
$result = foreach ($r in $fw.Rules) {
  try {
    if (-not $r.Enabled) { continue }
    if ($r.Action -ne 0) { continue } # 0=Block
    [PSCustomObject]@{
      Name          = $r.Name
      Direction     = $r.Direction   # 1=in, 2=out
      RemoteAddress = $r.RemoteAddresses  # строка: "*", "a,b,c", "x-y", "cidr"
    }
  } catch {}
}
$result | ConvertTo-Json -Compress -Depth 4
`
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	trim := strings.TrimSpace(out.String())
	if trim == "" {
		return []fwRule{}, nil
	}
	var arr []fwRule
	if strings.HasPrefix(trim, "{") {
		var one fwRule
		if e := json.Unmarshal([]byte(trim), &one); e != nil {
			return nil, e
		}
		one._src = "COM"
		return []fwRule{one}, nil
	}
	if e := json.Unmarshal([]byte(trim), &arr); e != nil {
		return nil, e
	}
	for i := range arr {
		arr[i]._src = "COM"
	}
	return arr, nil
}

func getBlockedFirewallRules_PS() ([]fwRule, error) {
	ps := `
$ErrorActionPreference="Stop"
try {
  $rules = Get-NetFirewallRule -Action Block -Enabled True
} catch {
  return
}

$result = foreach ($r in $rules) {
  $addr = @()

  try {
    $af1 = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
    if ($af1) { $addr += $af1.RemoteAddress }
  } catch {}

  try {
    $af2 = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    if ($af2) { $addr += $af2.RemoteAddress }
  } catch {}

  try {
    if ($r.PSObject.Properties.Match('RemoteAddress').Count -gt 0 -and $r.RemoteAddress) {
      $addr += $r.RemoteAddress
    }
  } catch {}

  $flat = @()
  foreach ($a in $addr) {
    if ($a -is [Array]) { $flat += $a } else { $flat += @($a) }
  }

  [PSCustomObject]@{
    Name = $r.Name
    Direction = $r.Direction
    RemoteAddress = $flat
  }
}
$result | ConvertTo-Json -Compress -Depth 8
`
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		// модуль может быть недоступен — это не фатал
		return []fwRule{}, nil
	}

	trim := strings.TrimSpace(out.String())
	if trim == "" {
		return []fwRule{}, nil
	}
	var arr []fwRule
	if strings.HasPrefix(trim, "{") {
		var one fwRule
		if e := json.Unmarshal([]byte(trim), &one); e != nil {
			return nil, e
		}
		one._src = "PS"
		return []fwRule{one}, nil
	}
	if e := json.Unmarshal([]byte(trim), &arr); e != nil {
		return nil, e
	}
	for i := range arr {
		arr[i]._src = "PS"
	}
	return arr, nil
}

func mergeRules(a, b []fwRule) []fwRule {
	type key struct{ name, dir string }
	m := make(map[key]fwRule)

	add := func(r fwRule) {
		k := key{strings.ToLower(r.Name), strings.ToLower(normDirection(r.Direction))}
		if ex, ok := m[k]; ok {
			// объединяем RemoteAddress
			m[k] = fwRule{
				Name:          ex.Name,
				Direction:     ex.Direction,
				RemoteAddress: mergeAddresses(ex.RemoteAddress, r.RemoteAddress),
				_src:          ex._src + "+" + r._src,
			}
		} else {
			m[k] = r
		}
	}

	for _, r := range a {
		add(r)
	}
	for _, r := range b {
		add(r)
	}

	out := make([]fwRule, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	return out
}

func mergeAddresses(a, b interface{}) interface{} {
	al := normalizeRemoteAddresses(a)
	bl := normalizeRemoteAddresses(b)
	seen := map[string]struct{}{}
	var out []string
	for _, s := range append(al, bl...) {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func matchRulesForIPs(rules []fwRule, ips []string) map[string][]fwRule {
	result := make(map[string][]fwRule)
	for _, ip := range ips {
		for _, r := range rules {
			if ruleAffectsIP(r, ip) {
				result[ip] = append(result[ip], r)
			}
		}
	}
	return result
}

func ruleAffectsIP(r fwRule, ip string) bool {
	items := normalizeRemoteAddresses(r.RemoteAddress)
	for _, it := range items {
		s := strings.TrimSpace(it)
		if s == "" {
			continue
		}
		lo := strings.ToLower(s)
		if lo == "*" || lo == "any" || lo == "anywhere" || lo == "anyany" || lo == "any0" {
			return true
		}
		if strings.EqualFold(s, "LocalSubnet") {
			// можно реализовать проверку локальных подсетей
			continue
		}
		if strings.Contains(s, "/") {
			if ipInCIDR(ip, s) {
				return true
			}
			continue
		}
		if strings.Contains(s, "-") {
			parts := strings.SplitN(s, "-", 2)
			if len(parts) == 2 && ipInRange(ip, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])) {
				return true
			}
			continue
		}
		if s == ip {
			return true
		}
	}
	return false
}

var csvSplitter = regexp.MustCompile(`\s*,\s*`)

func normalizeRemoteAddresses(v interface{}) []string {
	var out []string
	switch t := v.(type) {
	case nil:
		return out
	case string:
		out = append(out, splitCSV(t)...)
	case []interface{}:
		for _, x := range t {
			switch y := x.(type) {
			case string:
				out = append(out, splitCSV(y)...)
			default:
				out = append(out, fmt.Sprint(y))
			}
		}
	default:
		out = append(out, fmt.Sprint(t))
	}
	return out
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return csvSplitter.Split(s, -1)
}

func ipInCIDR(ip, cidr string) bool {
	_, nw, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ipv := net.ParseIP(ip)
	if ipv == nil {
		return false
	}
	return nw.Contains(ipv)
}

func ipToUint32(ip string) (uint32, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0, false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return 0, false
	}
	return (uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])), true
}

func ipInRange(ip, start, end string) bool {
	iv, ok := ipToUint32(ip)
	if !ok {
		return false
	}
	sv, ok := ipToUint32(start)
	if !ok {
		return false
	}
	ev, ok := ipToUint32(end)
	if !ok {
		return false
	}
	if sv > ev {
		sv, ev = ev, sv
	}
	return iv >= sv && iv <= ev
}

func waitExit() {
	fmt.Println("\nНажмите Enter для выхода...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func inputYesWithin(timeout time.Duration) bool {
	fmt.Print(">> ")
	ch := make(chan bool, 1)
	go func() {
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		ch <- strings.EqualFold(line, "да")
	}()
	select {
	case yes := <-ch:
		return yes
	case <-time.After(timeout):
		fmt.Println("\n[i] Можно запускать игру.")
		return false
	}
}

func quote(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}

func joinArgs(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.ContainsAny(a, " \t\"") {
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(a, `"`, `\"`))
			b.WriteByte('"')
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}
