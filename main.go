//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func main() {
	fmt.Println("=== Сброс правил брандмауэра Windows ===")

	if !isAdmin() {
		fmt.Println("[!] Запуск без прав администратора.")
		fmt.Println("    Попытка перезапустить с правами администратора...")
		err := runAsAdmin()
		if err != nil {
			fmt.Println("Не удалось запросить права администратора:", err)
			waitExit()
			os.Exit(1)
		}
		return
	}

	fmt.Println("[+] Запущено с правами администратора.")
	fmt.Println("[*] Выполняю команду: netsh advfirewall reset")

	cmd := exec.Command("netsh", "advfirewall", "reset")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	out, err := cmd.CombinedOutput()

	if len(out) > 0 {
		fmt.Println("\n--- Вывод команды ---")
		fmt.Print(string(out))
		fmt.Println("---------------------\n")
	}

	if err != nil {
		fmt.Println("Ошибка выполнения команды:", err)
		waitExit()
		os.Exit(1)
	}

	fmt.Println("[✔] Готово. Правила брандмауэра сброшены к значениям по умолчанию.")
	waitExit()
}

func isAdmin() bool {
	cmd := exec.Command("net", "session")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func runAsAdmin() error {
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

	hInstance, _, errShell := shellExecuteW(
		0,
		&verb[0],
		&lpFile[0],
		&lpParameters[0],
		nil,
		1,
	)

	if hInstance <= 32 {
		return fmt.Errorf("ShellExecuteW вернул код %d (ошибка: %v)", hInstance, errShell)
	}
	return nil
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if needsQuotes(a) {
			a = `"` + a + `"`
		}
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func needsQuotes(s string) bool {
	for _, r := range s {
		if r == ' ' || r == '\t' {
			return true
		}
	}
	return false
}

var (
	shell32        = syscall.NewLazyDLL("shell32.dll")
	procShellExecW = shell32.NewProc("ShellExecuteW")
)

func shellExecuteW(hwnd uintptr, lpOperation *uint16, lpFile *uint16, lpParameters *uint16, lpDirectory *uint16, nShowCmd int32) (uintptr, uintptr, error) {
	r1, r2, err := procShellExecW.Call(
		hwnd,
		uintptr(unsafe.Pointer(lpOperation)),
		uintptr(unsafe.Pointer(lpFile)),
		uintptr(unsafe.Pointer(lpParameters)),
		uintptr(unsafe.Pointer(lpDirectory)),
		uintptr(nShowCmd),
	)
	return r1, r2, err
}

func utf16FromString(s string) []uint16 {
	u := utf16.Encode([]rune(s))
	return append(u, 0)
}

func waitExit() {
	fmt.Println("\nНажмите Enter для выхода...")
	fmt.Scanln()
}
