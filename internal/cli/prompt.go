package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// promptPassphrase reads a passphrase from the terminal without echoing.
// Falls back to plain stdin (echoed) on non-TTY inputs, so scripted flows
// like `echo "pw" | drift recover --stdin-passphrase` work.
func promptPassphrase(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		return string(raw), nil
	}
	// Non-TTY: read a single line from stdin (no masking possible).
	br := bufio.NewReader(os.Stdin)
	line, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptPassphraseConfirm asks for a passphrase twice and requires the
// inputs match. Retries the pair up to maxPassphraseAttempts on
// mismatch — a typo on the confirm shouldn't kick the user out of the
// flow.
func promptPassphraseConfirm(prompt, confirmPrompt string) (string, error) {
	for attempt := 1; attempt <= maxPassphraseAttempts; attempt++ {
		first, err := promptPassphrase(prompt)
		if err != nil {
			return "", err
		}
		second, err := promptPassphrase(confirmPrompt)
		if err != nil {
			return "", err
		}
		if first == second {
			return first, nil
		}
		remaining := maxPassphraseAttempts - attempt
		if remaining > 0 {
			fmt.Fprintf(os.Stderr, "Passphrases do not match. Try again (%d attempts left).\n", remaining)
		}
	}
	return "", fmt.Errorf("passphrases did not match after %d attempts", maxPassphraseAttempts)
}

const maxPassphraseAttempts = 3

// promptYesNo prompts y/n with a default. Non-TTY → returns def silently.
func promptYesNo(question string, def bool) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return def
	}
	defaultMark := "[Y/n]"
	if !def {
		defaultMark = "[y/N]"
	}
	fmt.Fprintf(os.Stderr, "%s %s ", question, defaultMark)
	br := bufio.NewReader(os.Stdin)
	line, _ := br.ReadString('\n')
	trimmed := strings.ToLower(strings.TrimSpace(line))
	if trimmed == "" {
		return def
	}
	return trimmed == "y" || trimmed == "yes"
}
