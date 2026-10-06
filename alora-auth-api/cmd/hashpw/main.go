// Command hashpw prints an argon2id hash for a plaintext password.
//
// Test fixtures use it so seeded passwords are hashed with EXACTLY the
// parameters the API verifies against — hard-coding a hash would silently rot
// the moment those parameters changed.
package main

import (
	"fmt"
	"os"

	"github.com/alora/auth/internal/core/shared/crypto/password"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hashpw <plaintext>")
		os.Exit(2)
	}
	h, err := password.Hash(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}
	fmt.Println(h)
}
