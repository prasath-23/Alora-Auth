// Command bootstrap provisions the first tenant, its first product subscription
// and its first administrator.
//
// This exists because the API deliberately has no self-service signup: there is
// no HTTP route that creates a tenant, because anyone who could call it could
// create tenants. Somebody has to seed the first administrator out of band, and
// doing it by hand means writing an argon2 hash by hand — which is exactly how
// people end up pasting a weak or wrongly-parameterised hash into production.
//
//	go run ./cmd/bootstrap \
//	  -tenant "Acme Corp" \
//	  -email  admin@acme.com \
//	  -product CRM \
//	  -product-url https://crm.acme.com
//
// The password is read from the terminal without echoing, or from
// BOOTSTRAP_PASSWORD when running unattended. It is never taken as a flag, since
// flags land in shell history and in the process list.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alora/auth/internal/config"
	"github.com/alora/auth/internal/crypto/password"
	"github.com/alora/auth/internal/platform/database"
	"github.com/alora/auth/internal/platform/database/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/term"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		tenant     = flag.String("tenant", "", "tenant (organisation) name — required")
		email      = flag.String("email", "", "administrator's email address — required")
		domain     = flag.String("domain", "", "tenant email domain, e.g. acme.com (optional)")
		verify     = flag.Bool("verify-domain", false, "mark the domain verified — grants CORS trust and enables Google tenant resolution")
		productKey = flag.String("product", "", "product key to create and subscribe, e.g. CRM (optional)")
		productURL = flag.String("product-url", "", "product base URL — required with -product; login redirects are restricted to this origin")
	)
	flag.Parse()

	if *tenant == "" || *email == "" {
		flag.Usage()
		return errors.New("-tenant and -email are required")
	}
	if *productKey != "" && *productURL == "" {
		return errors.New("-product-url is required with -product: the base URL is what constrains login redirects")
	}
	if *verify && *domain == "" {
		return errors.New("-verify-domain requires -domain")
	}

	pw, err := readPassword()
	if err != nil {
		return err
	}
	// Hashing here (rather than in SQL) means the credential is created with
	// exactly the argon2 parameters the API verifies against.
	hash, err := password.Hash(pw)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// One connection: this runs once, by hand, and has no reason to occupy a
	// production-sized slice of the database's connection budget.
	pool, err := database.New(ctx, cfg.DatabaseURL, database.Options{MaxConns: 1, MinConns: 1})
	if err != nil {
		return err
	}
	defer pool.Close()
	q := sqlc.New(pool)

	// One transaction: a tenant with no administrator is not a useful outcome to
	// leave behind if a later step fails.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := q.WithTx(tx)

	normalisedEmail := strings.ToLower(strings.TrimSpace(*email))

	var verifiedAt pgtype.Timestamptz
	if *verify {
		verifiedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	}
	client, err := qtx.CreateClient(ctx, sqlc.CreateClientParams{
		Name:                *tenant,
		Domain:              text(*domain),
		AllowedIdpProviders: []sqlc.IdpProvider{sqlc.IdpProviderEMAIL, sqlc.IdpProviderGOOGLE},
		RequireMfa:          false,
		SubscriptionStatus:  sqlc.SubscriptionStatusACTIVE,
		MaxSeats:            pgtype.Int4{},
		IsActive:            true,
	})
	if err != nil {
		return fmt.Errorf("create tenant: %w", err)
	}
	if *verify {
		// Verification is a separate update because CreateClient deliberately
		// refuses to set it: a tenant must never be born already trusted.
		if _, err := qtx.UpdateClient(ctx, sqlc.UpdateClientParams{
			ClientID: client.ID, Name: client.Name, RequireMfa: client.RequireMfa,
			AllowedIdpProviders: client.AllowedIdpProviders,
			DomainVerifiedAt:    verifiedAt,
			SubscriptionStatus:  client.SubscriptionStatus,
			MaxSeats:            client.MaxSeats, IsActive: client.IsActive,
		}); err != nil {
			return fmt.Errorf("verify domain: %w", err)
		}
	}

	user, err := qtx.CreateUser(ctx, sqlc.CreateUserParams{
		ClientID: client.ID, Email: normalisedEmail,
		PasswordHash: pgtype.Text{String: hash, Valid: true},
		AccountType:  sqlc.AccountTypeEMAIL,
	})
	if err != nil {
		return fmt.Errorf("create administrator: %w", err)
	}

	var product sqlc.TblProduct
	if *productKey != "" {
		product, err = qtx.CreateProduct(ctx, sqlc.CreateProductParams{
			Key: *productKey, Name: *productKey,
			Description: text(""), BaseUrl: text(*productURL), IsActive: true,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errors.New("create product returned no row")
			}
			return fmt.Errorf("create product: %w", err)
		}
		if err := subscribe(ctx, tx, client.ID, product.ID); err != nil {
			return err
		}
		// The administrator needs the Admin role IN a product: RBAC precedence is
		// is_global_admin, then any product role of "Admin". Without this the
		// account exists but can reach nothing.
		if err := qtx.UpsertProductPermission(ctx, sqlc.UpsertProductPermissionParams{
			PUserid: user.ID, PClientid: client.ID, PProductid: product.ID,
			PRolename: "Admin", PGrantedby: user.ID,
		}); err != nil {
			return fmt.Errorf("grant admin role: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Println("Bootstrap complete.")
	fmt.Printf("  tenant    %s  (%s)\n", client.Name, client.ID)
	fmt.Printf("  admin     %s  (%s)\n", normalisedEmail, user.ID)
	if *productKey != "" {
		fmt.Printf("  product   %s  (%s)  base_url %s\n", product.Key, product.ID, *productURL)
		fmt.Println()
		fmt.Println("Sign in by sending the user to the authorize endpoint with PKCE parameters:")
		fmt.Printf("  %s/?product_id=%s&redirect_url=%s&code_challenge=<challenge>&code_challenge_method=S256&state=<state>\n",
			cfg.FrontendURL, product.ID, *productURL)
	} else {
		fmt.Println()
		fmt.Println("No product was created, so this administrator cannot sign in yet:")
		fmt.Println("login requires a product_id. Re-run with -product and -product-url.")
	}
	return nil
}

// subscribe links a tenant to a product. There is no stored procedure for this
// because it is a provisioning action, not part of the API surface.
func subscribe(ctx context.Context, tx pgx.Tx, clientID, productID string) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO tbl_client_products (client_id, product_id, is_active) VALUES ($1, $2, true)`,
		clientID, productID)
	if err != nil {
		return fmt.Errorf("subscribe tenant to product: %w", err)
	}
	return nil
}

// readPassword takes the password from the terminal without echoing it, or from
// BOOTSTRAP_PASSWORD when there is no terminal (CI, containers). It is never a
// flag: flags are visible in shell history and in the process list.
func readPassword() (string, error) {
	if pw := os.Getenv("BOOTSTRAP_PASSWORD"); pw != "" {
		return pw, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal available; set BOOTSTRAP_PASSWORD instead")
	}

	fmt.Print("Administrator password: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	fmt.Print("Confirm password: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}

	pw := string(first)
	if pw != string(second) {
		return "", errors.New("passwords do not match")
	}
	// The API enforces a minimum of 8 on the reset and invite paths; the first
	// administrator should not be the weakest account in the system.
	if len(pw) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	return pw, nil
}

func text(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}
