// Command bootstrap provisions what App Central deliberately has no API for.
//
// There is no self-service signup and no route that creates an Owner, because
// anyone who could call it could make themselves the Owner of every company.
// Somebody has to seed the first Owner out of band, and doing it by hand means
// writing an argon2 hash by hand — which is how weak or wrongly-parameterised
// hashes reach production. This does it properly, in one transaction, connected
// as the SCHEMA OWNER (DATABASE_URL): the application role cannot write
// tbl_platform_owners at all.
//
//	go run ./cmd/bootstrap platform -name "Alora" -email owner@alora.io
//
// creates the platform company and its first Owner (who is also a member of its
// Admins group). Everything else — companies, products, groups — the Owner then
// does in the Owner console. For a development or demo setup,
//
//	go run ./cmd/bootstrap demo -company "Acme Corp" -email admin@acme.test \
//	  -product CRM -base-url http://127.0.0.1:5174 \
//	  -initiate-login-uri http://127.0.0.1:5174/login \
//	  -redirect-uri http://127.0.0.1:5174/callback -roles Admin,Editor,Viewer
//
// creates a company with an Admin, registers a product (printing its client
// secret once), subscribes the company, and lets its Admins group into the
// product with the first role.
//
// Passwords are read from the terminal without echoing, or from
// BOOTSTRAP_PASSWORD when running unattended — never from a flag, since flags
// land in shell history and in the process list.
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
	"github.com/alora/auth/internal/core/shared/crypto/password"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	"github.com/alora/auth/internal/database/contexts"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/clientproducts"
	"github.com/alora/auth/internal/database/services/clients"
	"github.com/alora/auth/internal/database/services/groups"
	"github.com/alora/auth/internal/database/services/products"
	"github.com/alora/auth/internal/database/services/usergroups"
	"github.com/alora/auth/internal/database/services/users"
	"golang.org/x/term"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New("usage: bootstrap platform|demo [flags]; run with -h after the mode for its flags")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "platform":
		return platform(args[1:])
	case "demo":
		return demo(args[1:])
	default:
		return usage()
	}
}

// open connects as the schema owner, with one connection: this runs once, by
// hand, and has no reason to occupy a production-sized slice of the pool.
func open(ctx context.Context) (*contexts.DbContext, error) {
	dsn, err := config.LoadDatabase()
	if err != nil {
		return nil, err
	}
	return contexts.Connect(ctx, dsn, contexts.Options{MaxConns: 1, MinConns: 1})
}

// admin creates a password account and puts it in its company's Admins group.
func admin(ctx context.Context, q contexts.Querier, clientID, email, hash string) (dbmodels.User, error) {
	user, err := users.NewUserDbService(q).Create(ctx, clientID, email, &hash, dbmodels.AccountTypeEmail)
	if err != nil {
		return dbmodels.User{}, fmt.Errorf("create %s: %w", email, err)
	}
	adminsID, err := groups.NewGroupDbService(q).SystemGroupID(ctx, clientID, dbmodels.SystemGroupAdmins)
	if err != nil {
		return dbmodels.User{}, fmt.Errorf("find the Admins group: %w", err)
	}
	if err := usergroups.NewUserGroupDbService(q).Add(ctx, user.ID, adminsID, clientID, ""); err != nil {
		return dbmodels.User{}, fmt.Errorf("add %s to Admins: %w", email, err)
	}
	return user, nil
}

func platform(args []string) error {
	fs := flag.NewFlagSet("platform", flag.ContinueOnError)
	name := fs.String("name", "", "platform company name — required")
	email := fs.String("email", "", "the first Owner's email address — required")
	domain := fs.String("domain", "", "the platform company's verified email domain (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *email == "" {
		fs.Usage()
		return errors.New("-name and -email are required")
	}
	hash, err := readHash("Owner")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	co, err := clients.NewClientDbService(tx).Create(ctx, clients.NewClient{
		Name: *name, Domain: *domain, SubscriptionStatus: dbmodels.SubscriptionActive, IsActive: true, IsPlatform: true,
	})
	if err != nil {
		return fmt.Errorf("create the platform company (is there one already?): %w", err)
	}
	if *domain != "" {
		if _, err := clients.NewClientDbService(tx).SetDomain(ctx, co.ID, domain, true); err != nil {
			return fmt.Errorf("verify the domain: %w", err)
		}
	}
	owner, err := admin(ctx, tx, co.ID, normalise(*email), hash)
	if err != nil {
		return err
	}
	if err := users.NewUserDbService(tx).CreatePlatformOwner(ctx, owner.ID, co.ID); err != nil {
		return fmt.Errorf("make %s an Owner (connect as the schema owner, not alora_app): %w", owner.Email, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	fmt.Println("Platform provisioned.")
	fmt.Printf("  company   %s  (%s)\n", co.Name, co.ID)
	fmt.Printf("  owner     %s  (%s)\n", owner.Email, owner.ID)
	fmt.Println("Sign in at App Central with that address; the Owner console is at /owner.")
	return nil
}

func demo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	company := fs.String("company", "", "company name — required")
	email := fs.String("email", "", "the company's first Admin — required")
	domain := fs.String("domain", "", "the company's verified email domain (optional)")
	key := fs.String("product", "", "product key to register, e.g. CRM — required")
	productName := fs.String("product-name", "", "product display name (defaults to the key)")
	baseURL := fs.String("base-url", "", "product base URL — required")
	initiate := fs.String("initiate-login-uri", "", "where App Central launches the product — required")
	redirect := fs.String("redirect-uri", "", "the product's OAuth redirect URI — required")
	roles := fs.String("roles", "Admin", "comma-separated role catalogue; the first is granted to the Admins group")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *company == "" || *email == "" || *key == "" || *baseURL == "" || *initiate == "" || *redirect == "" {
		fs.Usage()
		return errors.New("-company, -email, -product, -base-url, -initiate-login-uri and -redirect-uri are required")
	}
	var roleList []string
	for _, r := range strings.Split(*roles, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roleList = append(roleList, r)
		}
	}
	if len(roleList) == 0 {
		return errors.New("-roles needs at least one role")
	}
	if *productName == "" {
		productName = key
	}
	hash, err := readHash("Admin")
	if err != nil {
		return err
	}
	secret, err := tokens.GenerateOpaque()
	if err != nil {
		return err
	}
	secret = "acs_" + secret

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := open(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	co, err := clients.NewClientDbService(tx).Create(ctx, clients.NewClient{
		Name: *company, Domain: *domain, SubscriptionStatus: dbmodels.SubscriptionActive, IsActive: true,
	})
	if err != nil {
		return fmt.Errorf("create the company: %w", err)
	}
	if *domain != "" {
		if _, err := clients.NewClientDbService(tx).SetDomain(ctx, co.ID, domain, true); err != nil {
			return fmt.Errorf("verify the domain: %w", err)
		}
	}
	a, err := admin(ctx, tx, co.ID, normalise(*email), hash)
	if err != nil {
		return err
	}

	prodDb := products.NewProductDbService(tx)
	p, err := prodDb.Create(ctx, *key, products.ProductFields{
		Name: *productName, BaseURL: *baseURL, InitiateLoginURI: *initiate, IsActive: true,
	})
	if err != nil {
		return fmt.Errorf("register the product: %w", err)
	}
	if _, err := prodDb.SetRoles(ctx, p.ID, roleList); err != nil {
		return fmt.Errorf("set the product's roles: %w", err)
	}
	if _, err := prodDb.SetRedirectURIs(ctx, p.ID, []string{*redirect}); err != nil {
		return fmt.Errorf("set the product's redirect URI: %w", err)
	}
	if _, err := prodDb.SetClientSecret(ctx, p.ID, tokens.HashToken(secret)); err != nil {
		return fmt.Errorf("set the product's secret: %w", err)
	}
	if _, err := clientproducts.NewClientProductDbService(tx).Upsert(ctx, co.ID, p.ID, true, nil, nil); err != nil {
		return fmt.Errorf("subscribe the company: %w", err)
	}
	adminsID, err := groups.NewGroupDbService(tx).SystemGroupID(ctx, co.ID, dbmodels.SystemGroupAdmins)
	if err != nil {
		return err
	}
	if _, err := groups.NewGroupDbService(tx).SetProductGrants(ctx, adminsID, co.ID,
		[]groups.ProductGrant{{ProductID: p.ID, RoleName: roleList[0]}}, ""); err != nil {
		return fmt.Errorf("grant the Admins group the product: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Println("Demo provisioned.")
	fmt.Printf("  company        %s  (%s)\n", co.Name, co.ID)
	fmt.Printf("  admin          %s  (%s)\n", a.Email, a.ID)
	fmt.Printf("  product        %s  key %s\n", p.ID, p.Key)
	fmt.Printf("  client_id      %s\n", p.ID)
	fmt.Printf("  client_secret  %s\n", secret)
	fmt.Println("The client secret is shown this once and stored only as a hash.")
	return nil
}

func normalise(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// readHash reads a password and hashes it here, so the credential is created
// with exactly the argon2 parameters the API verifies against.
func readHash(who string) (string, error) {
	pw, err := readPassword(who)
	if err != nil {
		return "", err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return hash, nil
}

// minPassword is the shortest password bootstrap accepts. The accounts it
// creates are an Owner and Admins — the first accounts in the system should not
// be its weakest, however the password arrives.
const minPassword = 12

// readPassword takes the password from the terminal without echoing it, or from
// BOOTSTRAP_PASSWORD when there is no terminal (CI, containers).
func readPassword(who string) (string, error) {
	pw, err := promptPassword(who)
	if err != nil {
		return "", err
	}
	if len(pw) < minPassword {
		return "", fmt.Errorf("password must be at least %d characters", minPassword)
	}
	return pw, nil
}

func promptPassword(who string) (string, error) {
	if pw := os.Getenv("BOOTSTRAP_PASSWORD"); pw != "" {
		return pw, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal available; set BOOTSTRAP_PASSWORD instead")
	}
	fmt.Printf("%s password: ", who)
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
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}
