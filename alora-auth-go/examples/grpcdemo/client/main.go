// Command client is an application calling the demo product's gRPC API with
// client credentials. The Go helper gets its token from App Central's
// TokenService — with the API client's id and secret — keeps it, renews it,
// and puts it on every call to the product.
//
//	ALORA_CLIENT_SECRET=acc_… go run ./examples/grpcdemo/client \
//	    -central central.example.com:443 -client-id aci_… -product INVENTORY \
//	    -addr inventory.example.com:443 list
//	… add "Forklift"
//
// It prints the answer as JSON; a refusal prints its gRPC code and reason and
// exits 1.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/aloraauth"
	"github.com/prasath-23/Alora-Auth/alora-auth-go/examples/grpcdemo/inventorypb"
)

func main() {
	central := flag.String("central", "", "App Central's gRPC address, host:port (required)")
	clientID := flag.String("client-id", "", "the API client's id, aci_… (required; the secret comes from ALORA_CLIENT_SECRET)")
	product := flag.String("product", "", "the product's key (required)")
	addr := flag.String("addr", "", "the product's gRPC address, host:port (required)")
	scopes := flag.String("scopes", "", "scopes to ask for, space-separated (default: all the API client holds)")
	plaintext := flag.Bool("insecure", false, "plaintext to App Central and to the product: development only")
	flag.Parse()
	secret := os.Getenv("ALORA_CLIENT_SECRET")
	if *central == "" || *clientID == "" || *product == "" || *addr == "" || secret == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: client -central host:port -client-id aci_… -product KEY -addr host:port [-scopes \"…\"] [-insecure] list | add NAME")
		os.Exit(2)
	}

	creds, err := aloraauth.ClientCredentials(aloraauth.Config{
		TokenAddress: *central, ClientID: *clientID, ClientSecret: secret, Product: *product,
		Scopes: strings.Fields(*scopes), Insecure: *plaintext,
	})
	if err != nil {
		fail(err)
	}
	defer creds.Close()
	transport := credentials.NewTLS(nil)
	if *plaintext {
		transport = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(transport), grpc.WithPerRPCCredentials(creds))
	if err != nil {
		fail(err)
	}
	defer conn.Close()
	inv := inventorypb.NewInventoryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch flag.Arg(0) {
	case "list":
		res, err := inv.ListItems(ctx, &inventorypb.ListItemsRequest{})
		if err != nil {
			fail(err)
		}
		items := []map[string]any{}
		for _, it := range res.GetItems() {
			items = append(items, map[string]any{"id": it.GetId(), "name": it.GetName()})
		}
		emit(map[string]any{"caller": res.GetCaller(), "items": items})
	case "add":
		res, err := inv.AddItem(ctx, &inventorypb.AddItemRequest{Name: strings.Join(flag.Args()[1:], " ")})
		if err != nil {
			fail(err)
		}
		emit(map[string]any{"item": map[string]any{"id": res.GetItem().GetId(), "name": res.GetItem().GetName()}})
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", flag.Arg(0))
		os.Exit(2)
	}
}

// emit prints v as one line of JSON.
func emit(v any) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

// fail prints a refusal — its gRPC code, the reason App Central or the product
// gave, its message — and exits 1.
func fail(err error) {
	out := map[string]any{"code": status.Code(err).String(), "message": err.Error()}
	if st, ok := status.FromError(err); ok {
		out["message"] = st.Message()
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok {
				out["reason"] = info.GetReason()
			}
		}
	}
	emit(out)
	os.Exit(1)
}
