// Command server is a demo product's gRPC API: an inventory that applications
// read and change with tokens App Central issued to their API clients. Every
// call's token is checked with the Go helper's Verifier — App Central's keys,
// RS256, the issuer, the audience product:<key>, the expiry — and the
// interceptor lets ListItems through with grpc:read, AddItem with grpc:edit,
// and nothing else.
//
//	go run ./examples/grpcdemo/server -issuer https://central.example.com -product INVENTORY
//
// It listens in plaintext, as a demo may; a real product serves TLS.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/aloraauth"
	"github.com/prasath-23/Alora-Auth/alora-auth-go/examples/grpcdemo/inventorypb"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4200", "where to listen (port 0: any free port)")
	issuer := flag.String("issuer", "", "App Central's issuer, e.g. https://central.example.com (required)")
	product := flag.String("product", "", "this product's key: tokens must be for product:<key> (required)")
	jwks := flag.String("jwks", "", "App Central's key set URL (default: from the issuer's discovery document)")
	flag.Parse()
	if *issuer == "" || *product == "" {
		flag.Usage()
		os.Exit(2)
	}

	v, err := aloraauth.NewVerifier(aloraauth.VerifierConfig{Issuer: *issuer, Product: *product, JWKSURL: *jwks})
	if err != nil {
		log.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(v.UnaryServerInterceptor(aloraauth.Rules{
			inventorypb.InventoryService_ListItems_FullMethodName: "grpc:read",
			inventorypb.InventoryService_AddItem_FullMethodName:   "grpc:edit",
		})),
		// No streaming method is open: every stream is refused.
		grpc.StreamInterceptor(v.StreamServerInterceptor(aloraauth.Rules{})),
	)
	inventorypb.RegisterInventoryServiceServer(srv, &inventory{items: []*inventorypb.Item{
		{Id: 1, Name: "Pallet jack"}, {Id: 2, Name: "Label printer"},
	}, next: 3})

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	// The address, on stdout, is how a harness finds a port chosen for it.
	fmt.Printf("inventory listening on %s (product:%s, issuer %s)\n", lis.Addr(), *product, *issuer)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		srv.GracefulStop()
	}()
	if err := srv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		log.Fatal(err)
	}
}

// inventory is the demo's whole product: a list in memory.
type inventory struct {
	inventorypb.UnimplementedInventoryServiceServer
	mu    sync.Mutex
	items []*inventorypb.Item
	next  int64
}

func (s *inventory) ListItems(ctx context.Context, _ *inventorypb.ListItemsRequest) (*inventorypb.ListItemsResponse, error) {
	claims, _ := aloraauth.ClaimsFrom(ctx) // the interceptor put them there
	s.mu.Lock()
	defer s.mu.Unlock()
	return &inventorypb.ListItemsResponse{Items: append([]*inventorypb.Item(nil), s.items...), Caller: claims.Subject}, nil
}

func (s *inventory) AddItem(ctx context.Context, req *inventorypb.AddItemRequest) (*inventorypb.AddItemResponse, error) {
	name := strings.TrimSpace(req.GetName())
	if name == "" || len(name) > 100 {
		return nil, status.Error(codes.InvalidArgument, "an item needs a name of at most 100 characters")
	}
	claims, _ := aloraauth.ClaimsFrom(ctx)
	log.Printf("%s (company %s) adds %q", claims.Subject, claims.TenantID, name)
	s.mu.Lock()
	defer s.mu.Unlock()
	item := &inventorypb.Item{Id: s.next, Name: name}
	s.next++
	s.items = append(s.items, item)
	return &inventorypb.AddItemResponse{Item: item}, nil
}
