package service

import (
	"context"
	"errors"
	"net/http"

	auditservice "github.com/alora/auth/internal/core/audit/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/user/models"
	"github.com/alora/auth/internal/database/contexts"
	"github.com/alora/auth/internal/database/services/clientproducts"
	"github.com/alora/auth/internal/database/services/productpermissions"
	usercustoms "github.com/alora/auth/internal/database/services/users/customs"
	"github.com/alora/auth/internal/exceptions"
)

// PermissionService administers product roles granted to a user DIRECTLY. Most
// access comes through groups; a direct grant is the exception, and the Owner's.
//
// A role change does not reach tokens already issued, so every change bumps
// permissions_version: product introspection then reports the old token
// inactive, and the product's next refresh carries the new roles.
type PermissionService interface {
	// Grant creates or replaces a user's direct role in one product.
	Grant(ctx context.Context, scope shared.Scope, userID, productID, roleName string) (models.Grant, error)
	// Revoke removes a user's direct role in one product.
	Revoke(ctx context.Context, scope shared.Scope, userID, productID string) error
}

type permissionService struct {
	db    *contexts.DbContext
	audit auditservice.AuditService
}

// NewPermissionService builds the permission service.
func NewPermissionService(db *contexts.DbContext, audit auditservice.AuditService) PermissionService {
	return &permissionService{db: db, audit: audit}
}

// Grant checks the user, the subscription and the role before anything is
// written: the upsert alone would happily create a grant row for a foreign user
// id, and the database's own foreign keys would then answer with a 500.
func (s *permissionService) Grant(ctx context.Context, scope shared.Scope, userID, productID, roleName string) (models.Grant, error) {
	if _, err := usercustoms.NewUserDbCustoms(s.db).TenantScoped(ctx, userID, scope.ClientID); err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.Grant{}, exceptions.ErrNotFound
		}
		return models.Grant{}, err
	}
	if _, err := clientproducts.NewClientProductDbService(s.db).ActiveSubscriptionID(ctx, scope.ClientID, productID); err != nil {
		if errors.Is(err, exceptions.ErrNoRows) {
			return models.Grant{}, exceptions.NewAPIError(http.StatusConflict, "The company is not subscribed to this product", nil)
		}
		return models.Grant{}, err
	}
	if err := productpermissions.NewProductPermissionDbService(s.db).Upsert(ctx, userID, scope.ClientID, productID, roleName, scope.Actor.UserID); err != nil {
		if exceptions.IsForeignKeyViolation(err) {
			return models.Grant{}, exceptions.NewAPIError(http.StatusBadRequest, "No such role in this product's catalogue", nil)
		}
		return models.Grant{}, err
	}
	// The procedure bumps the user's permissions_version in the same statement.
	s.audit.Record(scope, "permission.granted")
	return models.Grant{ProductID: productID, RoleName: roleName}, nil
}

func (s *permissionService) Revoke(ctx context.Context, scope shared.Scope, userID, productID string) error {
	n, err := productpermissions.NewProductPermissionDbService(s.db).Delete(ctx, userID, scope.ClientID, productID)
	if err != nil {
		return err
	}
	if n == 0 {
		return exceptions.ErrNotFound
	}
	s.audit.Record(scope, "permission.revoked")
	return nil
}
