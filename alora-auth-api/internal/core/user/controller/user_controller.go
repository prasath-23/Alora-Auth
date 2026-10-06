// Package controller serves company user administration, direct product grants,
// and the caller's own account and apps.
package controller

import (
	"net/http"
	"strconv"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/user/models"
	"github.com/alora/auth/internal/core/user/service"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// UserController serves the user list, detail and activation. It is wired twice:
// on /api/admin for a company's own Admins, and on the Owner console for any
// company.
type UserController struct {
	svc   service.UserService
	scope shared.ScopeResolver
}

// NewUserController builds the controller for the routes scope resolves.
func NewUserController(svc service.UserService, scope shared.ScopeResolver) *UserController {
	return &UserController{svc: svc, scope: scope}
}

// List handles GET /api/admin/users.
//
//	@Summary		List users
//	@Description	One keyset page of the company's users, with their groups and whether each is an Admin or an Owner.
//	@Description
//	@Description	Pass the `nextCursor` of a response as `cursor` to fetch the following page; a null `nextCursor` means there is no further page. The cursor is an opaque user id — internally a (created_at, id) position, stable under concurrent inserts in a way OFFSET is not. A cursor from another company simply fails to resolve.
//	@Tags			users
//	@Security		BearerAuth
//	@Produce		json
//	@Param			cursor	query		string	false	"nextCursor from the previous page"
//	@Param			take	query		int		false	"Page size, 1-100"	default(25)	minimum(1)	maximum(100)
//	@Param			search	query		string	false	"A literal, case-insensitive part of the address"
//	@Success		200		{object}	models.UserListResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"take out of range, or a cursor that does not resolve in this company"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks users:read"
//	@Router			/api/admin/users [get]
func (h *UserController) List(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	take := 25
	if v := c.Query("take"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			exceptions.FailWith(c, http.StatusBadRequest, "Invalid request")
			return
		}
		take = n
	}
	page, err := h.svc.List(c.Request.Context(), scope, models.ListQuery{
		Take: take, Cursor: c.Query("cursor"), Search: c.Query("search"),
	})
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewUserListResponse(page))
}

// Get handles GET /api/admin/users/:id.
//
//	@Summary		Get a user
//	@Description	One user with everything that decides what they can do: their groups, their direct product grants, their effective access (direct and through groups, each with its source) and the login policy that applies to them, with where it came from.
//	@Description
//	@Description	An unknown id and an id belonging to another organisation are answered identically.
//	@Tags			users
//	@Security		BearerAuth
//	@Produce		json
//	@Param			id	path		string	true	"User id"	example(4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d)
//	@Success		200	{object}	models.UserDetailResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller lacks users:read"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such user in this company"
//	@Router			/api/admin/users/{id} [get]
func (h *UserController) Get(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	user, err := h.svc.Get(c.Request.Context(), scope, userParam(c))
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewUserDetailResponse(user))
}

// Update handles PATCH /api/admin/users/:id (activate / deactivate).
//
//	@Summary		Activate or deactivate a user
//	@Description	The only editable field is `is_active`. Deactivation takes effect at once: every session of the user ends — at App Central and in every product — and App Central's tokens for them stop working on their next request.
//	@Description
//	@Description	Needs `users:edit`. Nobody may modify their own account here; nobody may act on someone with more access than they have (the Owner excepted); and the company's last active Admin cannot be deactivated.
//	@Tags			users
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string						true	"User id"	example(4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d)
//	@Param			request	body		models.UpdateUserRequest	true	"New active state"
//	@Success		200		{object}	models.UpdateUserResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body, or the target is the caller"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks users:edit, or the target has more access than the caller"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such user in this company"
//	@Failure		409		{object}	exceptions.ErrorResponse	"The target is the last active Admin"
//	@Router			/api/admin/users/{id} [patch]
func (h *UserController) Update(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	userID := userParam(c)
	// The self-lockout guard answers before the body is even read.
	if err := h.svc.CheckModifiable(scope, userID); err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.UpdateUserRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	state, err := h.svc.SetActive(c.Request.Context(), scope, userID, *req.IsActive)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewUpdateUserResponse(state))
}

// SetScopes handles PUT /api/admin/users/:id/scopes.
//
//	@Summary		Set a person's extra scopes
//	@Description	The COMPLETE set of App Central scopes given to this person alone, on top of what their groups give: any scope omitted is taken away. An edit scope brings its read scope.
//	@Description
//	@Description	Needs `users:edit`, and the two scope rules apply: you can only give or take away scopes you hold yourself, and only for someone with no more access than you (the Owner is bound by neither). Nobody changes their own extras. The person's next request sees the change; their login token says so with `X-Alora-Token-Stale`.
//	@Tags			users
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"User id"	example(4b5c6d7e-8f90-1a2b-3c4d-5e6f7a8b9c0d)
//	@Param			request	body		models.SetUserScopesRequest	true	"The complete set of extra scopes"
//	@Success		200		{object}	models.UserScopesResponse
//	@Failure		400		{object}	exceptions.ErrorResponse	"Malformed body, an unknown scope, or the target is the caller"
//	@Failure		401		{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403		{object}	exceptions.ErrorResponse	"Caller lacks users:edit, lacks a scope they tried to give or take, or the target has more access"
//	@Failure		404		{object}	exceptions.ErrorResponse	"No such user in this company"
//	@Router			/api/admin/users/{id}/scopes [put]
func (h *UserController) SetScopes(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.SetUserScopesRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	scopes, err := h.svc.SetExtraScopes(c.Request.Context(), scope, userParam(c), req.Scopes)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewUserScopesResponse(scopes))
}

// userParam is the user id from the path: :id on the admin routes, :uid under
// the Owner console's company.
func userParam(c *gin.Context) string {
	if id := c.Param("uid"); id != "" {
		return id
	}
	return c.Param("id")
}
