// Package controller serves login-policy administration. It is wired onto the
// Owner console only: how a company's people sign in is the Owner's decision.
package controller

import (
	"context"
	"net/http"

	"github.com/alora/auth/internal/core/policy/models"
	"github.com/alora/auth/internal/core/policy/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// PolicyController serves /api/owner/companies/:cid/login-policies and the
// user and group assignments.
type PolicyController struct {
	svc   service.PolicyService
	scope shared.ScopeResolver
}

// NewPolicyController builds the controller for the routes scope resolves.
func NewPolicyController(svc service.PolicyService, scope shared.ScopeResolver) *PolicyController {
	return &PolicyController{svc: svc, scope: scope}
}

// List handles GET /api/owner/companies/:cid/login-policies.
//
//	@Summary		List a company's login policies
//	@Description	Highest priority first. Exactly one is the company default, which applies to everyone with no policy of their own and no group policy.
//	@Tags			owner
//	@Security		BearerAuth
//	@Produce		json
//	@Param			cid	path		string	true	"Company id"
//	@Success		200	{array}		models.PolicyResponse
//	@Failure		401	{object}	exceptions.ErrorResponse	"Missing, invalid or stale token"
//	@Failure		403	{object}	exceptions.ErrorResponse	"Caller is not an Owner, or signed in too long ago"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such company"
//	@Router			/api/owner/companies/{cid}/login-policies [get]
func (h *PolicyController) List(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	ps, err := h.svc.List(c.Request.Context(), scope)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewPolicyListResponse(ps))
}

// Create handles POST /api/owner/companies/:cid/login-policies.
//
//	@Summary		Create a login policy
//	@Description	A policy allows any of password, Google and one of the company's SSO connections, and must allow at least one. Priorities are unique within a company; when a user's groups carry several policies, the highest priority wins.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			cid						path		string					true	"Company id"
//	@Param			X-Alora-Target-Company	header		string					true	"Must repeat the company id"
//	@Param			request					body		models.PolicyRequest	true	"The policy"
//	@Success		201						{object}	models.PolicyResponse
//	@Failure		400						{object}	exceptions.ErrorResponse	"Malformed body, no method allowed, or an SSO connection of another company"
//	@Failure		403						{object}	exceptions.ErrorResponse	"Caller is not an Owner, signed in too long ago, or the target header does not match"
//	@Failure		409						{object}	exceptions.ErrorResponse	"A policy with this name or priority already exists"
//	@Router			/api/owner/companies/{cid}/login-policies [post]
func (h *PolicyController) Create(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.PolicyRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	p, err := h.svc.Create(c.Request.Context(), scope, req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.NewPolicyResponse(p))
}

// Update handles PATCH /api/owner/companies/:cid/login-policies/:pid.
//
//	@Summary		Update a login policy
//	@Description	The body is the complete desired state. A session signed in with a method the policy no longer allows ends at its next refresh.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Produce		json
//	@Param			cid						path		string					true	"Company id"
//	@Param			pid						path		string					true	"Policy id"
//	@Param			X-Alora-Target-Company	header		string					true	"Must repeat the company id"
//	@Param			request					body		models.PolicyRequest	true	"The policy"
//	@Success		200						{object}	models.PolicyResponse
//	@Failure		400						{object}	exceptions.ErrorResponse	"Malformed body, no method allowed, or an SSO connection of another company"
//	@Failure		404						{object}	exceptions.ErrorResponse	"No such policy in this company"
//	@Failure		409						{object}	exceptions.ErrorResponse	"A policy with this name or priority already exists"
//	@Router			/api/owner/companies/{cid}/login-policies/{pid} [patch]
func (h *PolicyController) Update(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.PolicyRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	p, err := h.svc.Update(c.Request.Context(), scope, c.Param("pid"), req.Input())
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, models.NewPolicyResponse(p))
}

// Delete handles DELETE /api/owner/companies/:cid/login-policies/:pid.
//
//	@Summary		Delete a login policy
//	@Description	Neither the default policy nor one still assigned to a user or group can be deleted.
//	@Tags			owner
//	@Security		BearerAuth
//	@Param			cid						path	string	true	"Company id"
//	@Param			pid						path	string	true	"Policy id"
//	@Param			X-Alora-Target-Company	header	string	true	"Must repeat the company id"
//	@Success		204								"Deleted"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such policy in this company"
//	@Failure		409	{object}	exceptions.ErrorResponse	"The policy is the default or still assigned"
//	@Router			/api/owner/companies/{cid}/login-policies/{pid} [delete]
func (h *PolicyController) Delete(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.Delete(c.Request.Context(), scope, c.Param("pid")); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// SetDefault handles PUT /api/owner/companies/:cid/login-policies/:pid/default.
//
//	@Summary		Make a policy the company default
//	@Tags			owner
//	@Security		BearerAuth
//	@Param			cid						path	string	true	"Company id"
//	@Param			pid						path	string	true	"Policy id"
//	@Param			X-Alora-Target-Company	header	string	true	"Must repeat the company id"
//	@Success		204								"Now the default"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such policy in this company"
//	@Router			/api/owner/companies/{cid}/login-policies/{pid}/default [put]
func (h *PolicyController) SetDefault(c *gin.Context) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := h.svc.SetDefault(c.Request.Context(), scope, c.Param("pid")); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// AssignUser handles PUT /api/owner/companies/:cid/users/:uid/login-policy.
//
//	@Summary		Set a user's own login policy
//	@Description	A user's own policy overrides their groups' and the default. A null policy_id removes it.
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Param			cid						path	string						true	"Company id"
//	@Param			uid						path	string						true	"User id"
//	@Param			X-Alora-Target-Company	header	string						true	"Must repeat the company id"
//	@Param			request					body	models.AssignPolicyRequest	true	"The policy, or null"
//	@Success		204										"Assigned"
//	@Failure		400	{object}	exceptions.ErrorResponse	"No such policy in this company"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such user in this company"
//	@Router			/api/owner/companies/{cid}/users/{uid}/login-policy [put]
func (h *PolicyController) AssignUser(c *gin.Context) {
	h.assign(c, h.svc.AssignUser, c.Param("uid"))
}

// AssignGroup handles PUT /api/owner/companies/:cid/groups/:gid/login-policy.
//
//	@Summary		Set the login policy a group's members sign in under
//	@Tags			owner
//	@Security		BearerAuth
//	@Accept			json
//	@Param			cid						path	string						true	"Company id"
//	@Param			gid						path	string						true	"Group id"
//	@Param			X-Alora-Target-Company	header	string						true	"Must repeat the company id"
//	@Param			request					body	models.AssignPolicyRequest	true	"The policy, or null"
//	@Success		204										"Assigned"
//	@Failure		400	{object}	exceptions.ErrorResponse	"No such policy in this company"
//	@Failure		404	{object}	exceptions.ErrorResponse	"No such group in this company"
//	@Router			/api/owner/companies/{cid}/groups/{gid}/login-policy [put]
func (h *PolicyController) AssignGroup(c *gin.Context) {
	h.assign(c, h.svc.AssignGroup, c.Param("gid"))
}

func (h *PolicyController) assign(c *gin.Context,
	fn func(context.Context, shared.Scope, string, *string) error, id string) {
	scope, err := h.scope(c)
	if err != nil {
		exceptions.Fail(c, err)
		return
	}
	var req models.AssignPolicyRequest
	if err := shared.BindJSON(c, &req); err != nil {
		exceptions.Fail(c, err)
		return
	}
	if err := fn(c.Request.Context(), scope, id, req.PolicyID); err != nil {
		exceptions.Fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
