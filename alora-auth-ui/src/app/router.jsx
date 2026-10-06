import { createBrowserRouter } from 'react-router-dom'
import AuthBootstrap from '../components/auth/AuthBootstrap'
import RequireAuth from '../components/auth/RequireAuth'
import Guard from '../components/auth/Guard'
import AppShell from '../components/layout/AppShell'
import Login from '../pages/auth/Login'
import AcceptInvitation from '../pages/auth/AcceptInvitation'
import ResetPassword from '../pages/auth/ResetPassword'
import Launcher from '../pages/apps/Launcher'
import ProfilePage from '../pages/profile/ProfilePage'
import AdminLayout, { AdminHome } from '../pages/admin/AdminLayout'
import UsersPage, { UserDetailPage } from '../pages/admin/UsersPage'
import GroupsPage, { GroupDetailPage } from '../pages/admin/GroupsPage'
import ManagedGroupsPage, { ManagedGroupPage } from '../pages/admin/ManagedGroupsPage'
import InvitationsPage from '../pages/admin/InvitationsPage'
import SessionsPage from '../pages/admin/SessionsPage'
import ProductsPage from '../pages/admin/ProductsPage'
import CompanyPage from '../pages/admin/CompanyPage'
import APIClientsPage, { APIClientDetailPage } from '../pages/admin/APIClientsPage'
import OwnerLayout from '../pages/owner/OwnerLayout'
import CompaniesPage from '../pages/owner/CompaniesPage'
import CompanyLayout from '../pages/owner/CompanyLayout'
import CompanyOverview from '../pages/owner/CompanyOverview'
import CompanySubscriptions from '../pages/owner/CompanySubscriptions'
import { CompanyGroup, CompanyGroups, CompanyInvitations, CompanyUser, CompanyUsers } from '../pages/owner/CompanyPeople'
import CompanyPolicies from '../pages/owner/CompanyPolicies'
import CompanySSO from '../pages/owner/CompanySSO'
import CompanyAPIClients, { CompanyAPIClient } from '../pages/owner/CompanyAPIClients'
import CredentialsPage from '../pages/owner/CredentialsPage'
import OwnerProductsPage from '../pages/owner/ProductsPage'
import OwnerProductPage from '../pages/owner/ProductPage'
import NotFound from '../pages/NotFound'

// App Central's pages. The API lives on the same origin under /api, /auth,
// /oauth and /.well-known, so no page here may use those prefixes.
//
// The API sends browsers to three of these routes, and its tests hold it to
// that: '/login' (sign-in, and the return leg of Google and SSO),
// '/accept-invitation' (the invite link) and '/reset-password' (the reset link).
const router = createBrowserRouter([
  {
    element: <AuthBootstrap />,
    children: [
      { path: '/login',             element: <Login /> },
      { path: '/accept-invitation', element: <AcceptInvitation /> },
      { path: '/reset-password',    element: <ResetPassword /> },
      {
        element: <RequireAuth />,
        children: [
          {
            element: <AppShell />,
            children: [
              { path: '/',        element: <Launcher /> },
              { path: '/profile', element: <ProfilePage /> },
              {
                path: '/admin',
                element: <AdminLayout />,
                children: [
                  { index: true,                element: <AdminHome /> },
                  { path: 'users',              element: <Guard scope="users:read"><UsersPage /></Guard> },
                  { path: 'users/:id',          element: <Guard scope="users:read"><UserDetailPage /></Guard> },
                  { path: 'groups',             element: <Guard scope="groups:read"><GroupsPage /></Guard> },
                  { path: 'groups/:id',         element: <Guard scope="groups:read"><GroupDetailPage /></Guard> },
                  { path: 'my-groups',          element: <Guard manager><ManagedGroupsPage /></Guard> },
                  { path: 'my-groups/:id',      element: <Guard manager><ManagedGroupPage /></Guard> },
                  { path: 'invitations',        element: <Guard scope="invitations:read"><InvitationsPage /></Guard> },
                  { path: 'sessions',           element: <Guard scope="sessions:read"><SessionsPage /></Guard> },
                  { path: 'products',           element: <Guard scope="products:read"><ProductsPage /></Guard> },
                  { path: 'company',            element: <Guard scope="company:read"><CompanyPage /></Guard> },
                  { path: 'api-clients',        element: <Guard scope="api-clients:read"><APIClientsPage /></Guard> },
                  { path: 'api-clients/:id',    element: <Guard scope="api-clients:read"><APIClientDetailPage /></Guard> },
                ],
              },
              {
                path: '/owner',
                element: <Guard owner><OwnerLayout /></Guard>,
                children: [
                  { index: true,           element: <CompaniesPage /> },
                  {
                    path: 'companies/:cid',
                    element: <CompanyLayout />,
                    children: [
                      { index: true,          element: <CompanyOverview /> },
                      { path: 'subscriptions', element: <CompanySubscriptions /> },
                      { path: 'users',         element: <CompanyUsers /> },
                      { path: 'users/:uid',    element: <CompanyUser /> },
                      { path: 'groups',        element: <CompanyGroups /> },
                      { path: 'groups/:gid',   element: <CompanyGroup /> },
                      { path: 'invitations',   element: <CompanyInvitations /> },
                      { path: 'policies',      element: <CompanyPolicies /> },
                      { path: 'sso',           element: <CompanySSO /> },
                      { path: 'api-clients',   element: <CompanyAPIClients /> },
                      { path: 'api-clients/:aid', element: <CompanyAPIClient /> },
                    ],
                  },
                  { path: 'products',      element: <OwnerProductsPage /> },
                  { path: 'products/:pid', element: <OwnerProductPage /> },
                  { path: 'credentials',   element: <CredentialsPage /> },
                ],
              },
            ],
          },
        ],
      },
      { path: '*', element: <NotFound /> },
    ],
  },
])

export default router
