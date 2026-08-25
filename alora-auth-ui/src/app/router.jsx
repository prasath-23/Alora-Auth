// TODO: UI needs to be finalized — pages, styling, and flows are incomplete
import { createBrowserRouter } from 'react-router-dom'
import Login              from '../pages/auth/Login'
import GoogleCallback     from '../pages/auth/GoogleCallback'
import ResetPassword      from '../pages/auth/ResetPassword'
import AcceptInvitation   from '../pages/auth/AcceptInvitation'
import NotFound        from '../pages/NotFound'
import AuthBootstrap   from '../components/auth/AuthBootstrap'
import ProtectedRoute  from '../components/auth/ProtectedRoute'
import AdminLayout     from '../pages/admin/AdminLayout'
import Dashboard       from '../pages/admin/Dashboard'
import ProfilePage     from '../pages/admin/ProfilePage'
import InvitationsPage from '../pages/admin/InvitationsPage'
import UsersPage       from '../pages/admin/UsersPage'
import UserDetailPage  from '../pages/admin/UserDetailPage'
import GroupsPage      from '../pages/admin/GroupsPage'
import SessionsPage    from '../pages/admin/SessionsPage'
import ProductsPage    from '../pages/admin/ProductsPage'
import ClientPage      from '../pages/admin/ClientPage'

const router = createBrowserRouter([
  // ── Fully public (no auth) ────────────────────────────────────────────────
  { path: '/',                     element: <Login /> },
  { path: '/auth/google/callback', element: <GoogleCallback /> },
  { path: '/reset-password',       element: <ResetPassword /> },
  { path: '/accept-invitation',    element: <AcceptInvitation /> },

  // ── Admin portal ─────────────────────────────────────────────────────────
  // AuthBootstrap does a silent refresh on mount to settle auth state.
  // ProtectedRoute renders the login panel inline when unauthenticated —
  // there is no separate /admin/login page.
  {
    element: <AuthBootstrap />,
    children: [
      {
        element: <ProtectedRoute />,
        children: [
          {
            element: <AdminLayout />,
            children: [
              { path: '/admin',             element: <Dashboard /> },
              { path: '/admin/profile',     element: <ProfilePage /> },
              { path: '/admin/invitations', element: <InvitationsPage /> },
              {
                element: <ProtectedRoute featureKey="users:view" />,
                children: [
                  { path: '/admin/users',     element: <UsersPage /> },
                  { path: '/admin/users/:id', element: <UserDetailPage /> },
                ],
              },
              {
                element: <ProtectedRoute featureKey="groups:view" />,
                children: [{ path: '/admin/groups', element: <GroupsPage /> }],
              },
              {
                element: <ProtectedRoute featureKey="sessions:view" />,
                children: [{ path: '/admin/sessions', element: <SessionsPage /> }],
              },
              {
                element: <ProtectedRoute featureKey="products:view" />,
                children: [{ path: '/admin/products', element: <ProductsPage /> }],
              },
              {
                element: <ProtectedRoute featureKey="client:view" />,
                children: [{ path: '/admin/client', element: <ClientPage /> }],
              },
            ],
          },
        ],
      },
    ],
  },

  { path: '*', element: <NotFound /> },
])

export default router
