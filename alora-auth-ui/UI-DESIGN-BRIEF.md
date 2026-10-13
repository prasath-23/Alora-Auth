# Alora App Central — UI Design Brief

> **Who this is for:** a designer, or a design AI, producing a new UI for Alora
> App Central.
>
> **The one hard constraint:** the backend API stays exactly as it is. Every
> page, field and action below is backed by an endpoint that exists today. The
> layout, navigation, visual style, page grouping and routes are yours to
> redesign; §4 lists the few things that cannot change.
>
> **Sources:** the current SPA (`alora-auth-ui/src`), the API contract
> ([`SPEC.md`](../SPEC.md)) and the OpenAPI document
> (`alora-auth-api/docs/swagger.json`). If this brief and the API ever disagree,
> the API wins.

---

## Contents

1. [The product in one page](#1-the-product-in-one-page)
2. [Who uses it](#2-who-uses-it)
3. [Design goals and key aspects](#3-design-goals-and-key-aspects)
4. [What is fixed and what is free](#4-what-is-fixed-and-what-is-free)
5. [Information architecture and navigation](#5-information-architecture-and-navigation)
6. [Behaviour on every page](#6-behaviour-on-every-page)
7. [Pages](#7-pages)
8. [Shared components and patterns](#8-shared-components-and-patterns)
9. [Key user journeys](#9-key-user-journeys)
10. [Words, labels and messages](#10-words-labels-and-messages)
11. [Data reference](#11-data-reference)
12. [Opportunities and non-goals](#12-opportunities-and-non-goals)
13. [Appendix: endpoint map](#13-appendix-endpoint-map)
14. [What to deliver](#14-what-to-deliver)

---

## 1. The product in one page

**Alora App Central is where people sign in to all of Alora's business apps.**
Think of it as a company's front door and control room.

- **One sign-in for every app.** A person signs in once, with a password,
  Google, or their company's single sign-on (SSO). They then see a launcher of
  the apps ("products") they may open. Opening an app takes them straight in,
  with no second login screen.
- **Company administration.** Each customer company manages its own people:
  - users and invitations;
  - groups, and what each group lets its members do;
  - live sessions;
  - API clients (credentials for software, not people).
- **The platform Owner's console.** Alora's own operators ("Owners") sit above
  every company. They:
  - create companies;
  - decide which apps a company subscribes to and which groups open them;
  - configure how each company signs in (login policies, SSO);
  - register the apps themselves.
- **No self sign-up.** Owners create companies. People join a company only by
  invitation.

Words used throughout: an **app** and a **product** are the same thing (the API
says *product*). A **company** is a customer tenant; the API sometimes calls it
a *client*, as in `/api/admin/client` and `client_id`, and the UI must never
show that word for a company.

---

## 2. Who uses it

A person can be several of these at once. The UI decides what to show from
`GET /api/me` (§6.1).

| Role | Who they are | What they see |
|---|---|---|
| **Signed-out visitor** | Anyone at the sign-in page, a new invitee, or someone with a reset link | The sign-in flow, invitation acceptance, password reset |
| **Member** | Everyone signed in | **My apps** (launcher) and **Profile** |
| **Group manager** | A member who runs one or more groups | Also **Groups you manage**: they add and remove members of those groups, and nothing else |
| **Partial admin** | A member whose groups give *some* admin access, e.g. only "Users: Read" | Only the admin sections they hold access to, read-only or editable per section |
| **Company Admin** | A member of the company's built-in **Admins** group | The whole **Admin** area for their company |
| **Platform Owner** | An Alora operator | Also the **Owner console**: every company, every product, every credential |

Admin access is not all-or-nothing. It is granted per **feature**, each at
**None / Read / Edit** (§11.1). A designer must assume every combination is
possible: someone may see Users but not Groups, or see Sessions without being
allowed to revoke them.

---

## 3. Design goals and key aspects

### 3.1 Goals

1. **Clean and calm.** Most visits are "sign in → click an app". Those two
   screens should feel effortless and fast; everything else can be denser.
2. **Easy to understand.** Access control is the hardest concept here. Use plain
   words ("can see", "can change") and show *where* access comes from (a group,
   or extra access given to one person).
3. **Safe by default.** Many actions are security-sensitive: deactivating a
   person, revoking a secret, suspending a company. Make consequences visible
   before the click, and confirm destructive actions.
4. **Honest about permissions.** Hide what a person cannot see. Show read-only
   views where they can see but not change. When something is visible but not
   allowed, explain why in one line instead of failing silently.
5. **Redesignable.** Build on a small set of reusable patterns (§8), so the
   same components serve the company admin and the Owner. The current code
   already shares one component between both.

### 3.2 Key aspects to get right

- **Three spaces, one shell.** *My apps* (everyone), *Admin* (a company's
  administrators), and the *Owner console* (platform operators). One
  consistent shell, with a clear indicator of which space you are in. The Owner
  console must be visually distinct: Owners act on *other* companies and must
  never confuse that with their own.
- **Permission-aware everything.** Navigation items, page sections, buttons and
  individual choices all depend on the viewer's access.
- **One-time secrets.** Some values are shown exactly once and never again: API
  client secrets and product client secrets. They need a deliberate reveal
  pattern (§8.6).
- **Tables are the backbone of admin.** Users, groups, invitations, sessions,
  products, companies, API clients, policies and SSO connections are all lists.
  Invest in one excellent table pattern that works on a phone.
- **Responsive.**
  - Sign-in, invitation, reset, launcher and profile must be great on a phone.
  - Admin and Owner pages must be fully usable on a tablet and workable on a
    phone; tables become cards or stacked rows.
- **Accessible (WCAG 2.2 AA).** Real labels on every input, visible focus,
  keyboard operation, errors announced to screen readers, and status never
  shown by colour alone (a badge always has text).
- **Light theme required; dark theme welcome.** Define colours as semantic
  tokens (§8.1) so a dark theme is a token swap.

---

## 4. What is fixed and what is free

### 4.1 Fixed: the redesign must keep these

| Fixed thing | Why |
|---|---|
| **The API**: every endpoint, request body and response shape (§13) | The backend is not changing |
| **Three page addresses the API sends browsers to**: `/login`, `/accept-invitation`, `/reset-password` | Emails and server redirects point there |
| **Query parameters on those pages**: `/login?return_to=…`, `/login?choose=1`, `/login?google_error=<code>`, `/login?sso_error=<code>`, `/accept-invitation?token=…`, `/reset-password?token=…` | Written by the API |
| **Reserved path prefixes**: no SPA page may live under `/api`, `/auth`, `/oauth`, `/.well-known`, `/health` or `/docs` | The API owns them on the same origin |
| **The session model**: the access token lives only in page memory; nothing goes in localStorage or cookies; a page load starts with a refresh call | Security (SPEC §2) |
| **No self-service "Forgot password?"** | There is no endpoint for it. Only an administrator issues a reset (§12.2) |
| **Secrets are shown once** | The API returns the value in one response and never again |
| **Anti-enumeration wording on sign-in**: an unknown email and a wrong password both show *"Invalid email or password."* | Security: the page must not reveal whether an account exists |
| **Sign-in method discovery is by email domain** | The page must offer only the methods the API returns for that address |
| **A button whose request is in flight is disabled** | Prevents duplicates, e.g. two secrets or two companies |

### 4.2 Free: change any of these

- The routes of every other page: `/admin/...`, `/owner/...`, `/profile`, `/`.
- The navigation model: top bar, sidebar, space switcher, breadcrumbs, command
  palette.
- Page grouping: merge pages, split them, use tabs, drawers, modals or
  master–detail layouts.
- Visual identity: colour, type, spacing, iconography, illustration, motion.
- What gets a page and what gets a drawer, e.g. user details in a side panel.
- Client-side conveniences built on data the API already returns: filtering,
  sorting, grouping, copy buttons, counts, empty-state guidance.
- New views composed from existing endpoints, e.g. an admin overview with
  counts of pending invitations and live sessions (§12.1).

### 4.3 Not available without backend work

These are listed in §12.2 so the design does not promise them: user names and
avatars, self sign-up, MFA, an audit log viewer, deleting users, a total user
count, product logos and company branding.

---

## 5. Information architecture and navigation

### 5.1 Sitemap (current routes; redesign may rename all but the fixed three)

```
Signed out
├── /login                     Sign in (email → method → [choose company])
├── /accept-invitation         Accept an invitation            (fixed route)
├── /reset-password            Choose a new password           (fixed route)
└── *                          Not found

Signed in — shell with navigation
├── /                          My apps (launcher)
├── /profile                   Profile: account, access, change password
├── /admin                     → the first section the person may see
│   ├── users                  Users                      needs Users: Read
│   ├── users/:id              User detail                needs Users: Read
│   ├── groups                 Groups                     needs Groups: Read
│   ├── groups/:id             Group detail               needs Groups: Read
│   ├── my-groups              Groups you manage          needs to manage ≥1 group
│   ├── my-groups/:id          Managed group detail       needs to manage it
│   ├── invitations            Invitations                needs Invitations: Read
│   ├── sessions               Sessions                   needs Sessions: Read
│   ├── products               Products (subscriptions)   needs Products: Read
│   ├── company                Company                    needs Company: Read
│   ├── api-clients            API clients                needs API clients: Read
│   └── api-clients/:id        API client detail          needs API clients: Read
└── /owner                     Owner console              Owners only
    ├── (index)                Companies
    ├── companies/:cid         Company workspace (tabs)
    │   ├── (index)            Overview: settings and domain
    │   ├── subscriptions      Subscriptions
    │   ├── users, users/:uid  Users (Owner powers)
    │   ├── groups, groups/:gid Groups (Owner powers)
    │   ├── invitations        Invitations
    │   ├── policies           Login policies
    │   ├── sso                SSO connections
    │   └── api-clients, api-clients/:aid  API clients
    ├── products               Products (registration)
    ├── products/:pid          Product detail
    └── credentials            Client credentials (every product login and API client)
```

### 5.2 Navigation rules

- **Main navigation:** *Apps* always. *Admin* when the person holds any admin
  read access or manages a group. *Owner* when the person is an Owner.
- **Admin navigation** lists only the sections the person may see, in this
  order: Users, Groups, Groups you manage, Invitations, Sessions, Products,
  Company, API clients. `/admin` opens the first one. If none are visible, show
  the *No access* state.
- **Owner navigation:** Companies · Products · Client credentials. Inside a
  company: Overview · Subscriptions · Users · Groups · Invitations · Login
  policies · SSO · API clients, with a way back to all companies.
- **Identity area**, always visible: the person's email, their company's name,
  links to Profile and Sign out.
- **Access can change mid-session.** An administrator may change someone's
  access while they are signed in, and the app re-reads it (§6.3). Navigation
  must handle items appearing and disappearing without breaking the layout.
  A page the person just lost access to shows the *No access* state.

### 5.3 Suggested shell (one option, not a requirement)

- **Desktop:** a slim top bar holding the logo, a space switcher
  (Apps / Admin / Owner) and the account menu. A left sidebar shows only inside
  Admin and Owner.
- **Owner console:** a persistent coloured band or label ("Owner console —
  acting on *Acme Ltd*") whenever a company is open.
- **Phone:** the top bar collapses to a menu button, the sidebar becomes a
  drawer, and tables become cards.

---

## 6. Behaviour on every page

### 6.1 Who is signed in: `GET /api/me`

Every decision about what to show comes from this object. It decides only what
to *render*; the API checks every request again.

| Field | Meaning | UI use |
|---|---|---|
| `id`, `email` | The person. **There is no display name.** | Show the email; make avatars from initials of the email's local part |
| `company { id, name }` | Their company | Show in the shell |
| `is_admin` | Member of the Admins group | "Admin" badge |
| `is_owner` | Platform Owner | "Owner" badge; Owner console |
| `scopes[]` | Admin access held, e.g. `users:read`, `users:edit` | Show and hide features (§11.1) |
| `scope_sources[] { scope, source: GROUP\|EXTRA, group_id, group_name }` | Where each scope comes from | Profile → "Your access → From" |
| `products[]` | Keys of the apps they may open | Profile |
| `manages[] { id, name }` | Groups they manage | "Groups you manage" |
| `authenticated_at` | When they signed in | Profile |

### 6.2 Session lifecycle

| Situation | What happens | Design need |
|---|---|---|
| Page load | One session refresh, then `/api/me` | A full-page branded loading state, under a second in most cases |
| Not signed in, opening a protected page | Redirect to `/login?return_to=<that page>` | — |
| Session ended elsewhere (signed out in another tab, revoked by an admin, policy changed) | Back to sign-in with a notice | Notice: *"Your session has ended. Sign in again to continue."* |
| Sign out | `POST /auth/central/logout`, then sign-in page | Notice: *"You have signed out."* Signing out also ends every app login opened from this session |
| Password changed (Profile) | Every session of the account ends | Notice: *"Your password was changed and every session was signed out. Sign in with your new password."* |
| Owner signed in more than 12 h ago | Owner actions answer 403 *"Recent sign-in required"* | A warning with a **Sign in again** link that returns to the same page |

### 6.3 Access changed while working

When a response carries the header `X-Alora-Token-Stale: 1`, the app silently
refreshes and reloads `/api/me` (at most once every 10 s). The visible effect
is that navigation and buttons update to the new access. No design is needed
beyond graceful appearance and disappearance.

### 6.4 Errors

Every API error has the shape `{ error: "<message>", reqId: "<id>" }`.

- **4xx:** `error` is a safe, human-readable sentence. Show it as is; the
  messages are listed in §10.3.
- **5xx:** `error` is always `"Internal Server Error"`. Show a friendly message
  ("Something went wrong. Try again.") with the reference id.
- **Always show `reqId`** in small text ("ref 3f2a…") so support can find the
  request.
- **429:** "Too many attempts. Wait a minute, then try again."
- **Network failure:** "App Central could not be reached. Check your connection
  and try again."
- **Placement:** inline, at the top of the card or form the action belongs to.
  The current UI uses dismissible alert banners; toasts are fine for successes,
  but errors should stay until dismissed.

### 6.5 Loading and in-flight states

- Lists show a loading state the first time. On reload they keep the old data
  visible while refreshing.
- A pressed button shows a spinner and is **disabled** until its request
  finishes (fixed rule, §4.1).
- An answer that arrives after the person moved on is dropped. For example,
  after typing a new search, a late page from the old search is ignored. The
  design needs nothing for this beyond not mixing results.

---

## 7. Pages

Each page uses the same sections:

- **Purpose**: why the page exists.
- **Who**: who may see it.
- **Shows**: the data on it.
- **Actions**: what can be done, and the endpoint behind each.
- **States**: loading, empty, error, read-only and success.
- **Rules**: behaviour the design must respect.
- **Ideas**: optional improvements the API already supports.

### 7.1 Signed-out pages

All use a simple centred card layout: brand mark, title, short subtitle, content.

#### 7.1.1 Sign in: `/login` (fixed route)

**Purpose.** Identifier-first sign-in. The email comes first; its *domain*
decides which methods to offer.

**Steps**

1. **Email.** One field, "Email", and a **Continue** button.
   Calls `POST /auth/login/discover { email }`, which returns
   `{ password: bool, google: bool, sso: { connection_id } | null }`.
2. **Method.** Shows the email with a **Change** link (back to step 1), then
   whichever of these the response allows:
   - **Password** field and **Sign in** button →
     `POST /auth/login/password { email, password, return_to? }`.
   - **Continue with single sign-on** → browser navigation to
     `/auth/sso/start?connection_id=…&return_to=…`.
   - **Continue with Google**, with the Google mark → browser navigation to
     `/auth/google/start?return_to=…`.
   - Separate password from the federated buttons with an "or" divider. If
     there is no password, the first federated button becomes primary.
   - If nothing is offered: *"No sign-in method is available for this address.
     Contact your administrator."*
3. **Choose a company.** Appears only when the address has accounts in more
   than one company. The sign-in response is then
   `{ status: "choose_company", companies: [{ client_id, name }] }`.
   - Title "Choose a company"; text "Your address has accounts in more than one
     company. Which one do you want?"
   - One large button per company → `POST /auth/login/choose { client_id }`.
   - A "Use another address" link.
   - Coming back from Google or SSO with several companies, the API sends the
     browser to `/login?choose=1`; the page then loads the list from
     `GET /auth/login/choices`.

**After success.** The response carries `access_token` and, optionally,
`return_to`. Go to `return_to` when present. It may be a server path such as
`/oauth/authorize…`, which needs a full browser navigation. Otherwise go to the
launcher.

**States and messages**

- Wrong password **or** unknown email: *"Invalid email or password."*
  (identical, fixed rule). Clear the password field.
- Errors that come back from Google or SSO via `?google_error=` or
  `?sso_error=`: the codes and their texts are in §10.2.
- A notice carried from elsewhere, e.g. "You have signed out.", shows on the
  email step as an info banner.
- Already signed in with nothing to return to: skip the page and go to the
  launcher.

**Rules**

- No "Forgot password?" link (§4.1).
- No sign-up link.
- Email at most 320 characters; password at most 512.

**Design notes.** This is the most-seen screen. Make it calm and trustworthy:
product name "App Central", the tagline *"One sign-in for every Alora app"*,
generous spacing, and autofocus on the field.

#### 7.1.2 Accept invitation: `/accept-invitation?token=…` (fixed route)

**Purpose.** A new person sets up their account from an invitation email.

**Shows.** Loads `GET /auth/accept-invitation/lookup?token=…`, which returns
`{ client_name, email, expires_at, groups[], methods: { password, google, sso } }`.
The page shows "You have been invited to **{client_name}**", their email, and
the groups they will join.

**Actions**, depending on `methods`:

- **Google or SSO:** a "Create my account for Google" (or "…for your company's
  single sign-on") button → `POST /auth/accept-invitation/federated { token }`.
- **Password:** "Password" and "Confirm password" fields, at least 8
  characters, and **Create account** → `POST /auth/accept-invitation { token,
  password }`.
- **Both:** offer both, with "or choose a password" between them.
- **Neither:** a warning, "No sign-in method is available for this invitation.
  Contact your administrator."

**States**

- **Success:** "Your account is ready. Sign in with your new password." (or
  "…with Google using {email}"), then a **Go to sign-in** link.
- **Bad token:** "This invitation is invalid, expired or already used. Ask your
  administrator for a new one."
- **Missing token:** "This invitation link is incomplete."
- **Validation:** "Use at least 8 characters." / "The passwords do not match."

Invitations expire after 7 days. The page does not sign the person in; they
sign in afterwards.

#### 7.1.3 Reset password: `/reset-password?token=…` (fixed route)

**Purpose.** Set a new password from a reset link an administrator issued.

**Actions.** "New password" and "Confirm new password" (at least 8 characters),
then **Update password** → `POST /auth/reset-password { token, new_password }`.

**States**

- **Success:** "Your password was changed and every session was signed out.",
  then "Sign in with your new password →".
- **Missing token:** "This password reset link is incomplete." with a link back
  to sign-in.
- **API error:** show it, e.g. an expired link. Links last 60 minutes.

#### 7.1.4 Not found: `*`

A friendly 404 with "Back to your apps".

### 7.2 Pages for everyone signed in

#### 7.2.1 My apps (launcher): `/`

**Purpose.** The home screen. Every app the person may open, one click away.

**Shows.** `GET /api/me/apps` returns an array of
`{ product_id, key, name, description, roles[], launch_url }`. The header reads
"Your apps", with "Signed in to {company} as {email}".

**Actions.** **Open {app name}** is a normal link to `launch_url`. The app's
backend signs the person in without showing another login page.

**States**

- **Empty:** "You don't have access to any app yet. Ask your administrator."
- **No `launch_url`:** "This app has no launch address yet." (card not
  clickable).
- **Loading:** skeleton cards.

**Design notes**

- A grid of app tiles: name, a short description, and the person's roles in
  that app as small tags.
- There is **no logo or icon field**. Design a monogram tile, e.g. the first
  letters of the name on a colour derived from `key`.
- Consider pinning the most-used apps first; ordering by name is fine too.
- This page should feel like a home, not an admin table.

#### 7.2.2 Profile: `/profile`

**Purpose.** "Who am I here and what can I do?", and changing the password.

**Shows**, all from `/api/me`:

- **Account:** email, company, signed-in time, and role badges (Owner, Admin,
  or "Member").
- **Your access:** the access matrix (§8.3), read-only, with a **From** column
  naming the group(s), or "Extra access". Owners also see "You manage every
  company, whatever the table below says."
- **Apps you can open:** the product keys as tags.
- **Groups you manage**, when any: links to each, plus "You add and remove their
  members; what each gives is set by your company's Admins."
- **In your sign-in token** (technical, collapsible): the raw space-separated
  scope list, with "as it was when you signed in. App Central checks your access
  again on every request."

**Actions.** **Change password**: current, new (at least 8), confirm →
`POST /api/me/change-password { current_password, new_password }`.

- Warn before submitting: "Changing your password signs you out everywhere,
  including every app."
- On success the person is signed out and sent to sign-in with a notice (§6.2).
- **Errors:** 403 "Current password is incorrect"; 429 after 5 attempts in
  15 minutes; "The new passwords do not match."
- An account that signs in only with Google or SSO gets 400 "This account signs
  in without a password". Consider explaining this gently.

**Ideas.** Put the technical token section behind a "Show technical details"
toggle.

#### 7.2.3 No access (state, not a page)

Shown when a page needs access the person lacks: "You don't have access to this
page. Ask your administrator if you think you should.", with "Back to your
apps".

### 7.3 Company admin area: `/admin`

Each section needs its feature's **Read** access to be seen, and its **Edit**
access for its buttons. Read-only viewers see the same page without the action
controls.

The same panels are reused in the Owner console (§7.4), with extra Owner-only
controls switched on. **Design each admin page so it can take extra sections
without restructuring.**

#### 7.3.1 Users: list

**Purpose.** Everyone with an account in the company.

**Shows.** `GET /api/admin/users?search=&cursor=&take=25` returns
`{ users: [...], nextCursor }`. Each user is
`{ id, email, is_active, is_admin, is_owner, account_type, groups: [{ id, name, system_key }], created_at }`.
Columns: Email (with Owner and Admin badges), Groups, Status (Active or
Inactive).

**Actions**

- **Search by email** (server-side, partial match).
- **Load more**: keyset paging with `nextCursor`. There is **no total count**.
  `take` is 1–100.
- Row actions, with **Users: Edit**:
  - **Deactivate / Activate** → `PATCH /api/admin/users/:id { is_active }`.
  - **Reset password**, active users only →
    `POST /api/admin/users/:id/password-reset`, which returns
    `{ expires_at, reset_url? }`.
- Click a row to open the user.

**States**

- **Empty:** "No users found."
- **Reset issued:** "A password reset link was emailed to {email}." Outside
  production, without email set up, the API returns the link itself: show it
  with a copy button.

**Rules**

- Nobody deactivates themselves.
- A person with more access than the viewer cannot be acted on. The API answers
  403 "You can only manage people who have no more access than you." The list
  does not say in advance who that is, so handle the error inline. Consider
  moving these actions to the detail page, where the UI *can* tell in advance.
- The company's last active Admin cannot be deactivated (409).
- A seat limit can block reactivation (409 "Seat limit reached").

#### 7.3.2 User detail

**Purpose.** Everything about one person's access, in one place.

**Shows.** `GET /api/admin/users/:id`:

- **Header:** email; "Account created {date}"; badges: Active or Inactive,
  Owner, Admin, and account type (`EMAIL`, `OAUTH_ONLY` or `HYBRID`; §11.2).
- **Groups:** the groups the person belongs to (the Admins group stands out).
- **App Central access:**
  - a matrix with a read-only **From groups** column, and an editable **Extra**
    column for access given to this person alone (`extra_scopes`);
  - if they are an Admin: "A member of Admins: holds every scope";
  - if they manage groups: "Manages {groups}. They add and remove those groups'
    members — and so count as holding what the groups give."
- **App access:** a table of App, Role and Granted ("Directly" or "Through a
  group"), from `access[]`.
- **Sign-in:** the login policy that applies, where it comes from ("set on the
  user", "from a group" or "company default"), and the methods it allows.

**Actions**, with **Users: Edit**:

- **Reset password.**
- **Deactivate / Activate**: a danger style for deactivate, with confirmation.
- **Save extra access** → `PUT /api/admin/users/:id/scopes { scopes }`, the
  full list.

**Rules**

- The editing controls are hidden or disabled with a reason when:
  - it is the viewer's own account: "Nobody changes their own access.";
  - the person has more access than the viewer: "They have access you don't
    hold, so you can't change theirs.";
  - an individual choice would give or take away access the viewer does not
    hold. That radio is disabled, with the tooltip "You can only give or take
    away access you hold yourself."
- The UI can work all of this out from `/api/me.scopes` and the user's
  `scopes[]`. The rules are in §11.1.

**Owner-only extras** (the same page inside the Owner console):

- **The user's own login policy:** a picker, "None — follow the groups and the
  company default".
- **Direct grants:** a list of App and Role with **Revoke**, and an add row
  (subscribed app, then role) with **Grant**.

#### 7.3.3 Groups: list

**Purpose.** A company's groups: what each lets its members do in App Central,
and which apps it opens.

**Shows.** `GET /api/admin/groups` returns
`[{ id, name, description, system_key, member_count, scopes[], product_grants[{ product_id, product_key, role_name }], login_policy_id }]`.

| Column | Content |
|---|---|
| Group | Name, a "System" badge for Admins, and the description |
| Members | Count |
| Can do in App Central | e.g. "Users (edit), Sessions (read)", or "Everything in App Central" for Admins |
| Opens | e.g. "crm: Sales Rep" |

**Actions.** With **Groups: Edit**: **New group** (name, optional
description) → `POST /api/admin/groups { name, description, scopes: [] }`, then
go to the new group's page to set it up.

**States.** Empty: "No groups yet."

**Ideas.** Client-side search and filter (the full list is loaded). Show the
Admins group pinned first.

#### 7.3.4 Group detail

**Purpose.** One group's members, managers, access, apps and sign-in policy.

**Shows.** `GET /api/admin/groups/:id` returns name, description, `system_key`,
`members[{ user_id, email, assigned_at }]`,
`managers[{ user_id, email, appointed_by_email, appointed_by_owner, appointed_at }]`,
`scopes[]`, `product_grants[]`, `login_policy_id` and `login_policy_name`.

**Sections and actions**

| Section | Content | Action (with **Groups: Edit**) |
|---|---|---|
| **Members (n)** | Email, member since | Add by email → `POST …/members { email }`; Remove → `DELETE …/members/:userId` |
| **Managers (n)** | Email, appointed by (with "(Owner)"), since | Add by email → `POST …/managers { email }`; Remove → `DELETE …/managers/:userId`. Hint: "They will add and remove this group's members without needing Groups: Edit — so they can hand out everything it gives." |
| **Name and description** | Editable fields | Save → `PATCH …/groups/:id { name, description }` |
| **Can do in App Central** | Access matrix (§8.3) | Save access → `PUT …/scopes { scopes }`. If the group has managers: "whatever it gives, they can hand out." |
| **Opens these apps** | App and role list | Read-only for Admins ("Which apps a group opens is your platform Owner's to decide"). Editable in the Owner console |
| **Sign-in** | "Members sign in as the policy **X** allows…", or "Members follow the company's default sign-in policy…" | Read-only for Admins; a policy picker in the Owner console |
| **Delete group** | Danger button | Confirm: "Delete the group "X"? Its members keep their accounts but lose what it grants." → `DELETE …/groups/:id` |

**Rules**

- **The Admins group** (`system_key = ADMINS`):
  - it cannot be renamed, re-scoped or deleted;
  - it has no managers: "The Admins group can't have managers: only Admins
    decide who is an Admin.";
  - its last active member cannot be removed.
- **Changing members, managers or deleting** gives or takes away *all* of the
  group's access. A viewer who does not hold all of it sees "Joining or leaving
  this group gives or takes away all of its access. You can change its members
  once you hold all of that access yourself."
- **A group that opens apps** can be deleted only by an Owner.
- **Nobody makes themselves a manager.**
- **Adding a member can hit a seat limit** (409 "Seat limit reached").

#### 7.3.5 Groups you manage: `/admin/my-groups` and `/admin/my-groups/:id`

**Purpose.** A group manager's own view: add and remove members of the groups
they run, and nothing else.

**Shows.**
- `GET /api/me/managed-groups` returns the same shape as the groups list.
- `GET /api/me/managed-groups/:gid` returns the same shape as group detail.

**Actions**

- Add a member by email → `POST /api/me/managed-groups/:gid/members { email }`.
- Remove a member → `DELETE /api/me/managed-groups/:gid/members/:uid`.

**Rules**

- Show a banner: "You manage this group: you add and remove its members. What it
  gives, the apps it opens, its sign-in policy and its managers are set by your
  company's Admins…"
- Everything else is read-only.
- Managers' own membership rows have **no** remove action. That covers the
  viewer and fellow managers.
- Writes are limited to 60 per 15 minutes.

**Design note.** This is the same detail layout as 7.3.4, with fewer controls.
Design them as one component with permission states.

#### 7.3.6 Invitations

**Purpose.** Invite people into the company, straight into the right groups.

**Shows.** `GET /api/admin/invitations` returns
`[{ id, email, status: PENDING|ACCEPTED|EXPIRED|REVOKED, created_at, expires_at }]`.
Columns: Email, Status, Sent, Expires.

**Actions**, with **Invitations: Edit**:

- **Invite someone:** an Email field plus "Groups to join" checkboxes, from
  `GET /api/admin/groups` → `POST /api/admin/invitations { email, group_ids[] }`,
  which returns `{ id, email, expires_at, invite_url? }`.
  - **Success:** "Invitation created for {email}." Outside production without
    email, show the `invite_url` with a copy button.
  - A group that gives access the inviter lacks is disabled, with "Gives access
    you don't hold yourself".
  - Without **Groups: Read** no groups are offered: "The invitation joins no
    group. Inviting someone straight into groups needs Groups: Read."
- **Revoke**, pending invitations only → `DELETE /api/admin/invitations/:id`.

**States and errors**

- **Empty:** "No invitations yet."
- 409 "An invitation for this email is already pending".
- 409 "A user with this email already exists".

**Ideas**

- A **Resend** action = revoke + create (two calls; no new endpoint).
- Filter tabs by status.
- Show which groups an invitation joins? **Not available**: the list does not
  return groups.

#### 7.3.7 Sessions

**Purpose.** Who is signed in right now, and the ability to end a session.

**Shows.** `GET /api/admin/sessions` returns
`[{ id, email, kind: CENTRAL|PRODUCT, product_key, auth_method: EMAIL|GOOGLE|OIDC, device_label, ip_address, authenticated_at, last_seen_at, created_at }]`.

| Column | Content |
|---|---|
| User | Email |
| Kind | "App Central", or the product key |
| Signed in with | Password, Google or Single sign-on |
| Device | Device label and IP |
| Last used | Date and time |

**Actions.** With **Sessions: Edit**: **Revoke** → `DELETE /api/admin/sessions/:id`.

- Subtitle: "Revoking an App Central session also ends every app login opened
  from it."
- Confirm before revoking.

**States.** Empty: "No live sessions."

**Ideas.** Group the rows by user, with an App Central session and its app
logins nested under it. Filter by user or kind. Show `authenticated_at`.

#### 7.3.8 Products (company view)

**Purpose.** The apps the company subscribes to. Read-only: the Owner decides
subscriptions.

**Shows.** `GET /api/admin/products` returns
`[{ id, product_id, key, name, description, base_url, is_active, seat_limit, starts_at, ends_at }]`.
Columns: Product (name, key, description), Status (Active or Inactive), Seats
(number or "Unlimited"), Ends.

**States.** Empty: "No subscriptions."

#### 7.3.9 Company

**Purpose.** The company's own details.

**Shows.** `GET /api/admin/client` returns name, domain (with a Verified or
Unverified badge), subscription status, seats ("Unlimited" when empty), and the
created date.

**Actions.** With **Company: Edit**: **Rename** →
`PATCH /api/admin/client { name }`. The shell then shows the new name.

#### 7.3.10 API clients: list

**Purpose.** Credentials for *software*: a sync job, a backend or an AI agent
that calls the company's products with no person present.

**Shows.** `GET /api/admin/api-clients` returns
`[{ id, name, description, is_active, products[{ product_id, product_key, product_name, usable }], scopes[], live_secrets, last_used_at }]`.

| Column | Content |
|---|---|
| API client | Name, an "Off" badge when inactive, and the description |
| Products | Keys; struck through when not usable |
| Scope | e.g. `api:read grpc:edit` |
| Secrets | "N live", or "None" (warning) |
| Last used | Date, or "Never" |

**Actions.** With **API clients: Edit**: **New API client** (name, optional
description) → `POST /api/admin/api-clients`, then go to its page. Hint: "It
starts with nothing: choose its products and scope, then make it a secret."

#### 7.3.11 API client detail

**Purpose.** Set up and operate one API client.

**Shows.** `GET /api/admin/api-clients/:id` adds two things to the list item:

- `secrets[{ id, prefix, created_at, expires_at, last_used_at, revoked_at, is_live }]`;
- `product_choices[]`: products that may be added.

**Sections**

1. **Header:** the name, an On or Off badge, and the description. **Delete API
   client** (danger; confirm: "Its secrets stop working at once.") →
   `DELETE …/api-clients/:id`.
2. **Client ID:** `aci_…` in a monospace box with a copy button.
3. **Secrets:**
   - **Table:** Secret (`prefix…`), Made, Expires ("Never" when empty), Last
     used, Status (Live, Revoked or Expired), and **Revoke**, which needs
     confirmation → `DELETE …/secrets/:sid`.
   - **New secret:** an expiry choice (current UI: Never, 30 days, 90 days,
     1 year; the API accepts 1–730 days) → `POST …/secrets { expires_in_days? }`.
     It returns the secret **once**; use the one-time secret reveal (§8.6).
   - **At most two live secrets.** At two: "Two secrets are live, the most there
     can be. Revoke one to make another."
   - **At one:** a hint, "To rotate: make a second secret, deploy it, then revoke
     the first."
   - **None:** "No secret yet: the application cannot sign in."
4. **Products it may get a token for:** checkboxes →
   `PUT …/products { product_ids[] }`.
   - Only products the company subscribes to *and* the Owner has switched to
     accept API clients can be added.
   - A product already on the list that is no longer usable stays, marked
     "earns no token".
   - **Empty:** "No product accepts API clients yet. The Owner switches that on
     for each product."
5. **Scope: where its token may be used** → `PUT …/scopes { scopes[] }`:
   - REST API: None / Read / Read and edit;
   - gRPC: None / Read / Read and edit;
   - MCP tools: Off / On.

   Warnings appear when an edit level is chosen ("Edit lets this application
   change data through …") and when MCP is on ("MCP tools let an AI agent act
   through the product with this credential.").
6. **Try it:** developer snippets showing how the application gets a token:
   a `curl` call to `/oauth/token`, and a `grpcurl` call, with a product picker.
   - Until the client is on, holds a scope, has a live secret and a usable
     product, show what is missing.
   - Use a code block with a copy button.
7. **Details:** name, description, and an **On** switch ("Switched off, it gets
   no token, whatever its secrets.") → `PATCH …/api-clients/:id { name,
   description, is_active }`.

**Design notes**

- This page is a setup checklist: product → scope → secret → try it. Consider a
  progress or "ready" indicator built from the four conditions in *Try it*.
- Read-only viewers see everything except the controls.

### 7.4 Owner console: `/owner`

Owners only. Every write here acts on **another** company, so the console needs
a strong, persistent visual cue (§3.2). The Owner is not bound by the two
access rules (§11.1); every control is enabled.

#### 7.4.1 Companies

**Shows.** `GET /api/owner/companies` returns
`[{ id, name, domain, subscription_status, user_count, is_active, is_platform, max_seats, created_at, … }]`.
Columns: Company (with a "Platform" badge), Domain, Subscription, Users, Status.

`user_count` includes deactivated people; it is not the number seats limit.

**Actions.** **New company** (name, optional domain such as `acme.com`) →
`POST /api/owner/companies`, then open it. A new company starts with its
Admins group and a default login policy.

**Ideas**

- Search and filter (the full list is loaded).
- Set seats, status and active at creation: the API accepts `max_seats`,
  `subscription_status` and `is_active`.

#### 7.4.2 Company workspace: header and tabs

- **Header:** the company name, a "Platform" badge, and "{n} users ·
  {subscription status} · inactive".
- **Back link:** "← All companies".
- **Tabs:** Overview · Subscriptions · Users · Groups · Invitations · Login
  policies · SSO · API clients.

Every write sends the header `X-Alora-Target-Company: <cid>`. This is an
implementation detail, not a design one.

#### 7.4.3 Overview

- **Company settings** → `PATCH /api/owner/companies/:cid`:
  - Name.
  - Subscription: TRIAL, ACTIVE, SUSPENDED or CANCELLED. **Today this is a
    label**; nothing at runtime reads it (see `BACKLOG.md`). Do not design it as
    an on/off switch.
  - Seats: a number, or empty for unlimited (`clear_max_seats`).
  - **Active**: the real switch. "An inactive company signs nobody in, and every
    session in it stops working." Deactivating ends every session at once, and
    reactivating does **not** restore them. Use a strong confirmation.
  - The **platform company** cannot be suspended or deactivated: disable those
    controls and say why.
- **Domain** → `PUT /api/owner/companies/:cid/domain { domain, verified }`:
  - a domain and a "Verified" checkbox;
  - help text: "A verified domain is unique across companies. The sign-in page
    uses it to recognise the company's addresses, and it is what lets the
    company's SSO connections claim addresses at it.";
  - shows the current value with a Verified or Unverified badge.

#### 7.4.4 Subscriptions

**Shows.** Every registered product (`GET /api/owner/products`) joined with
this company's subscriptions (`GET …/subscriptions`, which returns
`[{ product_id, product_key, product_name, is_active, seat_limit, starts_at, ends_at }]`).
Columns: Product (with "Product inactive"), Subscription (Subscribed, Ended or
None), Seats (editable number, empty for unlimited), Since.

**Actions** → `PUT …/subscriptions/:pid { is_active, seat_limit?, ends_at? }`:

- **Subscribe**, when not subscribed.
- **Save** (seats) and **End**, when subscribed. Confirm before ending: people
  lose access to that app.

**Ideas.** An end-date picker (`ends_at` is supported but not exposed today).

#### 7.4.5 Users, groups and invitations (Owner powers)

These are the same pages as §7.3.1–7.3.6, through
`/api/owner/companies/:cid/...`, with every control enabled plus:

- **User detail:**
  - the user's own **login policy** → `PUT …/users/:uid/login-policy { policy_id | null }`;
  - **direct grants**: give a role in a subscribed app →
    `PUT …/users/:uid/grants/:pid { role_name }`; revoke →
    `DELETE …/users/:uid/grants/:pid`.
- **Group detail:**
  - **Opens these apps**: an editable list of app and role, with an add row and
    **Save apps** → `PUT …/groups/:gid/product-grants { product_grants: [{ product_id, role_name }] }`;
  - **login policy for members** → `PUT …/groups/:gid/login-policy { policy_id | null }`,
    with the help text "A user's own policy wins; otherwise the highest-priority
    policy among their groups; otherwise the company default."

The pickers offer the company's **active subscriptions**, each with its
product's role catalogue, and the company's **login policies**.

#### 7.4.6 Login policies

**Purpose.** How the company's people may sign in.

**Shows.** `GET …/login-policies` returns
`[{ id, name, priority, allow_password, allow_google, sso_connection_id, is_default }]`.
Columns: Policy (with a "Default" badge), Priority, Allows (e.g. "Password,
Google, Okta", or "Nothing").

**Actions**

- **New policy** / **Edit** → `POST` / `PATCH …/login-policies[/:pid]` with
  `{ name, priority, allow_password, allow_google, sso_connection_id }`.
  - Form fields: Name; Priority (−1000 to 1000, "higher wins among a user's
    groups"); Password checkbox; Google checkbox; Single sign-on picker
    (None, or one of the company's connections).
- **Make default** → `PUT …/login-policies/:pid/default`.
- **Delete**, not for the default → `DELETE …/login-policies/:pid`.

**Errors to design for**

- 400 "A policy must allow at least one sign-in method".
- 409 "A policy with this name or priority already exists".
- 409 "The default policy cannot be deleted; make another the default first".
- 409 "The policy is still assigned to a user or group".

**Design note.** Tightening a policy ends the sessions it no longer allows.
Say so near the save button.

**Ideas.** A small explainer diagram of the resolution order:
user → highest-priority group → company default.

#### 7.4.7 SSO connections

**Purpose.** The company's OpenID Connect identity providers (Okta, Entra ID,
Google Workspace…).

**Shows.** `GET …/sso-connections` returns
`[{ id, name, issuer, client_id, scopes, domains[], is_active, has_secret, trust_unverified_email }]`.

| Column | Content |
|---|---|
| Connection | Name, with the issuer under it |
| Domains | List |
| Status | Active / Inactive, "No secret" (warning), "Trusts unverified email" (warning) |

**Actions**

- **New connection** / **Edit**. A new connection is saved first
  (`POST …/sso-connections`), then its domains
  (`PUT …/sso-connections/:sid/domains { domains[] }`).
- Form fields:
  - Name;
  - Issuer, e.g. `https://acme.okta.com`: https, no query, no fragment;
  - Client ID;
  - Client secret. Write-only: "leave empty to keep the stored one";
  - Scopes, default `openid email profile`;
  - Domains, one per line, at most 50;
  - Active;
  - Trust unverified email addresses: "Only for a provider that never lets
    users choose their own address." Treat it as a risky option.
- **Test** → `POST …/sso-connections/:sid/test`. Success shows "{name} answered:
  issuer …, keys at …".

**Errors to design for**

- 409 "A domain is already registered on another connection".
- 409 "A domain is another company's verified domain".
- 409 duplicate name or issuer.
- 502 "The provider could not be used" (from Test).

#### 7.4.8 API clients (company)

The same as §7.3.10–7.3.11, through the Owner door, with everything editable.

#### 7.4.9 Products: list and register

**Purpose.** The apps App Central signs people in to. Every product is a
confidential OAuth client with its own backend.

**Shows.** `GET /api/owner/products` returns
`[{ id, key, name, description, base_url, initiate_login_uri, is_active, accepts_api_clients, has_secret, secret_rotated_at, redirect_uris[], roles[] }]`.
Columns: Product (name and key), Roles, Redirect URIs (count), Status (Active
or Inactive, "No secret").

**Actions.** **Register a product** → `POST /api/owner/products`, then open it.

| Field | Rules |
|---|---|
| Key | Required, **permanent**, 2–40 letters, digits, `-` or `_`. Hint: "tokens carry aud product:<key>" |
| Name | Required |
| Base URL | Optional |
| Launch (initiate login) URI | Optional; this is what *Open* in the launcher goes to |
| Description | Optional |

#### 7.4.10 Product detail

**Header.** The name, "Key `crm` · audience `product:crm`", and "← All
products".

**Sections**

1. **Client credentials:**
   - the Client ID with a copy button;
   - the client secret status ("Set {date}" or "Not issued");
   - **Issue secret** / **Rotate secret** → `POST …/client-secret`. Rotating
     needs confirmation: "The current one stops working immediately." The new
     secret is shown **once** (§8.6).
2. **Registration** → `PATCH /api/owner/products/:pid`:
   - name, base URL, launch URI and description;
   - **Active**: "An inactive product signs nobody in and renews no login.";
   - **Accepts API clients**: "Companies' API clients may get tokens for this
     product, for the scopes they hold. Off, no application token is issued for
     it."
3. **Redirect URIs**: one per line, at most 20, matched exactly →
   `PUT …/redirect-uris { redirect_uris[] }`.
4. **Roles**: the role names grants may use, one per line, at most 50, each at
   most 64 characters → `PUT …/roles { roles[] }`. Removing a role that is still
   granted fails with 409 "A role being removed is still granted".

**Ideas.** Use chip or list editors with per-line validation instead of plain
textareas. The API takes the whole list at once, so editing stays local until
**Save**.

#### 7.4.11 Client credentials

**Purpose.** Every credential that can get a token, in one place.

- **Product logins:** Product, Client ID, Secret ("Set {date}" or "Not issued",
  with a link to rotate), API clients ("Accepted" or "Not accepted").
- **API clients**, from every company (`GET /api/owner/api-clients`): the same
  columns as §7.3.10 plus Company, with a filter by name or company. A row
  opens the client inside its company's workspace.

---

## 8. Shared components and patterns

### 8.1 Design tokens: current identity, free to evolve

| Token | Current value | Use |
|---|---|---|
| `brand-500` | `#4f6ef7` | Primary buttons, links, focus ring |
| `brand-600` / `700` | `#3b55d9` / `#2d42b3` | Hover and pressed |
| `brand-50` / `100` | `#f0f4ff` / `#e0eaff` | Selected and highlight backgrounds |
| Neutral | Tailwind gray | Text, borders, surfaces (page `gray-50`, cards white) |
| Font | Inter, system-ui fallback | Everything; monospace for ids, secrets and code |

**Semantic status colours.** Keep the mapping even if the hues change.

| Meaning | Current tone | Examples |
|---|---|---|
| Positive / on | Green | Active, Live, Verified, Subscribed, Accepted |
| Negative / off | Red | Inactive, Revoked, Off; danger buttons |
| Caution | Amber | Owner, Unverified, No secret, None live, Trusts unverified email, Owner-console label, one-time secret |
| Informational | Blue | Pending, Read level, "Accepted" API clients |
| Brand emphasis | Brand | Admin, Edit level, Default, System group, App Central session |
| Neutral | Gray | Expired, Ended, product key tags |

### 8.2 Building blocks

| Component | Notes |
|---|---|
| **App shell** | §5.3. Space switcher, account menu, permission-aware navigation |
| **Page header** | Title, a one-sentence subtitle explaining the page, actions on the right, an optional back link |
| **Card / section** | A titled panel; most detail pages are a stack of them |
| **Data table** | Columns, row link, row actions, empty state, footer ("Load more"), loading skeleton; becomes stacked cards on narrow screens |
| **Badge** | Text plus tone (§8.1) |
| **Alert / banner** | Error, success, info, warning; dismissible; errors show `reqId` |
| **Buttons** | Primary, secondary, ghost, danger; sizes sm and md; a loading state (spinner, disabled) |
| **Form fields** | Text, email, password, number, select, checkbox, radio, textarea; label, hint, inline error, character limits (§11.4) |
| **Confirm dialog** | Replaces today's browser `confirm()` for every destructive action (§8.5) |
| **Copy-to-clipboard** | For ids, secrets, invite and reset links, code snippets; shows a "Copied" state |
| **Code block** | Monospace, scrolls horizontally, has a copy button (Try it, the token scope) |
| **Empty state** | One helpful sentence; optionally an action ("Invite someone") |
| **No access state** | §7.2.3 |
| **Full-page loader** | Session start-up |

### 8.3 The access matrix: the signature component

It is used to view and edit a group's access, a person's extra access, and
"Your access" on Profile.

- **One row per feature:** Users, Groups, Invitations, Sessions, Products,
  Company, API clients. Each row shows the feature name and a one-line
  description of what Read and Edit allow (§11.1).
- **Levels:** None / Read / Edit. Products has no Edit, so show "—".
- **Optional columns:**
  - **From groups**: read-only, for a person's inherited access;
  - **From**: where access comes from, on Profile.
- **Editable mode:**
  - a segmented control or radios per row;
  - a choice the viewer may not make is disabled, with the tooltip "You can
    only give or take away access you hold yourself";
  - a **Save** button that is enabled only when something changed. Consider
    showing a diff before saving.
- **Read-only mode:** the level as a badge (Read = blue, Edit = brand,
  None = "—").
- **Admins:** a note in place of the controls, "holds every scope, and that
  cannot be changed".

### 8.4 API-client scope picker

Three rows, each with a description and a warning when a risky level is chosen:

- REST API: None / Read / Read and edit;
- gRPC: None / Read / Read and edit;
- MCP tools: Off / On.

### 8.5 Confirmation for destructive or far-reaching actions

| Action | Consequence to state |
|---|---|
| Deactivate user | They are signed out everywhere and cannot sign in |
| Delete group | Members keep their accounts but lose what it grants |
| Remove member, or a manager | They lose what the group gives |
| Revoke session | That sign-in ends, with every app login opened from it |
| Revoke invitation | The link stops working |
| Delete API client | Its secrets stop working at once |
| Revoke API-client secret | It stops working at once |
| Rotate product secret | The current one stops working immediately |
| End subscription | People lose access to that app |
| Deactivate company | Nobody can sign in; every session ends; reactivating does not restore them |
| Change password (self) | Signed out everywhere, including every app |

### 8.6 One-time secret reveal

Used for a new API-client secret (`client_secret`, `acc_…`) and a new or
rotated product secret (`client_secret`, `acs_…`).

- A modal, or a prominent warning panel, titled "Copy this secret now. It will
  not be shown again."
- The value in monospace with a **Copy** button that confirms "Copied".
- Closing should take a deliberate step, e.g. "I've stored it" or a second
  confirmation.
- Never put the value into the URL, a toast, or anything that persists.

### 8.7 List editors (domains, redirect URIs, roles)

The API takes the whole list at once. Edit it locally as chips or rows, check
it in the browser (§11.4), and send it on **Save**. Name the first broken
entry, e.g. "A redirect URI can be at most 2,048 characters; one has 3,100."

---

## 9. Key user journeys

Make sure the design covers each journey end to end.

1. **Daily use.** `/login` → email → password → My apps → **Open CRM** (leaves
   App Central).
2. **Sign in with SSO.** Email at an SSO domain → **Continue with single
   sign-on** → the provider → back to My apps (or the choose-company step).
3. **Sign-in error from a provider.** Back at `/login?sso_error=email_unverified`
   → a clear message, then start again.
4. **A product asks for sign-in.** The API sends the browser to
   `/login?return_to=/oauth/authorize?...` → sign in → the browser continues to
   the product.
5. **New hire.** An Admin invites them into "Sales" → they open the email link →
   Accept invitation → set a password → sign in → see the apps Sales opens.
6. **Admin gives someone access.** Users → user → App Central access → set
   Sessions to Read → Save (rule-limited choices disabled).
7. **Group manager.** Admin → Groups you manage → "Support" → add a member by
   email.
8. **Set up an API client.** API clients → New → choose products → choose scope
   → New secret (one-time reveal) → copy the *Try it* snippet.
9. **Rotate an API-client secret.** Make a second secret → deploy it → revoke
   the first.
10. **Owner onboards a company.**
    1. Companies → New company (name, domain).
    2. Subscriptions → Subscribe to CRM, 50 seats.
    3. Groups → Admins → add the customer's first admin. Alternatively,
       Invitations → invite them into Admins.
    4. Login policies → set the default.
    5. SSO → add Okta and test it.
11. **Owner registers a product.** Products → Register (key, name, launch URI) →
    Issue secret (one-time reveal) → Redirect URIs → Roles → tick Accepts API
    clients (optional).
12. **Owner session older than 12 hours.** Any Owner action → "For your
    security, sign in again" → sign in → back on the same page.

---

## 10. Words, labels and messages

### 10.1 Glossary: use these words in the UI

| Say | Not | Meaning |
|---|---|---|
| App Central | auth server, IdP | This product |
| App (or product, in Owner screens) | client, service | A business app people open |
| Company | client, tenant, org | A customer |
| Admins | super users | The built-in group holding all admin access |
| Owner | super admin, root | An Alora platform operator |
| Access, Read / Edit | scopes, permissions | What someone may do in App Central. Show scope strings only as technical detail |
| Extra access | user scopes | Access given to one person on top of their groups' |
| Group manager | group admin | Adds and removes a group's members; nothing else |
| Login policy | auth policy | Which sign-in methods apply to someone |
| Single sign-on (SSO) | OIDC | The company's own identity provider |
| API client | service account, app credentials | A credential for software |
| Secret | password, key | An API client's or product's credential; shown once |
| Session | token | A live sign-in |
| Seats | licences | A cap on members, or on people who may open an app |

### 10.2 Sign-in messages from Google or SSO (the `?google_error=` / `?sso_error=` codes)

`{provider}` is "Google", or "your identity provider" for SSO.

| Code | Message |
|---|---|
| `invalid_request` | The sign-in request was incomplete. Please start again. |
| `state_mismatch` | Your sign-in could not be verified in this browser. Please try again. |
| `state_expired` | Your sign-in took too long. Please try again. |
| `exchange_failed` | {provider} could not confirm your sign-in. Please try again. |
| `email_unverified` | Your address is not verified with {provider}. Verify it, then try again. |
| `account_unavailable` | There is no account here that you can sign in to with {provider}. Contact your administrator. |
| `sso_unavailable` | Single sign-on is not available for this address. |
| `google_disabled` | Google sign-in is not available. |
| `server_error` | Something went wrong signing you in. Please try again. |
| `cancelled` | Sign-in was cancelled. |
| anything else | Sign-in failed. Please try again. |

### 10.3 API messages the UI will display (4xx)

| When | Message |
|---|---|
| Rule 1 | You can only give or take away scopes you hold yourself |
| Rule 2 | You can only manage people who have no more access than you |
| Group managers acting on managers | A group's managers can't add or remove themselves or each other; an Admin does that |
| Admin giving a group apps | Only the Owner can give a group products |
| Self | Cannot modify your own account · You can't make yourself a group's manager |
| Guards | Cannot deactivate the company's last active Admin · Cannot remove the company's last active Admin · The Admins group can't have managers · The platform company cannot be suspended |
| Duplicates (409) | A group with this name already exists · A user with this email already exists · An invitation for this email is already pending · User is already a member of this group · This person already manages the group · An API client with this name already exists · A product with this key already exists · Another company has verified this domain |
| Limits | Seat limit reached · The company is not subscribed to this product |
| Owner | Recent sign-in required (handled specially, §6.2) |
| Generic | Invalid request (a validation failure) · Forbidden (missing access) · Not Found (also used for another company's ids) |

Messages are English-only from the API. The UI may translate its own text, but
API messages will arrive in English.

---

## 11. Data reference

### 11.1 Admin access: features and levels

| Feature | Read lets you… | Edit lets you… |
|---|---|---|
| Users | See people and their access | Activate and deactivate people, send password resets, give extra access |
| Groups | See groups and their members | Create, rename and delete groups, choose their access, add and remove members |
| Invitations | See invitations | Invite people into groups, revoke invitations |
| Sessions | See who is signed in | Revoke sessions |
| Products | See the company's subscriptions (the Owner decides them) | — |
| Company | See the company's settings | Rename the company |
| API clients | See API clients | Create API clients, rotate their secrets, choose their products and scope |

- Scope strings are `feature:read` and `feature:edit`, e.g. `users:edit`.
  **Edit always includes Read.**
- Everyone holds `apps:read`, which is never shown as a choice. Owners also hold
  `owner`.
- A person's access is the union of their groups' plus their extra access. The
  Admins group holds everything.

**The two rules.** Grey out with a reason; never hide silently.

- **Rule 1.** Nobody gives or takes away access they do not hold. This covers a
  group's access, creating and deleting groups, adding and removing members, the
  groups an invitation joins, and someone's extra access.
- **Rule 2.** Nobody acts on someone with more access than they have. This
  covers deactivating, resetting a password, changing extra access or groups,
  and appointing or removing a manager. "More access" includes what the groups
  they *manage* give. Nobody but an Owner acts on an Owner.
- **The Owner console is bound by neither rule.**

### 11.2 Enumerations and how to show them

| Field | Values → label |
|---|---|
| Invitation `status` | PENDING → Pending (blue) · ACCEPTED → Accepted (green) · EXPIRED → Expired (gray) · REVOKED → Revoked (red) |
| Session `kind` | CENTRAL → "App Central" (brand) · PRODUCT → the product key (gray) |
| Session `auth_method` | EMAIL → Password · GOOGLE → Google · OIDC → Single sign-on |
| User `account_type` | EMAIL → password only · OAUTH_ONLY → Google/SSO only · HYBRID → both. (Today shown raw; a friendlier label is welcome) |
| Access `source` (user app access) | DIRECT → "Directly" · GROUP → "Through a group" |
| Scope `source` (Profile) | GROUP → the group's name · EXTRA → "Extra access" |
| Login policy `source` | USER → "set on the user" · GROUP → "from a group" · DEFAULT → "company default" |
| Company `subscription_status` | TRIAL · ACTIVE · SUSPENDED · CANCELLED (a label today; see §7.4.3) |
| Group `system_key` | `ADMINS` → the Admins group ("System" badge); empty for ordinary groups |
| API-client product `usable` | false → struck through, "earns no token" |
| Secret state | `is_live` → Live · `revoked_at` set → Revoked · otherwise → Expired |

### 11.3 Lifetimes worth showing in the UI

| Thing | Lifetime |
|---|---|
| Invitation | 7 days |
| Password reset link | 60 minutes |
| App Central session | 7 days idle, 14 days at most |
| Owner "recent sign-in" | 12 hours |
| API-client secret | Never, or 1–730 days (chosen at creation) |

### 11.4 Input limits (the API's; forms should stop at them)

| Field | Limit |
|---|---|
| Email | 320 characters |
| Password | 8–512 characters (8 minimum for new passwords) |
| Company name | 200 |
| Group name / description | 100 / 500 |
| API client name / description | 100 / 500 |
| Product key | 2–40: letters, digits, `-`, `_`; starts with a letter or digit |
| Product name / description | 200 / 1000 |
| URLs (base, launch, redirect) | 2,048; absolute `http(s)://host…`, no user info, no `#fragment` |
| Redirect URIs | At most 20 |
| Roles | At most 50, each at most 64 |
| Domain | 253; a valid domain name such as `acme.com` |
| SSO domains | At most 50 |
| Policy name | 100; priority −1000 to 1000 |
| SSO name / issuer / client id / secret / scopes | 100 / 512 / 256 / 1024 / 256; the issuer has no `?query` |
| Seats | 1 or more, or empty for unlimited |
| Names | Never blank; whitespace-only counts as empty |

---

## 12. Opportunities and non-goals

### 12.1 Supported by today's API, not yet in the UI

- **Admin overview / home.** Counts of pending invitations, live sessions,
  groups, API clients and subscriptions, each from its list endpoint. There is
  no total-users endpoint, so don't show a user count.
- **Owner overview.** Companies and their user counts, products, API clients
  without a live secret, and products without a secret.
- **Client-side search, filter and sort** on the fully loaded lists: groups,
  invitations, sessions, products, companies, policies, SSO connections and API
  clients. Users are searched server-side.
- **Resend invitation:** revoke, then create.
- **Subscription end date** (`ends_at`).
- **Seats, status and active at company creation.**
- **Direct grant expiry** (`valid_until`) shown on user detail.
- **Sessions grouped by person**, with `authenticated_at` shown.
- **Copy buttons** everywhere an id, link or secret appears.
- **Setup checklists:** an API client ready to use, a product fully registered
  (secret, redirect URIs, roles, launch URI), a company onboarded
  (subscriptions, admin, policy).
- **Avatars made from email initials.** Monogram app tiles coloured by product
  key.

### 12.2 Not possible without backend work: do not design as working features

- Self sign-up, or a "Create account" link.
- **"Forgot password?" on the sign-in page.** Only administrators issue resets.
- Personal names, avatars or profile fields other than email.
- MFA, passkeys or security keys.
- An audit-log viewer. Actions are audited, but there is no read endpoint.
- Deleting users (only deactivation) or editing an invitation.
- A total user count, analytics or charts over time.
- Logos for products or companies, or per-company theming.
- SAML connections (only OpenID Connect).
- Server-side sort or pagination on lists other than users.
- Real-time updates (no websockets). Lists refresh on load or after an action.
- Bulk actions as single calls. They could loop over single calls client-side,
  but each item can fail on its own (rules, seats), so the design needs
  per-item results.

---

## 13. Appendix: endpoint map

All `/api/*` calls carry the in-memory bearer token. All `/auth/*` POSTs are
same-origin. JSON only: unknown fields are rejected. `:cid` is a company id.

### Sign-in (`/auth`)

| Method & path | Body → response |
|---|---|
| POST `/auth/login/discover` | `{email}` → `{password, google, sso:{connection_id}\|null}` |
| POST `/auth/login/password` | `{email, password, return_to?}` → `{status:"authenticated", access_token, expires_in, return_to?}` or `{status:"choose_company", companies[{client_id,name}]}` |
| GET `/auth/login/choices` | → `{companies[]}` |
| POST `/auth/login/choose` | `{client_id}` → as password sign-in |
| GET `/auth/google/start?return_to=` · `/auth/sso/start?connection_id=&return_to=` | browser navigation |
| POST `/auth/central/refresh` | → `{access_token, token_type, expires_in}` |
| POST `/auth/central/logout` | → 204 |
| GET `/auth/accept-invitation/lookup?token=` | → `{client_name, email, expires_at, groups[], methods{password,google,sso}}` |
| POST `/auth/accept-invitation` | `{token, password}` → 204 |
| POST `/auth/accept-invitation/federated` | `{token}` → 204 |
| POST `/auth/reset-password` | `{token, new_password}` → 204 |

### Me (`/api/me`)

| Method & path | Body → response |
|---|---|
| GET `/api/me` | → Me (§6.1) |
| GET `/api/me/apps` | → `[{product_id, key, name, description, roles[], launch_url}]` |
| POST `/api/me/change-password` | `{current_password, new_password}` → 204 |
| GET `/api/me/managed-groups` · `/:gid` | → group list · group detail |
| POST `/api/me/managed-groups/:gid/members` · DELETE `…/members/:uid` | `{email}` → 201 · 204 |

### Company admin (`/api/admin`), each needing its feature's Read or Edit

| Method & path | Body → response |
|---|---|
| GET `/users?search=&cursor=&take=` | → `{users[], nextCursor}` |
| GET `/users/:id` | → UserDetail (§7.3.2) |
| PATCH `/users/:id` | `{is_active}` → `{id, is_active}` |
| PUT `/users/:id/scopes` | `{scopes[]}` → `{scopes[]}` |
| POST `/users/:id/password-reset` | → `{expires_at, reset_url?}` |
| GET / POST `/invitations` | → list · `{email, group_ids[]}` → `{id, email, expires_at, invite_url?}` |
| DELETE `/invitations/:id` | → 204 |
| GET / POST `/groups` | → list · `{name, description, scopes[]}` → group |
| GET / PATCH / DELETE `/groups/:id` | → detail · `{name, description}` → 204 · 204 |
| PUT `/groups/:id/scopes` | `{scopes[]}` → `{scopes[]}` |
| POST / DELETE `/groups/:id/members[/:userId]` | `{email}` → 201 · 204 |
| POST / DELETE `/groups/:id/managers[/:userId]` | `{email}` → 201 · 204 |
| GET / DELETE `/sessions[/:id]` | → list · 204 |
| GET `/products` | → subscriptions list |
| GET / PATCH `/client` | → company · `{name}` → company |
| GET / POST `/api-clients` | → list · `{name, description}` → client |
| GET / PATCH / DELETE `/api-clients/:id` | → detail · `{name, description, is_active}` · 204 |
| PUT `/api-clients/:id/scopes` | `{scopes[]}` |
| PUT `/api-clients/:id/products` | `{product_ids[]}` |
| POST `/api-clients/:id/secrets` | `{expires_in_days?}` → **secret, once** |
| DELETE `/api-clients/:id/secrets/:sid` | → 204 |

### Owner (`/api/owner`)

| Method & path | Body → response |
|---|---|
| GET / POST `/companies` | → list · `{name, domain?, max_seats?, subscription_status?, is_active?}` |
| GET / PATCH `/companies/:cid` | `{name?, subscription_status?, max_seats?, clear_max_seats?, is_active?}` |
| PUT `/companies/:cid/domain` | `{domain\|null, verified}` |
| GET `/companies/:cid/subscriptions` · PUT `…/subscriptions/:pid` | `{is_active, seat_limit?, ends_at?}` |
| `/companies/:cid/users…`, `/groups…`, `/invitations…`, `/api-clients…` | the admin routes above, at the same paths |
| PUT / DELETE `/companies/:cid/users/:uid/grants/:pid` | `{role_name}` |
| PUT `/companies/:cid/users/:uid/login-policy` | `{policy_id\|null}` |
| PUT `/companies/:cid/groups/:gid/product-grants` | `{product_grants[{product_id, role_name}]}` |
| PUT `/companies/:cid/groups/:gid/login-policy` | `{policy_id\|null}` |
| GET / POST / PATCH / DELETE `/companies/:cid/login-policies[/:pid]` | `{name, priority, allow_password, allow_google, sso_connection_id?}` |
| PUT `/companies/:cid/login-policies/:pid/default` | → 204 |
| GET / POST / PATCH `/companies/:cid/sso-connections[/:sid]` | `{name, issuer, client_id, client_secret?, scopes?, trust_unverified_email?, is_active}` |
| PUT `/companies/:cid/sso-connections/:sid/domains` | `{domains[]}` |
| POST `/companies/:cid/sso-connections/:sid/test` | → `{issuer, authorization_endpoint, token_endpoint, jwks_uri}` |
| GET / POST `/products` · GET / PATCH `/products/:pid` | `{key, name, description?, base_url?, initiate_login_uri?, is_active?, accepts_api_clients?}` |
| PUT `/products/:pid/redirect-uris` · `/roles` | `{redirect_uris[]}` · `{roles[]}` |
| POST `/products/:pid/client-secret` | → `{client_id, client_secret, rotated_at}` **once** |
| GET `/api-clients` | → every company's API clients (with `company_id`, `company_name`) |

The exact shapes of every request and response are in
`alora-auth-api/docs/swagger.json`, also served at `/docs` when the API runs
with documentation enabled.

---

## 14. What to deliver

A design that can be built against this API without a single backend change:

1. **A design system:** tokens (colour, type, spacing, radius, elevation) for
   light and optionally dark, plus the components in §8.2, with all their
   states (default, hover, focus, disabled, loading, error).
2. **The app shell:** desktop, tablet and phone, for all three spaces and the
   permission variations of the navigation.
3. **Every page in §7**, each with its states:
   - loading;
   - empty;
   - error;
   - read-only (Read without Edit);
   - choices disabled by rule;
   - success.
4. **Signed-out flows** on phone and desktop:
   - sign-in, with every method combination, the company chooser and the
     provider errors;
   - accept invitation, with every method combination;
   - reset password.
5. **The special patterns:** the access matrix (§8.3), one-time secret reveal
   (§8.6), confirmation dialogs (§8.5), list editors (§8.7) and the Owner
   console's "acting on another company" cue.
6. **Prototypes of the journeys in §9.**

**For the developer who builds it.** The Playwright suite in
`alora-auth-ui/e2e/` drives the current UI through accessible roles and names
(buttons, links, headings, labelled fields) and a few `data-testid`s. A
redesign that keeps accessible labels clear will need few test changes. Plan to
update the specs alongside the new UI.
