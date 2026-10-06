# Backlog

Work that is not built yet, and nothing else.

- **When an item is implemented, delete it from this file** in the same change
  that implements it.
- **New future work goes here**, in the same shape: what is missing, what to do,
  and how to tell it is done.

---

## Google sign-in in local runs

**What is missing.** The code is built: the login page's **Continue with
Google** button, the Google round trip and account linking. The Go suite tests
it against a stub Google. But no run has real Google credentials, and
`alora-auth-api/scripts/e2e-up.sh` leaves Google unset. So the API tells the
login page Google is off, and the button never shows.

**To do**
1. In Google Cloud Console, create an OAuth client of type *Web application*.
   Set its authorised redirect URI to `http://localhost:5173/auth/google/callback`.
2. Give the API all three settings. It refuses to start with only some of them.
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `GOOGLE_REDIRECT_URI=http://localhost:5173/auth/google/callback`

   `e2e-up.sh` passes on whatever the calling shell exports, so export the three
   before running it. Keep the secret out of the repository.
3. For production, create a separate Google client. Its redirect URI must be
   the production origin's `/auth/google/callback`, over https: the API
   refuses http there.

**Keep in mind**
- The button appears only after the email step.
- It appears only where the company's sign-in policy allows Google. The
  default policy does.
- Google sign-in never creates accounts. The Google address must be verified
  and belong to an existing user of the company.

**Done when**
- For a company whose policy allows Google, the login page offers **Continue
  with Google** after the email step.
- A verified Google address of an existing user signs in.
- The Playwright suite still passes with Google configured.

---

## Seat limits: the remaining edges

**What is missing.** Seat limits are enforced (SPEC.md §2, *Seat limits*): a
company's `max_seats` when a member is created or reactivated, and a product's
`seat_limit` on every grant that widens access. Each runs in the change's own
transaction, under a row lock. What is left:
- No test races additions at the limit, although the locks are designed for it.
- Reactivating a person restores their product access without re-checking each
  product's `seat_limit`; only `max_seats` is checked.
- Lowering a limit below current use changes nothing for people who already
  hold seats, and no document says whether that is intended.
- Invitations can be issued past `max_seats`; they fail only when accepted.
- The Owner door's direct grants and group product grants are tested over the
  limit at the service layer, but not through their HTTP routes.
- The Owner console reports a company's size as `user_count`
  (`vw_CompanyListItem`). That count includes deactivated people, so it is not
  the number `max_seats` limits.

**To do**
1. Add a test that accepts invitations and grants access concurrently at the
   limit.
2. Re-check `seat_limit` for each product a person regains on reactivation.
3. Decide, and state in SPEC.md, what lowering a limit does, and whether issuing
   an invitation past the limit is refused or warned.
4. Report the seat count, active members, wherever `max_seats` is shown or set.

**Done when**
- The concurrent test passes repeatedly with exactly the allowed number of
  successes.
- Reactivation past a product's limit is refused with 409.
- SPEC.md states both decisions.
- The Owner console's seat count counts only active members.

---

## What a company's subscription status means

**What is undecided.** Every door checks `tbl_clients.is_active`: sign-in, the
session gate, product access. Nothing at runtime reads `subscription_status`.
Yet the Owner console offers TRIAL, ACTIVE, SUSPENDED and CANCELLED beside the
active switch, and the API refuses SUSPENDED or CANCELLED for the platform
company as if they suspended it. An Owner who sets SUSPENDED but leaves the
company active has suspended nothing.

**To do.** Decide what the status is:
- either a billing label, in which case say so in the console and the API
  documentation, and drop it from the platform guard;
- or a door, in which case SUSPENDED and CANCELLED shut every door and end the
  company's sessions, exactly as `is_active: false` does.

**Done when**
- SPEC.md states the rule.
- A test sets each status and finds every door in the state the rule says.
