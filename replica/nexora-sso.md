# Nexora → CSPM single sign-on: what to add on onenexora.com

The CSPM side is done and tested (`GET /api/auth/sso`). The Nexora side lives in the onenexora.com console code, which is **not in this repository**, so I could not change it. This is everything it needs.

## 1. Shared secret
Generate one random secret, at least 32 characters: `openssl rand -base64 48`. Put the **same value** in:
- the CSPM API as `SSO_SECRET` (the API refuses to start in production if it is shorter than 32 characters);
- the Nexora console's server environment as, say, `CSPM_SSO_SECRET`. Server side only: never in browser code, never in `NEXT_PUBLIC_*`/client bundles.

## 2. Add the helper
Copy `lib/nexora-sso/src/index.ts` into the console (one file, only Node built-ins). Then add a route that runs **after** the console has checked the user is signed in:

```ts
import { createCspmSignInUrl } from "./nexora-sso";

// e.g. GET /console/open-cspm
export async function GET(req: Request) {
  const session = await requireNexoraSession(req);          // your existing auth; return 401 if not signed in
  const org = await currentOrganization(session);
  const url = createCspmSignInUrl({
    secret: process.env.CSPM_SSO_SECRET!,
    apiUrl: "https://api.cspm.onenexora.com",
    user: { id: session.userId, email: session.email, name: session.name, orgId: org.id, orgName: org.name,
            role: org.role === "admin" ? "admin" : "viewer" },   // owner is never granted this way
  });
  return Response.redirect(url, 302);
}
```
Then add an **"Open CSPM"** button in the console (and on the CSPM product page for signed-in users) linking to that route. Do not put the token URL in HTML: it is created per click.

## 3. What CSPM does with it
| Nexora sends | CSPM does |
| --- | --- |
| `sub` (user id), `org` (organization id) | finds or creates the user and the organization by those ids |
| `email` | **trusted and marked confirmed**, so only send addresses Nexora has verified |
| first user of an organization | becomes the CSPM **owner** |
| later users of the same organization | join with the `role` sent (`viewer` default, `analyst`, `admin`); `owner` is never accepted |
| `jti` | one-time: a link used twice is refused |
| `exp` | at most 10 minutes ahead, default 2 minutes |
Then it sets its session cookie and redirects to the dashboard. Role changes made in CSPM's Team page are not overwritten on later sign-ins (the role claim only applies when a person first joins).

## 4. Check it
1. Locally: `SSO_SECRET=<secret> API_URL=http://localhost:8080 node deploy/make-sso-token.mjs you@example.com "You" nexora-user-1 nexora-org-1 "Acme"` prints a URL; open it in a browser: you should land in the dashboard as owner of "Acme". Open the same URL again: it must be refused.
2. In production, after wiring the button: click it from the Nexora console as a normal user, check you arrive signed in, check the audit log shows `auth.sso`.
3. Negative checks: a link older than 10 minutes, an edited token, or one signed with another secret must all return 401.

## Things to decide
- **Sign-out:** signing out of Nexora does not sign out of CSPM (separate sessions, 7 days). Making it do so needs the console to call CSPM's `POST /api/auth/logout` from the browser, which only works if the console's origin is added to the API's `APP_ORIGINS` (CORS) and the request carries the `x-csrf: 1` header. Not built; decide whether you want it.
- **Removing a person from a Nexora org** does not remove them from CSPM. Do that on CSPM's Team page, or add a webhook later.
- **Domain verification:** CSPM trusts the email claim; do not mint links for unverified addresses.
