# Deploying NEXORA CSPM on one Oracle Cloud (OCI) VM

**Status:** the kit in `deploy/oci/` is written and was tested **on a laptop** (Docker, ARM): the three images build, Postgres, the API and Caddy start, migrations and row level security work, and the sites and API answer over HTTPS. It has **never run on OCI**, and I have no access to your OCI account or any server, so nothing is live. You run the steps below; they take about an hour, most of it waiting for DNS and the first build.

## What you get
One VM running three containers behind automatic HTTPS (Let's Encrypt):

| container | does |
| --- | --- |
| `web` (Caddy) | `cspm.<domain>` marketing site, `app.cspm.<domain>` dashboard, `api.cspm.<domain>` proxied to the API; security headers and CSP |
| `api` | the Node API (migrations run at start; row level security on) |
| `db` | Postgres 16 on a Docker volume; not reachable from outside the VM |

Only ports 80 and 443 are exposed. This is **one machine**: no high availability, no managed database. Fine for a beta; see "Not covered".

## 0. Before you start
- A domain you control (examples use `onenexora.com` with `cspm.`, `app.cspm.`, `api.cspm.`).
- For a **public launch** you still need the blockers in `replica/deploy.md` (email, Stripe test run, SSO, lawyer-reviewed legal pages). Deploying now as a private beta (nobody is told the URL) is fine; the app works without email and Stripe, only those features are off.

## 1. Create the VM (OCI console)
1. **Compute → Instances → Create.** Image: **Ubuntu 22.04 or 24.04**. Shape: **VM.Standard.A1.Flex (Ampere ARM)** with 2 OCPU / 8–12 GB RAM is within the Always Free allowance and is plenty; an x86 shape such as `VM.Standard.E4.Flex` (1 OCPU, 8 GB) also works. The kit builds natively on either.
2. Add your SSH public key. Create the instance in a **public subnet** with a public IP.
3. **Reserve the public IP** (Networking → Reserved public IPs, then attach it) so DNS keeps working if the VM is recreated.
4. **Open the network:** the instance's subnet **Security List** (or a Network Security Group) needs ingress rules, source `0.0.0.0/0`, TCP, destination ports **80** and **443**. Keep 22 restricted to your own IP if you can.
5. Note the public IP.

## 2. DNS
Create three **A records** to the VM's public IP, with a low TTL while testing:
`cspm.onenexora.com`, `app.cspm.onenexora.com`, `api.cspm.onenexora.com`.
Check with `dig +short app.cspm.onenexora.com` before continuing: Caddy asks Let's Encrypt for certificates on first start, and wrong DNS makes it retry (and, after repeated failures, wait).

## 3. Prepare the server
```bash
ssh ubuntu@<public ip>
git clone https://github.com/xsmartbartx/AI-Driven-CSPM.git && cd AI-Driven-CSPM/deploy/oci
bash bootstrap-ubuntu.sh        # installs Docker and opens 80/443 in the VM's own firewall; read it first
exit && ssh ubuntu@<public ip>  # log in again so the docker group applies
```
OCI Ubuntu images block everything but SSH in `iptables`, **in addition to** the OCI security list. Both must allow 80/443 (the script does the VM side; step 1.4 is the cloud side).

## 4. Configure
```bash
cd ~/AI-Driven-CSPM/deploy/oci
cp .env.example .env && chmod 600 .env
openssl rand -base64 36    # paste as JWT_SECRET
openssl rand -base64 24    # paste as POSTGRES_PASSWORD
nano .env                  # set SITE_HOST / APP_HOST / API_HOST, ACME_EMAIL, the two secrets
```
Leave the optional blocks empty for now. Add each one when you have set that service up (email: `replica/email-setup.md`, Stripe: `replica/stripe-setup.md`, SSO: `replica/nexora-sso.md`, AWS: `replica/aws-setup.md`), then `docker compose up -d` again. **Never commit `.env`**, and do not paste its contents into chats or tickets.

## 5. Start
```bash
docker compose up -d --build      # first build takes several minutes (it compiles the API and both sites)
docker compose ps                 # db healthy, api healthy, web running
docker compose logs -f web        # watch the certificates being issued; Ctrl-C to leave
```
Check from your own computer:
- `curl https://api.cspm.onenexora.com/api/healthz` → `{"status":"ok"}`
- open `https://cspm.onenexora.com` (landing page, demo scan works) and `https://app.cspm.onenexora.com` (sign up, run the sample scan).
- `docker compose logs api | head` shows `Server listening` with `db: "postgres"` and no `RLS_ENFORCE=0` warning.

## 6. Day-two operations
**Update to a new release**
```bash
cd ~/AI-Driven-CSPM && git pull && cd deploy/oci
./backup.sh                       # always before a release that adds a migration
docker compose up -d --build
```
Migrations run when the API starts. If one fails the API refuses to start and keeps the old container only if you did not stop it: check `docker compose logs api`.

**Backups** (database only; secrets are in `.env`, keep a copy somewhere safe and separate)
```bash
sudo mkdir -p /var/backups/nexora-cspm && sudo chown $USER /var/backups/nexora-cspm
crontab -e    # add:   17 3 * * *  cd $HOME/AI-Driven-CSPM/deploy/oci && ./backup.sh >> $HOME/backup.log 2>&1
```
It keeps the newest 14 and refuses to keep an empty dump. **Copy backups off the VM** (OCI Object Storage bucket, another machine): a backup on the same disk does not survive losing the VM. **Practise a restore** once on a throwaway copy: `./restore.sh <file>` asks you to type `restore`.

**Logs:** `docker compose logs -f api` (JSON lines; no tokens, passwords or request bodies are logged). **Restart:** `docker compose restart api`. **Stop everything:** `docker compose down` (data stays in the volumes; `down -v` deletes it).
**Disk:** `docker system df`; prune old images after updates with `docker image prune -f`.

**Rollback:** `git checkout <previous commit>` and `docker compose up -d --build`. A migration is forward-only: if a release added one, restore the backup taken before it as well.

## 7. Security notes
- Postgres has no published port. The API and web containers talk to it over the private compose network.
- The database role `cspm` owns the tables and runs migrations; requests run as the restricted role `cspm_app` (row level security). `RLS_ENFORCE` must stay on.
- Caddy sets HSTS, CSP, frame and content-type headers. Rate limits are per process and in memory (fine for one API container).
- Keep the OS patched: `sudo apt-get update && sudo apt-get upgrade -y` monthly, `sudo reboot` when told to (containers restart by themselves).
- `ssh` with keys only, no password logins (OCI default), and restrict port 22 to your IP in the security list.

## Not covered (add before relying on this)
Monitoring and alerts (uptime check on `/api/healthz`, disk and memory), log shipping, error tracking, automatic OS updates, off-VM backups on a schedule, a second VM or managed database for availability, a WAF or DDoS protection, secrets in OCI Vault instead of a file, and CI/CD that deploys on merge. None of these block a private beta.

## If something fails
| symptom | usual cause |
| --- | --- |
| site times out | OCI security list or the VM firewall still closed on 80/443 (both are needed) |
| certificate errors on first visit | DNS not yet pointing at the VM, or the A records mistyped; fix DNS, `docker compose restart web` |
| `api` keeps restarting | `docker compose logs api`: a missing secret, `Row level security is not usable` (the database user cannot `SET ROLE cspm_app`; the bundled Postgres user can), or a failed migration |
| dashboard loads but calls fail | `VITE_*` are baked in at build time: if you changed a hostname, `docker compose up -d --build` again |
| out of memory during the first build on a small VM | add swap (`sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`) or build with 8 GB RAM |
