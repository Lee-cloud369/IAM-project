# Deployment Guide — AETHER ARAN IAM

## Before you deploy anywhere

This dashboard shows CloudTrail events, unused permissions, and MFA/credential gaps for your AWS account — that's exactly the kind of data an attacker wants. Go through this checklist before putting it anywhere reachable by other people.

- [ ] `config.yaml` has real usernames/passwords (not the `ChangeMe123!` placeholders) and a freshly generated `cookie.key`
- [ ] `config.yaml` and `.env` are **not** committed to git (`git status` should show them ignored)
- [ ] `GEMINI_API_KEY` in `.env` is a real, working key with an appropriate quota/billing limit set on the Google Cloud side (NIMORA's rate limiter protects against runaway *usage*, not against a leaked key being used elsewhere)
- [ ] `pytest` passes (`29 passed`) on the machine/image you're about to deploy
- [ ] AWS credentials available to `detector_core.py` are **read-only** (CloudTrail/S3 read access only) — this app never needs write access to your AWS account
- [ ] You've decided who should have login access and created exactly those accounts in `config.yaml` — no shared/generic logins
- [ ] `logs/app.log` doesn't get exposed publicly (it can contain stack traces with internal details)

**Recommendation: internal-only for now.** Run this behind your company VPN, on an internal network, or restricted by IP/security group — not on the open internet — until you've had a chance to do a proper security review (pen test, secrets rotation policy, audit logging on the login events themselves).

---

## Option A — Internal server / VM (recommended for now)

Good for: a small team, already has a VPN or internal network, wants full control.

1. Provision a VM (EC2 in a private subnet, or any internal Linux box) with Python 3.10+.
2. Clone/copy the project, `cd "part 1"`, `pip install -r ../requirements.txt`.
3. Set up `.env` and `config.yaml` as in the main README — **do this on the server directly**, don't commit them and pull.
4. Attach an IAM role (if on EC2) with CloudTrail/S3 **read-only** access, so you don't need to manage long-lived AWS keys on the box at all.
5. Run behind a process manager so it survives reboots/crashes:
   ```bash
   # example with systemd — create /etc/systemd/system/aether-aran-iam.service
   [Unit]
   Description=AETHER ARAN IAM
   After=network.target

   [Service]
   WorkingDirectory=/opt/iam-project/part 1
   ExecStart=/opt/iam-project/part 1/.venv/bin/streamlit run app.py --server.port=8501 --server.address=0.0.0.0
   Restart=on-failure
   User=streamlit-app

   [Install]
   WantedBy=multi-user.target
   ```
   ```bash
   sudo systemctl enable --now aether-aran-iam
   ```
6. Put it behind an internal reverse proxy (nginx/Caddy) with **TLS**, even on an internal network — login credentials shouldn't travel in plaintext. A minimal nginx example:
   ```nginx
   server {
       listen 443 ssl;
       server_name iam-dashboard.internal.yourcompany.com;
       ssl_certificate     /etc/ssl/certs/internal.crt;
       ssl_certificate_key /etc/ssl/private/internal.key;

       location / {
           proxy_pass http://127.0.0.1:8501;
           proxy_set_header Host $host;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
       }
   }
   ```
7. Restrict network access at the security-group/firewall level to your VPN CIDR or office IP range.

---

## Option B — Docker (portable, same idea as Option A)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY "part 1" .
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

```bash
docker build -t aether-aran-iam .
docker run -d \
  -p 8501:8501 \
  --env-file .env \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  --name aether-aran-iam \
  aether-aran-iam
```
Still put this behind the same internal reverse proxy + network restrictions as Option A — the container itself has no additional access control.

---

## Option C — Streamlit Community Cloud

**Not recommended for this app.** Community Cloud apps are public-URL by default (viewer-restriction requires a paid tier), and you'd need to manage `config.yaml`/AWS credentials as platform secrets rather than local files — workable, but for a tool that displays your org's security posture, the extra control of Options A/B is worth it until you've done a full review.

If you still want to evaluate it for a demo with fake/sample data only: use Streamlit's `st.secrets` for `GEMINI_API_KEY` and the `config.yaml` contents instead of local files, and never point it at real AWS credentials.

---

## Post-deploy verification

1. Visit the URL — you should land on the **login screen**, not the dashboard.
2. Log in with a real account, confirm the sidebar shows "Signed in as ...".
3. Click through all four services (Privilege Escalation, Drift, Hygiene, NIMORA) and confirm data loads or the graceful "no data" message shows — no crashes.
4. Ask NIMORA a normal question, then try an obvious injection attempt ("ignore previous instructions...") — confirm it refuses.
5. Check `logs/app.log` exists and is being written to.
6. Confirm `config.yaml` and `.env` are **not** reachable via any URL on the server (they shouldn't be, since Streamlit only serves what the app renders — but worth a direct check: `curl https://your-url/config.yaml` should 404).
