# AETHER ARAN IAM

**Pluma Security** — a Streamlit-based cloud security dashboard for AWS IAM. Detects privilege escalation, flags least-privilege drift, checks credential hygiene, and lets you ask an AI assistant (**NIMORA**) questions about your findings.

---

## Features

| Service | What it does |
|---|---|
| ⚠️ **Privilege Escalation Detector** | Live AWS CloudTrail analysis — flags risky IAM changes (policy attachments, key creation, etc.), with date-range filtering and PDF export |
| 📊 **Least-Privilege Drift Analyzer** | Compares granted IAM permissions against AWS Access Advisor usage data — surfaces unused/over-provisioned permissions |
| 🔑 **Credential Hygiene** | MFA compliance, access key age, and root account usage checks |
| 🤖 **NIMORA** | Gemini-powered chat assistant scoped to your security data — answers questions about findings, explains the dashboard, and refuses off-topic requests |

---

## Architecture

The whole app lives in a single `app.py`, built around two ideas that keep the three detectors from drifting apart as the product grows:

- **Polymorphism** — `PrivilegeEscalationService`, `DriftAnalyzerService`, and `CredentialHygieneService` all implement a common `SecurityService` interface (`load()` / `metrics()` / `highlighter()`). The dashboard doesn't branch per-service; it just calls `.render()`. Adding a 4th detector later means writing one class, not touching the dashboard's control flow.
- **Isomorphism** — `IAM_EVENT_SCHEMA` is the single source of truth for the CloudTrail event shape. The DataFrame columns, the PDF export headers/widths, and the NIMORA/Gemini context are all *derived* from it, so they can't silently drift out of sync with each other.

All Streamlit page-rendering (auth gate, sidebar, service dispatch) runs inside `main()`, called only under `if __name__ == "__main__":`. This is what lets `pytest` `import app` safely — importing the module defines functions/classes without launching any UI.

---

## Project Structure

```
IAM project/
├── requirements.txt
├── .gitignore
├── .env                       # GEMINI_API_KEY (never committed)
├── part 1/                    # ← this app
│   ├── app.py                 # dashboard, services, utils — single file
│   ├── config.yaml            # auth credentials (never committed)
│   ├── config.yaml.example    # template — copy this to config.yaml
│   ├── generate_cookie_key.py # one-time helper for config.yaml's cookie.key
│   ├── detector_core.py       # fetch_iam_events() — CloudTrail/S3 fetch logic
│   ├── nimora_avatar.png
│   ├── pytest.ini
│   └── tests/
│       ├── conftest.py
│       ├── test_utils.py
│       ├── test_services.py
│       └── test_nimora.py
├── part 2/
│   ├── drift_analyzer.py
│   └── unused_permissions_report.csv
├── part 3/
│   └── test_gemini.py
└── part 4/
    ├── hygiene_checker.py
    └── hygiene_report.csv
```

---

## Setup

### 1. Install dependencies
```bash
cd "part 1"
pip install -r ../requirements.txt
```

### 2. Configure environment
```bash
cp ../.env.example ../.env
```
Edit `.env` and set:
```
GEMINI_API_KEY=your-real-gemini-api-key
```

### 3. Configure authentication
```bash
cp config.yaml.example config.yaml
python generate_cookie_key.py     # copy the printed value
```
Edit `config.yaml`:
- Set real usernames/passwords under `credentials.usernames`
- Paste the generated key into `cookie.key`

### 4. AWS access
`detector_core.py` needs AWS credentials with CloudTrail/S3 read access to the bucket configured in `app.py` (`aws-cloudtrail-logs-...`). Use whatever your environment normally uses (`~/.aws/credentials`, environment variables, or an IAM role if running on EC2/ECS).

### 5. Run
```bash
streamlit run app.py
```

---

## Security

This is a security product, so it gets held to its own standard:

- **Authentication** — `streamlit-authenticator` login gate; nothing renders until you're signed in.
- **NIMORA prompt-injection defense** — product rules live in a separate `system_instruction` channel from the data/question `contents`, so text embedded in a log row or typed by a user can't override NIMORA's behavior. Backed by a pattern-based input guard and session-scoped rate limiting (8 questions / 5 min).
- **No secrets in git** — `config.yaml` and `.env` are gitignored. Never commit real credentials.
- **Error handling** — AWS, Gemini, CSV, and PDF calls are all wrapped; a failure in one service degrades that service only, not the whole app. See `logs/app.log`.

See [`DEPLOYMENT.md`](../DEPLOYMENT.md) for the pre-deploy security checklist before putting this anywhere internet-facing.

---

## Testing

```bash
cd "part 1"
pytest
```
29 tests across `test_utils.py`, `test_services.py`, `test_nimora.py` — covers the risk highlighters, PDF export, the polymorphic service classes, the injection guard, rate limiting, and the LLM context row-capping.

---

## Performance notes

- Report tables paginate at 50 rows/page — large datasets don't get fully styled/rendered on every rerun.
- NIMORA's Gemini context caps at the 300 highest-risk rows per dataset, not the full CSV — keeps responses fast and token cost bounded.
- `@st.cache_data(ttl=300)` on all data loaders — 5-minute auto-refresh, plus a manual 🔄 button to force-clear.

---

## Known limitations

- No automated CI pipeline yet — tests are run manually (`pytest`) before each deploy.
- Rate limiting is per-browser-session (via `st.session_state`), not per-user account — a user with multiple tabs/sessions gets separate limits.
- `detector_core.py`'s AWS error handling depends on that module's own implementation; `app.py` catches whatever it raises but can't distinguish "no credentials" from "network timeout" without changes there too.
