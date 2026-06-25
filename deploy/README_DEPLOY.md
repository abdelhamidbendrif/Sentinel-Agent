# Sentinel — Deployment Guide

Two deployment targets are supported: **Streamlit Community Cloud** (free,
recommended for judges) and **Google Cloud Run** (production-grade container).

---

## Option A — Streamlit Community Cloud (recommended, free, 5 minutes)

This is the easiest path and produces the "public project link" required by
the Kaggle submission.

### Steps

1. **Push to GitHub**
   ```bash
   git init          # if not already a git repo
   git add .
   git commit -m "Initial Sentinel submission"
   git remote add origin https://github.com/<your-username>/sentinel-agent.git
   git push -u origin main
   ```

2. **Deploy on Streamlit Cloud**
   - Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
   - Click **New app**.
   - Repository: `<your-username>/sentinel-agent`
   - Branch: `main`
   - Main file path: `dashboard.py`
   - Click **Deploy**.

3. **Set the API key as a Secret**
   - In your app's settings → **Secrets**, add:
     ```toml
     GOOGLE_API_KEY = "AIza..."
     ```
   - This injects the key as an environment variable at runtime without
     exposing it in the repository.

4. **Share the URL** — Streamlit Cloud gives you a public URL like
   `https://<your-app>.streamlit.app`. Paste this as the Project Link in
   your Kaggle submission.

### Notes
- Free tier allows 1 private app or unlimited public apps.
- The dashboard reads `GOOGLE_API_KEY` from the environment (set via Secrets
  above) or from the sidebar input at runtime — both work.

---

## Option B — Google Cloud Run (production container)

Use this if you want a fully managed, auto-scaling deployment on GCP.

### Prerequisites
- Docker installed
- `gcloud` CLI authenticated (`gcloud auth login`)
- A GCP project with Cloud Run and Artifact Registry enabled

### Build and push

```bash
# Set your project and region
export PROJECT_ID=your-gcp-project-id
export REGION=us-central1
export IMAGE=gcr.io/$PROJECT_ID/sentinel-agent

# Build the container image
docker build -t $IMAGE .

# Push to Google Container Registry
docker push $IMAGE
```

### Deploy to Cloud Run

```bash
gcloud run deploy sentinel-agent \
  --image $IMAGE \
  --region $REGION \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars GOOGLE_API_KEY=your_key_here \
  --port 8501
```

> **Security note:** For production, store the API key in
> [Secret Manager](https://cloud.google.com/secret-manager) and reference it
> via `--set-secrets` instead of `--set-env-vars`.

### Run the scenario harness (non-interactive)

The default Docker CMD runs all five scenarios and exits:

```bash
docker run --rm -e GOOGLE_API_KEY=$GOOGLE_API_KEY sentinel-agent
```

To run a specific scenario:

```bash
docker run --rm -e GOOGLE_API_KEY=$GOOGLE_API_KEY sentinel-agent \
  python scenarios/run_scenarios.py financial_fraud
```

### Run the Streamlit dashboard in Docker

```bash
docker run --rm -p 8501:8501 \
  -e GOOGLE_API_KEY=$GOOGLE_API_KEY \
  sentinel-agent \
  streamlit run dashboard.py --server.port=8501 --server.address=0.0.0.0
```

Then open [http://localhost:8501](http://localhost:8501).

---

## No secrets in the codebase

`GOOGLE_API_KEY` is **always** read from the environment — never hard-coded.
The `.gitignore` excludes `.env` and `.streamlit/secrets.toml` to prevent
accidental commits.
