#!/usr/bin/env bash
# Deploys the Apps Script connector to Google Cloud Run.
# Run it in Cloud Shell from this folder:  ./deploy.sh
#
# First run: asks for the Google OAuth client id and secret, then deploys.
# Later runs: redeploy the code and keep the settings already on the service.
#   ./deploy.sh --set-google-client   asks for the client id and secret again.
#
# Optional overrides: PROJECT, REGION (default us-central1), SERVICE (default apps-script-mcp).
set -euo pipefail

SERVICE="${SERVICE:-apps-script-mcp}"
REGION="${REGION:-us-central1}"
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
ASK_CLIENT=false
[[ "${1:-}" == "--set-google-client" ]] && ASK_CLIENT=true

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
die() { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

cd "$(dirname "$0")"
[[ -f main.ts && -f Dockerfile ]] || die "Run this from the apps-script-mcp folder."
[[ -n "$PROJECT" ]] || die "No project selected. Run: gcloud config set project YOUR_PROJECT_ID"
gcloud config set project "$PROJECT" >/dev/null 2>&1

say "Project: $PROJECT   Region: $REGION   Service: $SERVICE"

say "Checking billing"
gcloud services enable cloudbilling.googleapis.com --quiet
BILLING_ENABLED="$(gcloud billing projects describe "$PROJECT" --format='value(billingEnabled)')"
[[ "${BILLING_ENABLED,,}" == "true" ]] || die "Billing is off for $PROJECT. Link it at https://console.cloud.google.com/billing/projects and run this again."
BILLING_ACCOUNT="$(gcloud billing projects describe "$PROJECT" --format='value(billingAccountName)')"
BILLING_ACCOUNT="${BILLING_ACCOUNT#billingAccounts/}"

say "Turning on the Google APIs this needs"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  script.googleapis.com billingbudgets.googleapis.com --quiet

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
BASE_URL="https://${SERVICE}-${PROJECT_NUMBER}.${REGION}.run.app"
REDIRECT_URI="${BASE_URL}/oauth/google/callback"

HAS_CLIENT=false
if gcloud run services describe "$SERVICE" --region "$REGION" --format=json >/dev/null 2>&1; then
  if gcloud run services describe "$SERVICE" --region "$REGION" \
    --format='value(spec.template.spec.containers[0].env[].name)' | tr ';,' '\n\n' | grep -qx GOOGLE_CLIENT_ID; then
    HAS_CLIENT=true
  fi
fi

ENV_FILE=""
cleanup() { [[ -n "$ENV_FILE" ]] && rm -f "$ENV_FILE"; }
trap cleanup EXIT
yaml_quote() { printf "'%s'" "${1//\'/\'\'}"; }

DEPLOY_ARGS=(
  --source . --region "$REGION" --allow-unauthenticated
  --min-instances 0 --max-instances 2 --memory 256Mi --cpu 1 --concurrency 80 --timeout 60
  --quiet
)

if [[ "$HAS_CLIENT" == false || "$ASK_CLIENT" == true ]]; then
  say "Google sign-in client"
  cat <<EOF
Create a Web application client here:
  https://console.cloud.google.com/auth/clients?project=${PROJECT}
Press Create client, pick Web application, name it anything (for example Claude connector), and add this Authorized redirect URI:
  ${REDIRECT_URI}
Then copy the client ID and client secret Google shows you.
EOF
  read -r -p "Client ID: " CLIENT_ID
  CLIENT_ID="$(echo "$CLIENT_ID" | tr -d '[:space:]')"
  [[ "$CLIENT_ID" == *.apps.googleusercontent.com ]] || die "That doesn't look like a client ID (it ends in .apps.googleusercontent.com)."
  read -r -s -p "Client secret (hidden as you type): " CLIENT_SECRET
  echo
  CLIENT_SECRET="$(echo "$CLIENT_SECRET" | tr -d '[:space:]')"
  [[ -n "$CLIENT_SECRET" ]] || die "No client secret entered."

  DEFAULT_EMAIL="$(gcloud config get-value account 2>/dev/null || true)"
  read -r -p "Google account allowed to sign in [${DEFAULT_EMAIL}]: " ALLOWED
  ALLOWED="${ALLOWED:-$DEFAULT_EMAIL}"
  [[ -n "$ALLOWED" ]] || die "No account entered."

  TOKEN_SECRET="$(openssl rand -base64 32)"
  ENV_FILE="$(mktemp)"
  chmod 600 "$ENV_FILE"
  {
    echo "GOOGLE_CLIENT_ID: $(yaml_quote "$CLIENT_ID")"
    echo "GOOGLE_CLIENT_SECRET: $(yaml_quote "$CLIENT_SECRET")"
    echo "TOKEN_SECRET: $(yaml_quote "$TOKEN_SECRET")"
    echo "ALLOWED_EMAILS: $(yaml_quote "$ALLOWED")"
    echo "PUBLIC_BASE_URL: $(yaml_quote "$BASE_URL")"
  } >"$ENV_FILE"
  unset CLIENT_SECRET TOKEN_SECRET
  if [[ "$HAS_CLIENT" == true ]]; then
    warn "New settings replace the old ones. Claude will need to connect again."
  fi
  DEPLOY_ARGS+=(--env-vars-file "$ENV_FILE")
fi

say "Building and deploying (takes a few minutes the first time)"
gcloud run deploy "$SERVICE" "${DEPLOY_ARGS[@]}"
cleanup
ENV_FILE=""

# Cloud Run gives each service a fixed URL built from the project number. Check it is live.
URLS="$(gcloud run services describe "$SERVICE" --region "$REGION" --format=json 2>/dev/null |
  python3 -c 'import json,sys; print(" ".join(json.loads(json.load(sys.stdin)["metadata"]["annotations"].get("run.googleapis.com/urls","[]"))))' 2>/dev/null || true)"
if [[ -n "$URLS" && "$URLS" != *"$BASE_URL"* ]]; then
  ALT_URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)')"
  warn "This service's URL is $ALT_URL, not $BASE_URL. Switching to it."
  BASE_URL="$ALT_URL"
  REDIRECT_URI="${BASE_URL}/oauth/google/callback"
  gcloud run services update "$SERVICE" --region "$REGION" --update-env-vars "PUBLIC_BASE_URL=${BASE_URL}" --quiet
  warn "Add this redirect URI to the Google client too: $REDIRECT_URI"
fi

say "Keeping only the 2 newest images (stays inside the free 0.5 GB)"
POLICY_FILE="$(mktemp)"
cat >"$POLICY_FILE" <<'EOF'
[
  {"name": "keep-newest", "action": {"type": "Keep"}, "mostRecentVersions": {"keepCount": 2}},
  {"name": "delete-old", "action": {"type": "Delete"}, "condition": {"tagState": "any", "olderThan": "1d"}}
]
EOF
gcloud artifacts repositories set-cleanup-policies cloud-run-source-deploy --location "$REGION" \
  --policy "$POLICY_FILE" --no-dry-run --quiet >/dev/null ||
  warn "Couldn't set the image cleanup rule. Old images may pile up slowly."
rm -f "$POLICY_FILE"

say "Budget alert"
BUDGET_NAME="Claude Apps Script connector"
if gcloud billing budgets list --billing-account "$BILLING_ACCOUNT" --billing-project "$PROJECT" \
  --format='value(displayName)' 2>/dev/null | grep -qxF "$BUDGET_NAME"; then
  echo "Already set."
elif gcloud billing budgets create --billing-account "$BILLING_ACCOUNT" --billing-project "$PROJECT" \
  --display-name "$BUDGET_NAME" --budget-amount 1USD --filter-projects "projects/${PROJECT}" \
  --threshold-rule percent=0.01 --threshold-rule percent=1.0 >/dev/null 2>&1; then
  echo "You'll get an email if this project is charged anything (alerts at 1 cent and \$1)."
else
  warn "Couldn't create the budget alert. Make one at https://console.cloud.google.com/billing/${BILLING_ACCOUNT}/budgets"
fi

say "Checking the connector answers"
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/mcp" -H 'content-type: application/json' -d '{}' || true)"
if [[ "$CODE" == "401" ]]; then
  echo "Live. It asks for sign-in, as it should."
else
  warn "Got HTTP $CODE from ${BASE_URL}/mcp (expected 401). Logs: https://console.cloud.google.com/run/detail/${REGION}/${SERVICE}/logs?project=${PROJECT}"
fi

say "Done"
cat <<EOF
Google redirect URI:  ${REDIRECT_URI}
Connector URL:        ${BASE_URL}/mcp

Add it in Claude: https://claude.ai/customize/connectors > Add custom connector > paste the Connector URL.
EOF
