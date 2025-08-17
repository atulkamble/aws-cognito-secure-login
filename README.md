# 🔐 Project #2: Build a Secure Login System Using Amazon Cognito

A complete, end‑to‑end reference project that provisions a Cognito **User Pool** with **MFA**, a **Hosted UI** (optional), an **API Gateway + Lambda** backend protected by a **Cognito Authorizer**, and a minimal **frontend** that signs up/signs in users and calls the protected API with the ID token.

---

## 🗂 Repository Layout

```
aws-cognito-secure-login/
├─ infra/terraform/
│  ├─ main.tf
│  ├─ variables.tf
│  ├─ outputs.tf
│  └─ README.md
├─ backend/
│  ├─ lambda_handler.py
│  └─ requirements.txt
├─ frontend/
│  ├─ index.html
│  ├─ app.js
│  └─ README.md
└─ README.md
```

---

## 🚀 What You’ll Learn

* Create and configure a **Cognito User Pool** and **App Client** (no secret)
* Enforce **MFA** (TOTP by default; SMS optional)
* Configure **Cognito Hosted UI** with your own domain prefix
* Protect an **API Gateway** with a **Cognito Authorizer** and call it from the frontend
* Use **IAM roles** to restrict Lambda to authenticated users (context claims)
* Local + CLI flows for **TOTP registration** and **testing**

---

## ✅ Prerequisites

* AWS account with admin access
* Terraform ≥ 1.5, AWS CLI ≥ 2.15, Python ≥ 3.9
* An S3 bucket to store Terraform state (or switch backend to local)

---

# 1) Infrastructure as Code (Terraform)

Create files under `infra/terraform/` as below. Update `region`, `email` (for SES/SMS if using SMS), and the `domain_prefix` to something globally unique.

### `main.tf`

```hcl
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40"
    }
  }
}

provider "aws" {
  region = var.region
}

# ------------------ Cognito User Pool ------------------
resource "aws_cognito_user_pool" "this" {
  name = "${var.project_name}-user-pool"

  # Enforce strong password policy
  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  mfa_configuration = "ON" # enforce MFA

  software_token_mfa_configuration {
    enabled = true
  }

  # Optional: enable SMS MFA (requires SNS SMS role/quota)
  # sms_configuration {
  #   external_id    = "${var.project_name}-sms-external-id"
  #   sns_caller_arn = aws_iam_role.cognito_sns_role.arn
  # }

  auto_verified_attributes = ["email"]

  schema {
    name                     = "email"
    attribute_data_type      = "String"
    required                 = true
    developer_only_attribute = false
    mutable                  = true
    string_attribute_constraints { min_length = 5 max_length = 2048 }
  }
}

resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.domain_prefix
  user_pool_id = aws_cognito_user_pool.this.id
}

resource "aws_cognito_user_pool_client" "web" {
  name         = "${var.project_name}-web-client"
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret = false # public SPA/JS client

  supported_identity_providers = ["COGNITO"]
  allowed_oauth_flows          = ["code"]
  allowed_oauth_scopes         = ["email", "openid", "profile"]
  allowed_oauth_flows_user_pool_client = true

  callback_urls = [var.callback_url]
  logout_urls   = [var.logout_url]

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_USER_PASSWORD_AUTH"
  ]
  prevent_user_existence_errors = "ENABLED"
}

# ------------------ Backend: Lambda + API Gateway ------------------
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "hello" {
  function_name = "${var.project_name}-hello"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "lambda_handler.lambda_handler"
  runtime       = "python3.11"
  filename      = "${path.module}/../..//backend/hello.zip"
  source_code_hash = filebase64sha256("${path.module}/../..//backend/hello.zip")
  environment {
    variables = {
      PROJECT_NAME = var.project_name
    }
  }
}

resource "aws_apigatewayv2_api" "http" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
}

# Cognito Authorizer for HTTP API (JWT Authorizer)
resource "aws_apigatewayv2_authorizer" "cognito_jwt" {
  api_id           = aws_apigatewayv2_api.http.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "cognito-jwt"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.web.id]
    issuer   = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.region}.amazoncognito.com"
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.hello.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "hello" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /hello"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorizer_id = aws_apigatewayv2_authorizer.cognito_jwt.id
  authorization_type = "JWT"
}

resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.hello.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
}

# (Optional) Role for Cognito SMS if enabling SMS MFA
resource "aws_iam_role" "cognito_sns_role" {
  count = var.enable_sms_mfa ? 1 : 0
  name  = "${var.project_name}-cognito-sns-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "cognito-idp.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "cognito_sns_policy" {
  count = var.enable_sms_mfa ? 1 : 0
  name  = "${var.project_name}-cognito-sns-policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = ["sns:Publish"],
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_sns" {
  count      = var.enable_sms_mfa ? 1 : 0
  role       = aws_iam_role.cognito_sns_role[0].name
  policy_arn = aws_iam_policy.cognito_sns_policy[0].arn
}
```

### `variables.tf`

```hcl
variable "project_name" { type = string default = "cognito-secure-login" }
variable "region"       { type = string default = "us-east-1" }

# For Hosted UI (use your local dev URL or actual domain)
variable "callback_url" { type = string default = "http://localhost:5500/" }
variable "logout_url"   { type = string default = "http://localhost:5500/" }

# Must be globally unique across Cognito domains
variable "domain_prefix" { type = string default = "cognito-secure-login-demo-1234" }

variable "enable_sms_mfa" { type = bool default = false }
```

### `outputs.tf`

```hcl
output "user_pool_id" { value = aws_cognito_user_pool.this.id }
output "user_pool_client_id" { value = aws_cognito_user_pool_client.web.id }
output "cognito_domain" { value = aws_cognito_user_pool_domain.this.domain }
output "issuer" { value = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.region}.amazoncognito.com" }
output "api_invoke_url" { value = aws_apigatewayv2_api.http.api_endpoint }
```

### `infra/terraform/README.md`

```md
# Deploy Infra

# 0) (Optional) Create Lambda package
cd ../../backend
pip install -r requirements.txt -t .
zip -r hello.zip . -x "__pycache__/*"
mkdir -p ../infra/terraform/../../backend && mv hello.zip ../infra/terraform/../../backend/hello.zip

# 1) Init/apply Terraform
cd ../infra/terraform
terraform init
terraform apply -auto-approve

# 2) Note outputs
# - user_pool_id
# - user_pool_client_id
# - cognito_domain
# - api_invoke_url
```

---

# 2) Backend (Lambda)

Create files under `backend/`:

### `lambda_handler.py`

```python
import json
import os

def lambda_handler(event, context):
    # event['requestContext']['authorizer']['jwt']['claims'] is available for JWT authorizer
    claims = (event.get("requestContext", {})
                    .get("authorizer", {})
                    .get("jwt", {})
                    .get("claims", {}))

    username = claims.get("cognito:username", "anonymous")
    project = os.environ.get("PROJECT_NAME", "cognito-secure-login")

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "message": f"Hello, {username}! Your call to {project} is authorized.",
            "claims": {k: claims[k] for k in ["sub", "email", "cognito:username"] if k in claims}
        })
    }
```

### `requirements.txt`

```
# (empty) – standard library only
```

> **Package & copy**: See the packaging step in `infra/terraform/README.md`.

---

# 3) Frontend (Vanilla JS + Hosted UI or SRP)

This minimal frontend uses **Hosted UI OAuth Code Flow** (recommended). It reads the `id_token` from the URL after Cognito redirects back, stores it, and calls the protected API.

Create files under `frontend/`:

### `index.html`

```html
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Cognito Secure Login Demo</title>
    <style>
      body{font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin:2rem;}
      button{padding:10px 16px; margin:8px;}
      pre{background:#f5f5f5; padding:12px; border-radius:8px;}
    </style>
  </head>
  <body>
    <h1>🔐 Cognito Secure Login Demo</h1>

    <div>
      <button id="loginBtn">Login (Hosted UI)</button>
      <button id="logoutBtn">Logout</button>
      <button id="callApiBtn">Call Protected API</button>
    </div>

    <h3>Tokens</h3>
    <pre id="tokens">(none)</pre>

    <h3>API Response</h3>
    <pre id="apiResp">(none)</pre>

    <script src="app.js"></script>
  </body>
</html>
```

### `app.js`

```javascript
// ---- Replace with Terraform outputs ----
const region = "us-east-1";                  // var.region
const domain = "cognito-secure-login-demo-1234"; // output.cognito_domain
const clientId = "<USER_POOL_CLIENT_ID>";    // output.user_pool_client_id
const redirectUri = window.location.origin + "/"; // var.callback_url
const apiBase = "<API_INVOKE_URL>";          // output.api_invoke_url

const authEndpoint = `https://${domain}.auth.${region}.amazoncognito.com/oauth2/authorize`;
const tokenEndpoint = `https://${domain}.auth.${region}.amazoncognito.com/oauth2/token`;
const logoutEndpoint = `https://${domain}.auth.${region}.amazoncognito.com/logout`;

const tokensEl = document.getElementById('tokens');
const apiRespEl = document.getElementById('apiResp');

function toParams(hash) {
  const p = new URLSearchParams(hash);
  return Object.fromEntries(p.entries());
}

function saveTokens(obj) {
  if (obj) localStorage.setItem('tokens', JSON.stringify(obj));
  const t = JSON.parse(localStorage.getItem('tokens') || 'null');
  tokensEl.textContent = t ? JSON.stringify({ id_token: t.id_token?.slice(0,30)+"...", access_token: t.access_token?.slice(0,30)+"..." }, null, 2) : '(none)';
}

async function exchangeCodeForTokens(code) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: redirectUri
  });
  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
  if (!res.ok) throw new Error('Token exchange failed');
  const data = await res.json();
  saveTokens(data);
}

// Handle OAuth code returned to /?code=...
(async function init(){
  const url = new URL(window.location.href);
  const code = url.searchParams.get('code');
  if (code) {
    await exchangeCodeForTokens(code);
    // clean URL
    history.replaceState({}, document.title, redirectUri);
  }
  saveTokens();
})();

// Login via Hosted UI
document.getElementById('loginBtn').onclick = () => {
  const loginUrl = `${authEndpoint}?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=openid+email+profile`;
  window.location = loginUrl;
};

// Logout
document.getElementById('logoutBtn').onclick = () => {
  localStorage.removeItem('tokens');
  saveTokens();
  const url = `${logoutEndpoint}?client_id=${clientId}&logout_uri=${encodeURIComponent(redirectUri)}`;
  window.location = url;
};

// Call protected API using ID token (JWT Authorizer expects ID token audience)
// Note: Depending on authorizer config, you may also use access_token.

document.getElementById('callApiBtn').onclick = async () => {
  const tok = JSON.parse(localStorage.getItem('tokens') || 'null');
  if (!tok?.id_token) {
    apiRespEl.textContent = 'No id_token; login first.';
    return;
  }
  const res = await fetch(`${apiBase}/hello`, {
    headers: { 'Authorization': tok.id_token }
  });
  apiRespEl.textContent = await res.text();
};
```

### `frontend/README.md`

```md
# Run Frontend

# Simple local server
npx serve . -p 5500
# or
python3 -m http.server 5500

# Update app.js with values from terraform outputs
# - domain (cognito_domain)
# - clientId (user_pool_client_id)
# - apiBase (api_invoke_url)
```

---

# 4) End‑to‑End Setup Steps

1. **Package Lambda & Deploy Terraform**

   * Follow `infra/terraform/README.md` to zip Lambda and run `terraform apply`.
2. **Update Frontend**

   * Put `cognito_domain`, `user_pool_client_id`, and `api_invoke_url` into `frontend/app.js`.
3. **Run Frontend**

   * Start a local web server at `http://localhost:5500/`.
   * Click **Login** → complete sign‑up/sign‑in (Hosted UI).
   * After login + MFA, the URL returns with `?code=...` → frontend exchanges code → **Call Protected API**.

> **Note**: MFA is **ON** (software token). On first sign‑in Cognito will prompt to set up a TOTP authenticator (Google Authenticator, 1Password, etc.).

---

# 5) (Optional) Admin & CLI Helpers

### Create a test user (admin‑create)

```bash
aws cognito-idp admin-create-user \
  --user-pool-id $(terraform -chdir=infra/terraform output -raw user_pool_id) \
  --username testuser@example.com \
  --user-attributes Name=email,Value=testuser@example.com \
  --message-action SUPPRESS

# set password
aws cognito-idp admin-set-user-password \
  --user-pool-id $(terraform -chdir=infra/terraform output -raw user_pool_id) \
  --username testuser@example.com \
  --password 'StrongP@ssw0rd!' --permanent
```

### Associate and verify TOTP via CLI (advanced)

```bash
# Initiate auth (SRP or USER_PASSWORD_AUTH); here we use USER_PASSWORD_AUTH for demo
CLIENT_ID=$(terraform -chdir=infra/terraform output -raw user_pool_client_id)
USER="testuser@example.com"
PASS='StrongP@ssw0rd!'

# 1) Initiate auth → returns Session
aws cognito-idp initiate-auth --client-id $CLIENT_ID --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=$USER,PASSWORD=$PASS > resp.json
SESSION=$(jq -r .Session resp.json)

# 2) Associate software token → returns secret code (use to set up TOTP in your authenticator)
aws cognito-idp associate-software-token --session "$SESSION" > totp.json
SECRET=$(jq -r .SecretCode totp.json)
echo "Add this TOTP secret to your authenticator: $SECRET"

# 3) Enter current 6‑digit code from authenticator
CODE=123456
aws cognito-idp verify-software-token --user-code $CODE --session "$SESSION" --friendly-device-name "Laptop"

# 4) Respond to MFA challenge
aws cognito-idp respond-to-auth-challenge --client-id $CLIENT_ID \
  --challenge-name SOFTWARE_TOKEN_MFA \
  --challenge-responses USERNAME=$USER,SOFTWARE_TOKEN_MFA_CODE=$CODE \
  --session "$SESSION"
```

---

# 6) IAM Enforcement Tips

* The **API Gateway JWT authorizer** validates the token’s **issuer** and **audience (client id)**.
* Inside Lambda, read `event.requestContext.authorizer.jwt.claims` to make authorization decisions (e.g., check `cognito:groups`).
* To **restrict actions** by group/role, create Cognito **Groups**, attach IAM roles, and enable **role-based access** (token contains `cognito:groups`).

Example group check in Lambda:

```python
claims = event.get('requestContext',{}).get('authorizer',{}).get('jwt',{}).get('claims',{})
if 'admins' not in claims.get('cognito:groups',''):
    return { 'statusCode': 403, 'body': 'Forbidden' }
```

---

# 7) Security Best Practices

* Use **Hosted UI + OAuth Code Flow** for SPAs (don’t keep client secret in frontend).
* Enforce **MFA** (already ON). Consider **Adaptive Auth** via Risk Settings (Console).
* Set **refresh token** validity to minimal acceptable (default 30 days; can reduce).
* Configure **allowed callback/logout URLs** precisely for each environment.
* For production domains, use **custom domain** for Cognito with ACM certificate.
* Rotate and scope **IAM policies** for Lambda to least privilege.

---

# 8) Troubleshooting

* **`NotAuthorizedException: Invalid token`** → Ensure you pass **ID token** to API when authorizer is configured for `audience = clientId` of the User Pool client.
* **Callback URL mismatch** → Make sure `variables.tf` `callback_url` exactly matches your local server origin.
* **MFA challenge loop** → Ensure device TOTP is verified and time is in sync.
* **403 from API** → Missing/incorrect `Authorization` header or using `access_token` when authorizer expects `id_token`.

---

# 9) Clean Up

```bash
terraform -chdir=infra/terraform destroy -auto-approve
```

---

## 📌 Next Extensions

* Add **Cognito Triggers** (PreSignUp, PostConfirmation) via Lambda for custom workflows
* Add **Cognito Identity Pools** to obtain temporary AWS credentials (S3 uploads from browser)
* Add **groups & RBAC** with `cognito:groups` claim and per-route authorization
* Replace vanilla JS frontend with **React + Amplify** and advanced UI flows
