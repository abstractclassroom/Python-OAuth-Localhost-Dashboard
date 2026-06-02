# Python OAuth (GitHub) with API Gateway + Lambda

This repo shows a minimal GitHub OAuth login flow using a single AWS Lambda behind API Gateway.

Base URL for this class demo:

- `https://8jqr6mgxui.execute-api.us-east-1.amazonaws.com/Production/<action>`

Endpoints:

- `.../login` shows a page with a GitHub SSO button
- `.../go` redirects to GitHub SSO
- `.../callback` handles the OAuth redirect and displays a simple page

## Files

- `app.py` Lambda handler
- `config.py` base URL + GitHub client id + state secret

## GitHub configuration (OAuth App)

1. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App
2. Set:
   - Homepage URL: `https://8jqr6mgxui.execute-api.us-east-1.amazonaws.com/Production/`
   - Authorization callback URL: `https://8jqr6mgxui.execute-api.us-east-1.amazonaws.com/Production/callback`
3. Create the app.

## AWS configuration

### Lambda

- Runtime: Python 3.11 (or 3.12)
- Handler: `app.lambda_handler`
- Environment variables:
  - `GITHUB_CLIENT_SECRET` = the OAuth app client secret

The client id and base URL are kept in `config.py`.

### API Gateway

Use a single wildcard route that forwards everything to the Lambda.

HTTP API:

- Route: `GET /{proxy+}` → Lambda integration
- Deploy to stage `Production`

(REST API works too as long as the Lambda receives `path` or `rawPath`.)

## Try it

Visit:

- `https://8jqr6mgxui.execute-api.us-east-1.amazonaws.com/Production/login`

Click the button to start GitHub login. After GitHub login, you’ll be redirected to `/Production/callback` and see a page with the user’s name, username, and avatar.
