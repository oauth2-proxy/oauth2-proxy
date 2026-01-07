---
id: apple
title: Apple
---

Apple Sign in with Apple is an OIDC provider that supports authentication using Apple ID.

## Prerequisites

1. You need an Apple Developer account
2. Register an App ID in the [Apple Developer Portal](https://developer.apple.com/account/resources/identifiers/list)
3. Create a Service ID for Sign in with Apple
4. Create a private key for Sign in with Apple

## Configuration

### Step 1: Create an App ID

1. Go to [Identifiers](https://developer.apple.com/account/resources/identifiers/list) in the Apple Developer Portal
2. Click the `+` button to create a new identifier
3. Select "App IDs" and continue
4. Fill in the description and Bundle ID
5. Under Capabilities, enable "Sign in with Apple"
6. Click "Continue" and then "Register"

### Step 2: Create a Service ID

1. Go to [Identifiers](https://developer.apple.com/account/resources/identifiers/list)
2. Click the `+` button to create a new identifier
3. Select "Services IDs" and continue
4. Fill in the description and identifier (this will be your `client-id`)
5. Enable "Sign in with Apple" and click "Configure"
6. Select your Primary App ID
7. Add your domain and return URL (e.g., `https://your-domain.com/oauth2/callback`)
8. Click "Continue" and then "Register"

### Step 3: Create a Private Key

1. Go to [Keys](https://developer.apple.com/account/resources/authkeys/list)
2. Click the `+` button to create a new key
3. Enter a key name and enable "Sign in with Apple"
4. Click "Configure" and select your Primary App ID
5. Click "Continue" and then "Register"
6. Download the `.p8` private key file (you can only download it once!)
7. Note the Key ID (you'll need this for configuration)

### Step 4: Get Your Team ID

Your Team ID can be found in the top right corner of the Apple Developer Portal, or in [Membership Details](https://developer.apple.com/account/#!/membership).

## Usage

To use the Apple provider, start oauth2-proxy with `--provider=apple` and the required options:

```shell
oauth2-proxy \
  --provider=apple \
  --client-id=com.example.yourservice \
  --apple-team-id=TEAM123456 \
  --apple-key-id=KEY1234567 \
  --apple-private-key-file=/path/to/AuthKey_KEY1234567.p8 \
  --redirect-url=https://your-domain.com/oauth2/callback \
  --email-domain=* \
  --cookie-secret=your-cookie-secret
```

### Configuration Options

| Option | Description |
|--------|-------------|
| `--apple-team-id` | Your 10-character Apple Developer Team ID |
| `--apple-key-id` | The 10-character Key ID of your private key |
| `--apple-private-key-file` | Path to the `.p8` private key file |
| `--apple-private-key` | The private key content directly (alternative to file) |

**Note:** You must provide either `--apple-private-key-file` or `--apple-private-key`, but not both.

### Alpha Configuration Example

```yaml
providers:
  - id: apple
    provider: apple
    clientID: com.example.yourservice
    appleConfig:
      teamID: TEAM123456
      keyID: KEY1234567
      privateKeyFile: /path/to/AuthKey_KEY1234567.p8
```

Or with the private key content directly:

```yaml
providers:
  - id: apple
    provider: apple
    clientID: com.example.yourservice
    appleConfig:
      teamID: TEAM123456
      keyID: KEY1234567
      privateKey: |
        -----BEGIN PRIVATE KEY-----
        MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg...
        -----END PRIVATE KEY-----
```

## How It Works

Apple Sign in with Apple has some unique requirements compared to standard OIDC providers:

1. **Dynamic Client Secret**: Apple requires the `client_secret` to be a JWT signed with your private key (ES256). OAuth2-Proxy automatically generates this JWT for each token request.

2. **Form Post Response Mode**: Apple returns the authorization code via form POST rather than query parameters. OAuth2-Proxy handles this automatically.

3. **Limited User Information**: Apple only provides the user's email (and optionally name) on the first authentication. Subsequent authentications may not include the name.

## Restricting Access

Like other providers, you can restrict access using:

- `--email-domain` to allow only specific email domains
- `--authenticated-emails-file` to allow only specific email addresses

Example:
```shell
oauth2-proxy \
  --provider=apple \
  --client-id=com.example.yourservice \
  --apple-team-id=TEAM123456 \
  --apple-key-id=KEY1234567 \
  --apple-private-key-file=/path/to/key.p8 \
  --email-domain=yourcompany.com \
  --upstream=http://localhost:3000/
```
