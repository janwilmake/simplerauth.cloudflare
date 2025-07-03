# Login with Cloudflare

A secure OAuth provider that allows users to authenticate with GitHub and then provide their Cloudflare API keys to trusted applications.

## 🚀 Features

- **GitHub Authentication**: Users login with their GitHub account
- **Secure API Key Management**: Users can add, manage, and remove their Cloudflare API keys
- **Selective Access**: Users choose which API key to share with each requesting application
- **Usage Tracking**: See when and how API keys are being used
- **Standard OAuth 2.0**: Easy integration for developers using standard OAuth flow

## 🔧 Setup

### 1. Prerequisites

- Cloudflare Workers account
- GitHub OAuth application
- Node.js and npm/yarn

### 2. GitHub OAuth App Setup

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the details:
   - **Application name**: Login with Cloudflare
   - **Homepage URL**: `https://cloudflare.simplerauth.com`
   - **Authorization callback URL**: `https://cloudflare.simplerauth.com/callback`
4. Note down your `Client ID` and `Client Secret`

### 3. Cloudflare Workers Setup

1. Clone this repository
2. Install dependencies:

   ```bash
   npm install
   ```

3. Set up your secrets:

   ```bash
   wrangler secret put GITHUB_CLIENT_ID
   wrangler secret put GITHUB_CLIENT_SECRET
   ```

4. Deploy to Cloudflare Workers:

   ```bash
   wrangler deploy
   ```

5. Update your `wrangler.toml` with your custom domain:
   ```toml
   routes = [
     { pattern = "cloudflare.simplerauth.com", custom_domain = true }
   ]
   ```

## 💻 For Users

### How to Use

1. **Login**: Visit [cloudflare.simplerauth.com](https://cloudflare.simplerauth.com) and click "Get Started"
2. **Authenticate**: Login with your GitHub account
3. **Add API Keys**: Go to "Manage API Keys" and add your Cloudflare API tokens
4. **Grant Access**: When apps request access, choose which API key to share

### Getting Your Cloudflare API Key

1. Go to [Cloudflare Dashboard → My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click "Create Token" and choose "Custom token"
3. Configure the token with the permissions you want to grant
4. Copy the token and your Account ID (shown in the right sidebar)

### Security Best Practices

- ⚠️ **Only grant access to applications you completely trust**
- 🔑 **Create dedicated API tokens with minimal required permissions**
- 📊 **Regularly review token usage in your dashboard**
- 🗑️ **Remove unused tokens from your account**

## 🛠️ For Developers

### Integration

Login with Cloudflare uses standard OAuth 2.0 flow. Here's how to integrate:

#### 1. Authorization Request

Redirect users to the authorization endpoint:

```javascript
const authUrl = new URL("https://cloudflare.simplerauth.com/authorize");
authUrl.searchParams.set("client_id", "yourdomain.com"); // Your domain
authUrl.searchParams.set("redirect_uri", "https://yourdomain.com/callback");
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("state", "random-state-string"); // CSRF protection

window.location.href = authUrl.toString();
```

#### 2. Handle Authorization Callback

After the user grants access, they'll be redirected to your `redirect_uri` with a code:

```
https://yourdomain.com/callback?code=AUTH_CODE&state=YOUR_STATE
```

#### 3. Exchange Code for Token

Make a POST request to exchange the authorization code for an access token:

```javascript
const response = await fetch("https://cloudflare.simplerauth.com/token", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: "AUTH_CODE_FROM_CALLBACK",
    client_id: "yourdomain.com",
    redirect_uri: "https://yourdomain.com/callback",
  }),
});

const data = await response.json();
```

#### 4. Token Response

The response includes the user's selected Cloudflare credentials:

```json
{
  "access_token": "encrypted_token_for_your_app",
  "token_type": "bearer",
  "scope": "user:email",
  "cloudflare_account_id": "1234567890abcdef1234567890abcdef",
  "cloudflare_api_key": "your-users-api-token",
  "cloudflare_key_name": "User's Key Name"
}
```

#### 5. Use Cloudflare API

Now you can use the provided credentials to access the Cloudflare API:

```javascript
const cfResponse = await fetch(
  `https://api.cloudflare.com/client/v4/accounts/${data.cloudflare_account_id}/zones`,
  {
    headers: {
      Authorization: `Bearer ${data.cloudflare_api_key}`,
      "Content-Type": "application/json",
    },
  },
);
```

### Client Registration

Unlike traditional OAuth providers, Login with Cloudflare doesn't require client registration. Your domain name serves as your client ID, and redirect URIs are automatically validated to ensure they're on the same domain.

### Security Considerations

- **Domain Validation**: Client IDs must be valid domains, and redirect URIs must be HTTPS and on the same domain
- **No Client Secrets**: This is a public client flow - no client secrets needed
- **CSRF Protection**: Always use the `state` parameter for CSRF protection
- **HTTPS Required**: All redirect URIs must use HTTPS (except localhost for development)

### Example Implementation

Check out the `/demo` endpoint on the deployed service to see a working example of the OAuth flow.

## 🔒 Security

### For Users

- API keys are encrypted at rest using AES-GCM with PBKDF2 key derivation
- Only you can see and manage your API keys
- Applications receive your actual API keys - only share with trusted apps
- GitHub authentication ensures only you can access your account

### For Developers

- Standard OAuth 2.0 flow with PKCE support
- Domain-based client validation
- CSRF protection via state parameter
- Encrypted token storage
- No client secrets required (public client model)

## 📊 Monitoring

Users can monitor their API key usage through the dashboard:

- View all registered API keys
- See when each key was last used
- Track which applications are using which keys
- Remove API keys that are no longer needed

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

- **Documentation**: This README and inline code comments
- **Demo**: Try the OAuth flow at `/demo`
- **Issues**: Report bugs via GitHub Issues

---

**⚠️ Important Security Notice**: This service provides direct access to users' Cloudflare API keys. Applications receive the actual API tokens with full permissions. Only use this service with applications you completely trust, and consider creating API tokens with minimal required permissions for each application.
