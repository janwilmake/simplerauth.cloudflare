import {
  handleOAuth,
  handleManagement,
  getAccessToken,
  CodeDO,
  Env,
  GitHubUser,
} from "./cloudflare-oauth-provider";

export { CodeDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) return oauthResponse;

    // Handle management routes
    const managementResponse = await handleManagement(request, env);
    if (managementResponse) return managementResponse;

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/") {
      return handleHome(request, env);
    }

    if (path === "/demo") {
      return handleDemo(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

async function handleHome(request: Request, env: Env): Promise<Response> {
  const accessToken = getAccessToken(request);

  if (!accessToken) {
    return new Response(
      `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login with Cloudflare</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          .hero { text-align: center; padding: 40px 0; }
          .hero h1 { color: #f38020; font-size: 3em; margin-bottom: 20px; }
          .hero p { font-size: 1.2em; color: #666; margin-bottom: 30px; }
          .cta { background: #f38020; color: white; padding: 15px 30px; border: none; border-radius: 8px; font-size: 1.1em; cursor: pointer; text-decoration: none; display: inline-block; }
          .cta:hover { background: #e06d00; }
          .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; margin: 40px 0; }
          .feature { background: #f8f9fa; padding: 20px; border-radius: 8px; }
          .feature h3 { color: #f38020; margin-bottom: 10px; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin: 20px 0; }
          .warning strong { color: #856404; }
          .code { background: #f8f9fa; padding: 15px; border-radius: 8px; font-family: monospace; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="hero">
          <h1>🔐 Login with Cloudflare</h1>
          <p>Securely provide your Cloudflare API keys to trusted applications</p>
          <a href="/authorize" class="cta">Get Started</a>
        </div>

        <div class="features">
          <div class="feature">
            <h3>🔒 Secure Authentication</h3>
            <p>Login with your GitHub account, then securely manage your Cloudflare API keys.</p>
          </div>
          <div class="feature">
            <h3>🎯 Selective Access</h3>
            <p>Choose which API key to share with each application. Full control over your credentials.</p>
          </div>
          <div class="feature">
            <h3>📊 Usage Tracking</h3>
            <p>See when and how your API keys are being used by different applications.</p>
          </div>
        </div>

        <div class="warning">
          <strong>⚠️ Important:</strong> This service provides your actual Cloudflare API keys to applications. 
          Only use with applications you completely trust. We recommend creating dedicated API tokens 
          with limited permissions for each application.
        </div>

        <h2>How it works</h2>
        <ol>
          <li>Login with your GitHub account</li>
          <li>Add your Cloudflare API keys and account IDs</li>
          <li>When apps request access, choose which key to share</li>
          <li>The app receives your API key directly</li>
        </ol>

        <h2>For Developers</h2>
        <p>Integrate with Login with Cloudflare using standard OAuth 2.0:</p>
        <div class="code">
          # Authorization URL
          https://cloudflare.simplerauth.com/authorize?client_id=yourdomain.com&redirect_uri=https://yourdomain.com/callback&response_type=code
          
          # Token exchange
          POST https://cloudflare.simplerauth.com/token
          Content-Type: application/x-www-form-urlencoded
          
          grant_type=authorization_code&code=AUTH_CODE&client_id=yourdomain.com&redirect_uri=https://yourdomain.com/callback
        </div>
        
        <p>The token response includes:</p>
        <div class="code">
          {
            "access_token": "...",
            "token_type": "bearer",
            "cloudflare_account_id": "account123",
            "cloudflare_api_key": "token456",
            "cloudflare_key_name": "My API Key"
          }
        </div>

        <p><a href="/demo">Try the OAuth demo</a></p>
      </body>
      </html>
    `,
      {
        headers: { "Content-Type": "text/html" },
      },
    );
  }

  // User is authenticated, show dashboard
  const userDOId = env.CODES.idFromName(`user:${accessToken}`);
  const userDO = env.CODES.get(userDOId);
  const userData = await userDO.getUser();
  const keys = await userDO.getCloudflareKeys();

  if (!userData) {
    return new Response("User not found", { status: 404 });
  }

  const { user } = userData;

  return new Response(
    `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login with Cloudflare - Dashboard</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .user-info { background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #f38020; }
        .stat-label { color: #666; }
        .nav { margin-bottom: 20px; }
        .nav a { color: #007bff; text-decoration: none; margin-right: 20px; }
        .nav a:hover { text-decoration: underline; }
        .cta { background: #f38020; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .cta:hover { background: #e06d00; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="/manage">Manage API Keys</a>
        <a href="/demo">OAuth Demo</a>
        <a href="/logout">Logout</a>
      </div>

      <h1>Dashboard</h1>
      
      <div class="user-info">
        <img src="${user.avatar_url}" alt="${
      user.name || user.login
    }" width="40" height="40" style="border-radius: 50%; vertical-align: middle; margin-right: 10px;">
        <strong>${user.name || user.login}</strong>
      </div>

      <div class="stats">
        <div class="stat">
          <div class="stat-number">${keys.length}</div>
          <div class="stat-label">API Keys</div>
        </div>
        <div class="stat">
          <div class="stat-number">${
            keys.filter((k) => k.lastUsed).length
          }</div>
          <div class="stat-label">Used Keys</div>
        </div>
      </div>

      <h2>Quick Actions</h2>
      <p>
        <a href="/manage" class="cta">Manage API Keys</a>
        <a href="/demo" class="cta" style="background: #007bff; margin-left: 10px;">Test OAuth Flow</a>
      </p>

      <h2>Recent Activity</h2>
      ${
        keys.length > 0
          ? `
        <ul>
          ${keys
            .filter((k) => k.lastUsed)
            .sort(
              (a, b) =>
                new Date(b.lastUsed!).getTime() -
                new Date(a.lastUsed!).getTime(),
            )
            .slice(0, 5)
            .map(
              (key) => `
            <li><strong>${key.name}</strong> - Last used ${new Date(
                key.lastUsed!,
              ).toLocaleDateString()}</li>
          `,
            )
            .join("")}
        </ul>
      `
          : '<p>No API keys added yet. <a href="/manage">Add your first key</a>.</p>'
      }
    </body>
    </html>
  `,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}

async function handleDemo(request: Request, env: Env): Promise<Response> {
  return new Response(
    `
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Demo - Login with Cloudflare</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .code { background: #f8f9fa; padding: 15px; border-radius: 8px; font-family: monospace; margin: 10px 0; white-space: pre-wrap; }
        .nav { margin-bottom: 20px; }
        .nav a { color: #007bff; text-decoration: none; margin-right: 20px; }
        .nav a:hover { text-decoration: underline; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        #result { margin-top: 20px; padding: 15px; border-radius: 8px; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="/">Home</a>
        <a href="/manage">Manage Keys</a>
        <a href="/logout">Logout</a>
      </div>

      <h1>OAuth Demo</h1>
      <p>This demo shows how other applications can integrate with Login with Cloudflare.</p>

      <h2>Step 1: Authorization</h2>
      <p>Click this button to start the OAuth flow as if you were a third-party application:</p>
      <button onclick="startOAuth()">Start OAuth Flow</button>

      <h2>Step 2: Token Exchange</h2>
      <p>After authorization, the code will be exchanged for an access token automatically.</p>

      <h2>Step 3: Result</h2>
      <div id="result"></div>

      <h2>Implementation Example</h2>
      <div class="code">// 1. Redirect user to authorize endpoint
const authUrl = new URL('https://cloudflare.simplerauth.com/authorize');
authUrl.searchParams.set('client_id', 'yourdomain.com');
authUrl.searchParams.set('redirect_uri', 'https://yourdomain.com/callback');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('state', 'random-state-string');
window.location.href = authUrl.toString();

// 2. Handle callback and exchange code for token
const response = await fetch('https://cloudflare.simplerauth.com/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: 'AUTH_CODE_FROM_CALLBACK',
    client_id: 'yourdomain.com',
    redirect_uri: 'https://yourdomain.com/callback'
  })
});

const data = await response.json();
// data.cloudflare_api_key contains the user's API key
// data.cloudflare_account_id contains the account ID</div>

      <script>
        const CLIENT_ID = window.location.hostname;
        const REDIRECT_URI = window.location.origin + '/demo';

        function startOAuth() {
          const authUrl = new URL('${new URL(request.url).origin}/authorize');
          authUrl.searchParams.set('client_id', CLIENT_ID);
          authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
          authUrl.searchParams.set('response_type', 'code');
          authUrl.searchParams.set('state', Math.random().toString(36));
          
          window.location.href = authUrl.toString();
        }

        // Handle OAuth callback
        async function handleCallback() {
          const urlParams = new URLSearchParams(window.location.search);
          const code = urlParams.get('code');
          const state = urlParams.get('state');

          if (code) {
            try {
              const response = await fetch('${
                new URL(request.url).origin
              }/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                  grant_type: 'authorization_code',
                  code: code,
                  client_id: CLIENT_ID,
                  redirect_uri: REDIRECT_URI
                })
              });

              const data = await response.json();
              
              if (data.cloudflare_api_key) {
                document.getElementById('result').innerHTML = \`
                  <div class="success">
                    <h3>✅ Success!</h3>
                    <p><strong>Key Name:</strong> \${data.cloudflare_key_name}</p>
                    <p><strong>Account ID:</strong> \${data.cloudflare_account_id}</p>
                    <p><strong>API Key:</strong> \${data.cloudflare_api_key.substring(0, 20)}...</p>
                    <p><em>In a real application, you would now use these credentials to access the Cloudflare API.</em></p>
                  </div>
                \`;
              } else {
                document.getElementById('result').innerHTML = \`
                  <div class="error">
                    <h3>❌ Error</h3>
                    <p>Token exchange failed: \${JSON.stringify(data)}</p>
                  </div>
                \`;
              }
            } catch (error) {
              document.getElementById('result').innerHTML = \`
                <div class="error">
                  <h3>❌ Error</h3>
                  <p>Token exchange failed: \${error.message}</p>
                </div>
              \`;
            }

            // Clean up URL
            window.history.replaceState({}, document.title, window.location.pathname);
          }
        }

        // Check for OAuth callback on page load
        handleCallback();
      </script>
    </body>
    </html>
  `,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}
