import { DurableObject } from "cloudflare:workers";

export interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  CODES: DurableObjectNamespace<CodeDO>;
}

interface OAuthState {
  redirectTo?: string;
  codeVerifier: string;
  resource?: string;
}

export interface GitHubUser {
  id: number;
  login: string;
  name: string;
  email: string;
  avatar_url: string;
  [key: string]: any;
}

export interface CloudflareAPIKey {
  id: string;
  name: string;
  accountId: string;
  apiKey: string;
  createdAt: string;
  lastUsed?: string;
}

export class CodeDO extends DurableObject {
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.storage = state.storage;
    // Set alarm for 10 minutes from now for auth codes
    this.storage.setAlarm(Date.now() + 10 * 60 * 1000);
  }

  async alarm() {
    // Only self-delete if this is not a user storage (auth codes expire, users don't)
    const user = await this.storage.get("user");
    if (!user) {
      await this.storage.deleteAll();
    }
  }

  async setAuthData(
    githubAccessToken: string,
    encryptedAccessToken: string,
    clientId: string,
    redirectUri: string,
    selectedKeyId?: string,
    resource?: string,
  ) {
    await this.storage.put("data", {
      github_access_token: githubAccessToken,
      access_token: encryptedAccessToken,
      clientId,
      redirectUri,
      selectedKeyId,
      resource,
    });
  }

  async getAuthData() {
    return this.storage.get<{
      github_access_token: string;
      access_token: string;
      clientId: string;
      redirectUri: string;
      selectedKeyId?: string;
      resource?: string;
    }>("data");
  }

  async setUser(
    user: GitHubUser,
    githubAccessToken: string,
    encryptedAccessToken: string,
  ) {
    await this.storage.put("user", user);
    await this.storage.put("github_access_token", githubAccessToken);
    await this.storage.put("access_token", encryptedAccessToken);
  }

  async getUser(): Promise<{
    user: GitHubUser;
    githubAccessToken: string;
    accessToken: string;
  } | null> {
    const user = await this.storage.get<GitHubUser>("user");
    const githubAccessToken = await this.storage.get<string>(
      "github_access_token",
    );
    const accessToken = await this.storage.get<string>("access_token");

    if (!user || !githubAccessToken || !accessToken) {
      return null;
    }

    return {
      user,
      githubAccessToken,
      accessToken,
    };
  }

  async addCloudflareKey(key: CloudflareAPIKey) {
    const keys =
      (await this.storage.get<CloudflareAPIKey[]>("cloudflare_keys")) || [];
    keys.push(key);
    await this.storage.put("cloudflare_keys", keys);
  }

  async getCloudflareKeys(): Promise<CloudflareAPIKey[]> {
    return (
      (await this.storage.get<CloudflareAPIKey[]>("cloudflare_keys")) || []
    );
  }

  async updateKeyLastUsed(keyId: string) {
    const keys =
      (await this.storage.get<CloudflareAPIKey[]>("cloudflare_keys")) || [];
    const keyIndex = keys.findIndex((k) => k.id === keyId);
    if (keyIndex !== -1) {
      keys[keyIndex].lastUsed = new Date().toISOString();
      await this.storage.put("cloudflare_keys", keys);
    }
  }

  async removeCloudflareKey(keyId: string) {
    const keys =
      (await this.storage.get<CloudflareAPIKey[]>("cloudflare_keys")) || [];
    const filteredKeys = keys.filter((k) => k.id !== keyId);
    await this.storage.put("cloudflare_keys", filteredKeys);
  }
}

export async function handleOAuth(
  request: Request,
  env: Env,
  scope = "user:email",
  sameSite: "Strict" | "Lax" = "Lax",
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET || !env.CODES) {
    return new Response(
      `Environment misconfigured. Ensure to have GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET secrets set, as well as the CODES DO binding.`,
      { status: 500 },
    );
  }

  // OAuth metadata endpoints
  if (path === "/.well-known/oauth-authorization-server") {
    return handleAuthorizationServerMetadata(request, env);
  }

  if (path === "/.well-known/oauth-protected-resource") {
    return handleProtectedResourceMetadata(request, env);
  }

  if (path === "/token") {
    return handleToken(request, env, scope);
  }

  if (path === "/authorize") {
    return handleAuthorize(request, env, scope, sameSite);
  }

  if (path === "/callback") {
    return handleCallback(request, env, sameSite);
  }

  if (path === "/logout") {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    return new Response(null, {
      status: 302,
      headers: {
        Location: redirectTo,
        "Set-Cookie": `access_token=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      },
    });
  }

  return null;
}

function handleAuthorizationServerMetadata(
  request: Request,
  env: Env,
): Response {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const metadata = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["user:email"],
    token_endpoint_auth_methods_supported: ["none"],
  };

  return new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

function handleProtectedResourceMetadata(request: Request, env: Env): Response {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const metadata = {
    resource: baseUrl,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    resource_documentation: `${baseUrl}`,
  };

  return new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

async function handleAuthorize(
  request: Request,
  env: Env,
  scope: string,
  sameSite: string,
): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  let redirectUri = url.searchParams.get("redirect_uri");
  const responseType = url.searchParams.get("response_type") || "code";
  const state = url.searchParams.get("state");
  const resource = url.searchParams.get("resource");

  // If no client_id, this is a direct login request
  if (!clientId) {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    const resource = url.searchParams.get("resource");

    // Generate PKCE code verifier and challenge
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    const state: OAuthState = { redirectTo, codeVerifier, resource };
    const stateString = btoa(JSON.stringify(state));

    // Build GitHub OAuth URL
    const githubUrl = new URL("https://github.com/login/oauth/authorize");
    githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
    githubUrl.searchParams.set("scope", scope);
    githubUrl.searchParams.set("state", stateString);
    githubUrl.searchParams.set("code_challenge", codeChallenge);
    githubUrl.searchParams.set("code_challenge_method", "S256");

    return new Response(null, {
      status: 302,
      headers: {
        Location: githubUrl.toString(),
        "Set-Cookie": `oauth_state=${encodeURIComponent(
          stateString,
        )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
      },
    });
  }

  // Validate client_id
  if (!isValidDomain(clientId) && clientId !== "localhost") {
    return new Response("Invalid client_id: must be a valid domain", {
      status: 400,
    });
  }

  // If no redirect_uri provided, use default pattern
  if (!redirectUri) {
    redirectUri = `https://${clientId}/callback`;
  }

  // Validate redirect_uri
  try {
    const redirectUrl = new URL(redirectUri);
    if (redirectUrl.protocol !== "https:" && clientId !== "localhost") {
      return new Response("Invalid redirect_uri: must use HTTPS", {
        status: 400,
      });
    }
    if (redirectUrl.hostname !== clientId) {
      return new Response(
        "Invalid redirect_uri: must be on same origin as client_id",
        { status: 400 },
      );
    }
  } catch {
    return new Response("Invalid redirect_uri format", { status: 400 });
  }

  // Only support authorization code flow
  if (responseType !== "code") {
    return new Response("Unsupported response_type", { status: 400 });
  }

  // Check if user is already authenticated
  const accessToken = getAccessToken(request);
  if (accessToken) {
    // User is authenticated, show key selection page
    return await showKeySelectionPage(
      request,
      env,
      clientId,
      redirectUri,
      state,
      accessToken,
      resource,
    );
  }

  // User not authenticated, redirect to GitHub OAuth
  const providerState = {
    clientId,
    redirectUri,
    state,
    originalState: state,
    resource,
  };

  const providerStateString = btoa(JSON.stringify(providerState));

  // Generate PKCE for GitHub OAuth
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  const githubState: OAuthState = {
    redirectTo: url.pathname + url.search,
    codeVerifier,
    resource,
  };

  const githubStateString = btoa(JSON.stringify(githubState));

  const githubUrl = new URL("https://github.com/login/oauth/authorize");
  githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  githubUrl.searchParams.set("scope", scope);
  githubUrl.searchParams.set("state", githubStateString);
  githubUrl.searchParams.set("code_challenge", codeChallenge);
  githubUrl.searchParams.set("code_challenge_method", "S256");

  const headers = new Headers({ Location: githubUrl.toString() });
  headers.append(
    "Set-Cookie",
    `oauth_state=${encodeURIComponent(
      githubStateString,
    )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
  );
  headers.append(
    "Set-Cookie",
    `provider_state=${encodeURIComponent(
      providerStateString,
    )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

async function showKeySelectionPage(
  request: Request,
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string | null,
  accessToken: string,
  resource?: string,
): Promise<Response> {
  // Get user's Cloudflare keys
  const userDOId = env.CODES.idFromName(`user:${accessToken}`);
  const userDO = env.CODES.get(userDOId);
  const userData = await userDO.getUser();
  const keys = await userDO.getCloudflareKeys();

  if (!userData) {
    return new Response("User not found", { status: 404 });
  }

  const { user } = userData;

  // Handle form submission
  if (request.method === "POST") {
    const formData = await request.formData();
    const selectedKeyId = formData.get("keyId");
    const action = formData.get("action");

    if (action === "select" && selectedKeyId) {
      return await createAuthCodeAndRedirect(
        env,
        clientId,
        redirectUri,
        state,
        accessToken,
        selectedKeyId.toString(),
        resource,
      );
    }
  }

  // Show key selection page
  const keyOptions = keys
    .map(
      (key) => `
    <div class="key-option">
      <input type="radio" id="key-${key.id}" name="keyId" value="${
        key.id
      }" required>
      <label for="key-${key.id}">
        <strong>${escapeHtml(key.name)}</strong><br>
        <small>Account ID: ${escapeHtml(key.accountId)}</small><br>
        <small>Created: ${new Date(key.createdAt).toLocaleDateString()}</small>
        ${
          key.lastUsed
            ? `<br><small>Last used: ${new Date(
                key.lastUsed,
              ).toLocaleDateString()}</small>`
            : ""
        }
      </label>
    </div>
  `,
    )
    .join("");

  return new Response(
    `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Select Cloudflare API Key</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
        .user-info { background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .key-option { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 8px; }
        .key-option:hover { background: #f9f9f9; }
        .key-option input[type="radio"] { margin-right: 10px; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .warning strong { color: #856404; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .manage-keys { margin-top: 20px; }
        .manage-keys a { color: #007bff; text-decoration: none; }
        .manage-keys a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <h1>Select Cloudflare API Key</h1>
      
      <div class="user-info">
        <img src="${user.avatar_url}" alt="${escapeHtml(
      user.name || user.login,
    )}" width="40" height="40" style="border-radius: 50%; vertical-align: middle; margin-right: 10px;">
        <strong>${escapeHtml(user.name || user.login)}</strong>
      </div>

      <div class="warning">
        <strong>⚠️ Important:</strong> The selected API key will be provided directly to <strong>${escapeHtml(
          clientId,
        )}</strong>. 
        This gives them full access to your Cloudflare account with the permissions of this key. 
        Only proceed if you trust this application.
      </div>

      <form method="POST">
        <input type="hidden" name="action" value="select">
        
        ${
          keys.length > 0
            ? `
          <h3>Choose an API key:</h3>
          ${keyOptions}
          <button type="submit">Grant Access</button>
        `
            : `
          <p>You haven't added any Cloudflare API keys yet. <a href="/manage">Add one now</a>.</p>
        `
        }
      </form>

      <div class="manage-keys">
        <a href="/manage">Manage my API keys</a> | 
        <a href="/logout">Logout</a>
      </div>
    </body>
    </html>
  `,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}

async function createAuthCodeAndRedirect(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string | null,
  encryptedAccessToken: string,
  selectedKeyId: string,
  resource?: string,
): Promise<Response> {
  // Generate auth code
  const authCode = generateCodeVerifier();

  // Decrypt to get GitHub access token
  const githubAccessToken = await decrypt(
    encryptedAccessToken,
    env.GITHUB_CLIENT_SECRET,
  );

  // Create Durable Object for this auth code
  const id = env.CODES.idFromName(`code:${authCode}`);
  const authCodeDO = env.CODES.get(id);

  await authCodeDO.setAuthData(
    githubAccessToken,
    encryptedAccessToken,
    clientId,
    redirectUri,
    selectedKeyId,
    resource,
  );

  // Redirect back to client with auth code
  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  return new Response(null, {
    status: 302,
    headers: { Location: redirectUrl.toString() },
  });
}

async function handleToken(
  request: Request,
  env: Env,
  scope: string,
): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { "Access-Control-Allow-Origin": "*" },
    });
  }

  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  };

  const formData = await request.formData();
  const grantType = formData.get("grant_type");
  const code = formData.get("code");
  const clientId = formData.get("client_id");
  const redirectUri = formData.get("redirect_uri");
  const resource = formData.get("resource");

  if (grantType !== "authorization_code") {
    return new Response(JSON.stringify({ error: "unsupported_grant_type" }), {
      status: 400,
      headers,
    });
  }

  if (!code || !clientId) {
    return new Response(JSON.stringify({ error: "invalid_request" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id
  if (
    !isValidDomain(clientId.toString()) &&
    clientId.toString() !== "localhost"
  ) {
    return new Response(JSON.stringify({ error: "invalid_client" }), {
      status: 400,
      headers,
    });
  }

  // Get auth code data
  const id = env.CODES.idFromName(`code:${code.toString()}`);
  const authCodeDO = env.CODES.get(id);
  const authData = await authCodeDO.getAuthData();

  if (!authData) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id and redirect_uri match
  if (
    authData.clientId !== clientId ||
    (redirectUri && authData.redirectUri !== redirectUri)
  ) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Validate resource parameter
  if (resource && authData.resource !== resource) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Get the selected Cloudflare API key
  const userDOId = env.CODES.idFromName(`user:${authData.access_token}`);
  const userDO = env.CODES.get(userDOId);
  const keys = await userDO.getCloudflareKeys();
  const selectedKey = keys.find((k) => k.id === authData.selectedKeyId);

  if (!selectedKey) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Update last used timestamp
  await userDO.updateKeyLastUsed(selectedKey.id);

  // Return the Cloudflare API key details
  return new Response(
    JSON.stringify({
      access_token: authData.access_token,
      token_type: "bearer",
      scope,
      cloudflare_account_id: selectedKey.accountId,
      cloudflare_api_key: selectedKey.apiKey,
      cloudflare_key_name: selectedKey.name,
    }),
    { headers },
  );
}

async function handleCallback(
  request: Request,
  env: Env,
  sameSite: string,
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  // Get state from cookie
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const stateCookie = cookies.oauth_state;
  const providerStateCookie = cookies.provider_state;

  if (!stateCookie || stateCookie !== stateParam) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  // Parse state
  let state: OAuthState;
  try {
    state = JSON.parse(atob(stateParam));
  } catch {
    return new Response("Invalid state format", { status: 400 });
  }

  // Exchange code for token with GitHub
  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${url.origin}/callback`,
        code_verifier: state.codeVerifier,
      }),
    },
  );

  const tokenData = (await tokenResponse.json()) as any;

  if (!tokenData.access_token) {
    return new Response("Failed to get access token", { status: 400 });
  }

  // Get user info from GitHub
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      "User-Agent": "CloudflareOAuthProvider",
    },
  });

  if (!userResponse.ok) {
    return new Response("Failed to get user info", { status: 400 });
  }

  const user = (await userResponse.json()) as GitHubUser;

  // Encrypt the GitHub access token
  const encryptedAccessToken = await encrypt(
    tokenData.access_token,
    env.GITHUB_CLIENT_SECRET,
  );

  // Store user data
  const userDOId = env.CODES.idFromName(`user:${encryptedAccessToken}`);
  const userDO = env.CODES.get(userDOId);
  await userDO.setUser(user, tokenData.access_token, encryptedAccessToken);

  // Check if this was part of an OAuth provider flow
  if (providerStateCookie) {
    try {
      const providerState = JSON.parse(atob(providerStateCookie));

      // Redirect back to the authorize endpoint to show key selection
      const headers = new Headers({
        Location: `/authorize?client_id=${
          providerState.clientId
        }&redirect_uri=${encodeURIComponent(
          providerState.redirectUri,
        )}&response_type=code&state=${providerState.state || ""}${
          providerState.resource
            ? `&resource=${encodeURIComponent(providerState.resource)}`
            : ""
        }`,
      });

      headers.append(
        "Set-Cookie",
        `oauth_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      );
      headers.append(
        "Set-Cookie",
        `provider_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      );
      headers.append(
        "Set-Cookie",
        `access_token=${encryptedAccessToken}; HttpOnly; Secure; SameSite=${sameSite}; Path=/`,
      );

      return new Response(null, { status: 302, headers });
    } catch {
      // Fall through to normal redirect
    }
  }

  // Normal redirect (direct login)
  const headers = new Headers({ Location: state.redirectTo || "/" });
  headers.append(
    "Set-Cookie",
    `oauth_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
  );
  headers.append(
    "Set-Cookie",
    `access_token=${encryptedAccessToken}; HttpOnly; Secure; SameSite=${sameSite}; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

export function getAccessToken(request: Request): string | null {
  // Check Authorization header first
  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  // Fallback to cookie
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  return cookies.access_token || null;
}

// Management routes
export async function handleManagement(
  request: Request,
  env: Env,
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/manage") {
    return handleManagePage(request, env);
  }

  if (path === "/api/keys" && request.method === "POST") {
    return handleAddKey(request, env);
  }

  if (path === "/api/keys" && request.method === "DELETE") {
    return handleDeleteKey(request, env);
  }

  return null;
}

async function handleManagePage(request: Request, env: Env): Promise<Response> {
  const accessToken = getAccessToken(request);
  if (!accessToken) {
    return new Response(null, {
      status: 302,
      headers: { Location: "/authorize?redirect_to=/manage" },
    });
  }

  const userDOId = env.CODES.idFromName(`user:${accessToken}`);
  const userDO = env.CODES.get(userDOId);
  const userData = await userDO.getUser();
  const keys = await userDO.getCloudflareKeys();

  if (!userData) {
    return new Response("User not found", { status: 404 });
  }

  const { user } = userData;

  if (request.method === "POST") {
    const formData = await request.formData();
    const action = formData.get("action");

    if (action === "add") {
      const name = formData.get("name")?.toString();
      const accountId = formData.get("accountId")?.toString();
      const apiKey = formData.get("apiKey")?.toString();

      if (!name || !accountId || !apiKey) {
        return new Response("Missing required fields", { status: 400 });
      }

      // Validate the API key by making a test request
      const testResponse = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}`,
        {
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (!testResponse.ok) {
        return showManagePage(user, keys, "Invalid API key or Account ID");
      }

      const newKey: CloudflareAPIKey = {
        id: crypto.randomUUID(),
        name,
        accountId,
        apiKey,
        createdAt: new Date().toISOString(),
      };

      await userDO.addCloudflareKey(newKey);
      return new Response(null, {
        status: 302,
        headers: { Location: "/manage" },
      });
    }

    if (action === "delete") {
      const keyId = formData.get("keyId")?.toString();
      if (keyId) {
        await userDO.removeCloudflareKey(keyId);
      }
      return new Response(null, {
        status: 302,
        headers: { Location: "/manage" },
      });
    }
  }

  return showManagePage(user, keys);
}

function showManagePage(
  user: GitHubUser,
  keys: CloudflareAPIKey[],
  error?: string,
): Response {
  const keysList = keys
    .map(
      (key) => `
    <tr>
      <td>${escapeHtml(key.name)}</td>
      <td>${escapeHtml(key.accountId)}</td>
      <td>${new Date(key.createdAt).toLocaleDateString()}</td>
      <td>${
        key.lastUsed ? new Date(key.lastUsed).toLocaleDateString() : "Never"
      }</td>
      <td>
        <form method="POST" style="display: inline;">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="keyId" value="${key.id}">
          <button type="submit" onclick="return confirm('Are you sure?')" style="background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer;">Delete</button>
        </form>
      </td>
    </tr>
  `,
    )
    .join("");

  return new Response(
    `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Manage Cloudflare API Keys</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .user-info { background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
        .info { background: #d1ecf1; color: #0c5460; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .nav { margin-bottom: 20px; }
        .nav a { color: #007bff; text-decoration: none; margin-right: 20px; }
        .nav a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="/">Home</a>
        <a href="/logout">Logout</a>
      </div>

      <h1>Manage Cloudflare API Keys</h1>
      
      <div class="user-info">
        <img src="${user.avatar_url}" alt="${escapeHtml(
      user.name || user.login,
    )}" width="40" height="40" style="border-radius: 50%; vertical-align: middle; margin-right: 10px;">
        <strong>${escapeHtml(user.name || user.login)}</strong>
      </div>

      <div class="info">
        <strong>How to get your Cloudflare API key:</strong><br>
        1. Go to <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank">Cloudflare Dashboard → My Profile → API Tokens</a><br>
        2. Click "Create Token" and choose "Custom token"<br>
        3. Give it a name and select the permissions you want to grant<br>
        4. Copy the token and your Account ID from the right sidebar
      </div>

      ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}

      <h2>Add New API Key</h2>
      <form method="POST">
        <input type="hidden" name="action" value="add">
        
        <div class="form-group">
          <label for="name">Key Name (for your reference):</label>
          <input type="text" id="name" name="name" required placeholder="e.g., My Website API Key">
        </div>

        <div class="form-group">
          <label for="accountId">Cloudflare Account ID:</label>
          <input type="text" id="accountId" name="accountId" required placeholder="e.g., 1234567890abcdef1234567890abcdef">
        </div>

        <div class="form-group">
          <label for="apiKey">Cloudflare API Token:</label>
          <input type="password" id="apiKey" name="apiKey" required placeholder="Your API token">
        </div>

        <button type="submit">Add API Key</button>
      </form>

      <h2>Your API Keys</h2>
      ${
        keys.length > 0
          ? `
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Account ID</th>
              <th>Created</th>
              <th>Last Used</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${keysList}
          </tbody>
        </table>
      `
          : "<p>No API keys added yet.</p>"
      }
    </body>
    </html>
  `,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}

async function handleAddKey(request: Request, env: Env): Promise<Response> {
  // This is handled in the manage page
  return new Response("Method not allowed", { status: 405 });
}

async function handleDeleteKey(request: Request, env: Env): Promise<Response> {
  // This is handled in the manage page
  return new Response("Method not allowed", { status: 405 });
}

// Utility functions
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  cookieHeader.split(";").forEach((cookie) => {
    const [name, value] = cookie.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });
  return cookies;
}

function isValidDomain(domain: string): boolean {
  const domainRegex =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return (
    domainRegex.test(domain) && domain.includes(".") && domain.length <= 253
  );
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(
    String.fromCharCode.apply(null, Array.from(new Uint8Array(digest))),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Simple HTML escaping for server-side
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function encrypt(text: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data,
  );

  const combined = new Uint8Array(
    salt.length + iv.length + encrypted.byteLength,
  );
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);

  return btoa(String.fromCharCode.apply(null, Array.from(combined)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function decrypt(encrypted: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const combined = new Uint8Array(
    atob(encrypted.replace(/-/g, "+").replace(/_/g, "/"))
      .split("")
      .map((c) => c.charCodeAt(0)),
  );

  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const data = combined.slice(28);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data,
  );
  return decoder.decode(decrypted);
}
