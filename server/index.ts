import {
  OAuth2Client,
  generateCodeVerifier,
  type OAuth2Token,
} from "@badgateway/oauth2-client";

import cookie from "cookie";

/**
 * The scopes used by your application. It'll probably be a subset of these.
 */
const DefaultScopes = {
  "account:read":
    "See your account info such as account details, analytics, and memberships.",
  "user:read":
    "See your user info such as name, email address, and account memberships.",
  "workers:write":
    "See and change Cloudflare Workers data such as zones, KV storage, namespaces, scripts, and routes.",
  "workers_kv:write":
    "See and change Cloudflare Workers KV Storage data such as keys and namespaces.",
  "workers_routes:write":
    "See and change Cloudflare Workers data such as filters and routes.",
  "workers_scripts:write":
    "See and change Cloudflare Workers scripts, durable objects, subdomains, triggers, and tail data.",
  "workers_tail:read": "See Cloudflare Workers tail and script data.",
  "d1:write": "See and change D1 Databases.",
  "pages:write":
    "See and change Cloudflare Pages projects, settings and deployments.",
  "zone:read": "Grants read level access to account zone.",
  "ssl_certs:write": "See and manage mTLS certificates for your account",
  "constellation:write": "Manage Constellation projects/models",
  "ai:write": "See and change Workers AI catalog and assets",
  "queues:write": "See and change Cloudflare Queues settings and data",
} as const;

/**
 * Character set to generate code verifier defined in rfc7636.
 */
const PKCE_CHARSET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/**
 * A sensible length for the state's length, for anti-csrf.
 */
const RECOMMENDED_STATE_LENGTH = 32;

/**
 * Generates random state to be passed for anti-csrf.
 */
function generateRandomState(lengthOfState: number): string {
  const output = new Uint32Array(lengthOfState);
  crypto.getRandomValues(output);
  return Array.from(output)
    .map((num: number) => PKCE_CHARSET[num % PKCE_CHARSET.length])
    .join("");
}

type Env = {
  CF_OAUTH_CLIENT_ID: string;
  CF_OAUTH_CLIENT_SECRET: string;
};

export default {
  async fetch(request: Request, env: Env) {
    const client = new OAuth2Client({
      // The base URI of your OAuth2 server
      server: "https://dash.cloudflare.com/",

      // OAuth2 client id
      clientId: env.CF_OAUTH_CLIENT_ID,

      // OAuth2 client secret.
      clientSecret: env.CF_OAUTH_CLIENT_SECRET,

      // Token endpoint. Most flows need this.
      tokenEndpoint: "/oauth2/token",

      // Authorization endpoint.
      authorizationEndpoint: "/oauth2/auth",

      // Revocation endpoint
      revocationEndpoint: "/oauth2/revoke",
    });

    const url = new URL(request.url);

    switch (`${request.method} ${url.pathname}`) {
      case "GET /login": {
        // Part of PCKE
        const codeVerifier = await generateCodeVerifier();

        const randomState = generateRandomState(RECOMMENDED_STATE_LENGTH);

        // This generates the URL to redirect the user to the CF OAuth2 server.
        const authorizeUri = await client.authorizationCode.getAuthorizeUri({
          redirectUri: `${url.origin}/oauth/cf/callback`,
          state: randomState,
          codeVerifier,
          scope: Object.keys(DefaultScopes),
        });

        // Let's save some state in cookies that we'll need later.
        const headers = new Headers();
        headers.append(
          "Set-Cookie",
          `code_verifier=${codeVerifier}; Path=/; Secure; HttpOnly; SameSite=Lax`
        );
        headers.append(
          "Set-Cookie",
          `state=${randomState}; Path=/; Secure; HttpOnly; SameSite=Lax`
        );
        headers.append("Location", authorizeUri);

        return new Response("Redirecting to cloudflare...", {
          status: 302,
          headers: headers,
        });
      }

      case "GET /oauth/cf/callback": {
        var cookies = cookie.parse(request.headers.get("cookie") || "");
        const codeVerifier = cookies.code_verifier;
        const state = cookies.state;

        if (!codeVerifier || !state) {
          return new Response("No code_verifier or state found", {
            status: 400,
          });
        }

        const { code } = await client.authorizationCode.validateResponse(url, {
          state: state,
        });

        if (!code) {
          return new Response("No code found", { status: 400 });
        }

        // Now we get the actual token from the code.
        const oauth2Token =
          await client.authorizationCode.getTokenFromCodeRedirect(request.url, {
            redirectUri: `${url.origin}/oauth/cf/callback`,
            codeVerifier,
            state,
          });

        const headers = new Headers();
        headers.append(
          "Set-Cookie",
          `token=${JSON.stringify(
            oauth2Token
          )}; Path=/; Secure; HttpOnly; SameSite=Lax`
        );
        // remove code_verifier and state cookies
        headers.append(
          "Set-Cookie",
          `code_verifier=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`
        );
        headers.append(
          "Set-Cookie",
          `state=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`
        );
        headers.append("Location", "/");
        return new Response("", {
          status: 302,
          headers: headers,
        });
        break;
      }

      case "GET /logout": {
        var cookies = cookie.parse(request.headers.get("cookie") || "");
        const token = cookies.token;
        const headers = new Headers();
        headers.append(
          "Set-Cookie",
          `token=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`
        );

        // This will revoke the token
        client.revoke(JSON.parse(token));

        return new Response("Logged out", {
          status: 302,
          headers: headers,
        });
      }

      case "GET /": {
        // get oauth2 token from cookie
        const cookies = cookie.parse(request.headers.get("cookie") || "");
        const authToken: OAuth2Token = JSON.parse(cookies.token || "{}");

        if (!authToken.accessToken) {
          const headers = new Headers();
          headers.append("Location", "/login");
          return new Response("Not logged, let's redirect to /login", {
            status: 302,
            headers: headers,
          });
        }

        // get user info
        const user = await fetch("https://api.cloudflare.com/client/v4/user", {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${authToken.accessToken}`,
          },
        }).then((res) => res.json());

        return new Response(JSON.stringify(user, null, 2));
      }
    }
    return new Response("Hello, World!");
  },
};
