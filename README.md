# 🎈 cf-auth

A sample app for oauth flow with cloudflare for web applications. Ths example uses cloudflare workers, but adjust according to your needs.

- change `dev.port` in `wrangler.toml` to the port that's registered with your oauth app. This is important for local development because cloudflare will redirect to this port.

- assuming your registered local dev URLs are `https` you will want to start wrangler with `wrangler dev --local-protocol=https`

- store your client id/secret somewhere. In this example, we'll use the wrangler's secret management by running these commands.

```
npx wrangler secret put CF_OAUTH_CLIENT_ID
npx wrangler secret put CF_OAUTH_CLIENT_SECRET
```

- we'll also make a `.dev.vars` file with these values so they can be picked up in local development.

```
# .dev.vars
CF_OAUTH_CLIENT_ID=your-client-id
CF_OAUTH_CLIENT_SECRET=your-client-secret
```

- in your worker code, you can access these secrets with `env.CF_OAUTH_CLIENT_ID` and `env.CF_OAUTH_CLIENT_SECRET` respectively.

On to the app, there are 3 main URLs:

- `/`: this will redirect to `/login` if not logged in, otherwise will spit out user information
- `/login`: this will redirect to cloudflare's oauth login page. Once you login, you will be redirected back to `/` with the user information.
- `/logout`: this will clear the session

- Additionally, we've setup `/cf/oauth/callback` to handle the oauth callback. This is the URL that cloudflare will redirect to after the user logs in. This will exchange the code for an access token and store the user information in the session.

# Notes

- We use cookies to store state for intermediate steps. You may want to encrypt these cookies.
- This flow is only for web applications where the secret is not exposed ot the user. If you're building something like a CLI, you may want to use the authorization code flow. Lemme know if you need a sample app for that.
- This doesn't implement token refreshes (yet, I'll update this app later wih it). You may want to implement that if you're storing the access token for a long time.
