# OPNsense OIDC Interactive Authentication Plugin

Experimental plugin providing an interactive OpenID Connect (Authorization Code + PKCE) login option for the OPNsense GUI.

## Features
- Authorization Code + PKCE redirect flow
- Injects "Login with OIDC" button on login page
- Maps ID token claim to username for backend authentication mapping
- JWKS caching (planned full signature verification)

## Status / Caveats
- Alpha quality; signature verification and audience/nonce checks need completion.
- No refresh token usage yet.
- Auto user provisioning not implemented.

## Install (development)
```sh
# from plugins security directory
make package
pkg add ./opnsense-auth-oidc-*.txz
```

## Configure Provider
Set redirect URI to: `https://<your-firewall-domain>/oidc/callback`

Configure in Model (future UI) or temporary hardcoded values in `IndexController::getConfig()`.

## TODO
- Implement full discovery (fetch .well-known)
- Validate ID token signature and claims
- Persist configuration via model integration and GUI form
- Group / role mapping enforcement
- Optional refresh handling

