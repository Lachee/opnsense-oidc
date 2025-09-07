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

## Troubleshooting: OIDC type not showing
If you do not see "OIDC Interactive" in System -> Access -> Servers:

1. Confirm install paths (example):
	- `/usr/local/opnsense/mvc/app/library/OPNsense/Auth/OIDC.php`
	- `/usr/local/etc/inc/plugins.inc.d/oidc.inc`
2. Restart services:
	```sh
	service configd restart
	service php-fpm restart
	```
3. Inspect registered auth factories:
	```sh
	php -r 'include "/usr/local/etc/inc/auth.inc"; global $authFactory; var_dump(array_keys($authFactory));'
	```
	Expect to see `oidc`.
4. If missing, manually include registration file in a quick test:
	```sh
	php -r 'include "/usr/local/etc/inc/auth.inc"; include "/usr/local/etc/inc/plugins.inc.d/oidc.inc"; global $authFactory; var_dump($authFactory["oidc"]);'
	```
5. Ensure plugin.xml visibility is set to `visible`.
6. Clear PHP opcache (if enabled) or reboot.

If still absent, OPNsense version may require core patch to allow custom auth backends.

