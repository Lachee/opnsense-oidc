# Offline ID-token tests

`idtoken-harness.php` exercises `OidcClient` (the plugin's wrapper around the
vendored jumbojett client and the bundled firebase/php-jwt) without a firewall
or a network. It stubs the few OPNsense classes the client touches, fakes the
provider (discovery, JWKS, token endpoint) with a locally generated RSA key,
and runs 37 cases:

- a valid RS256 login
- HS256 signed with the client secret, `alg: none`, a different key, an
  unknown `kid`, a tampered payload, an oversized token
- missing/wrong `nonce`, missing/expired `exp`, missing/future `iat`
- wrong `aud`/`iss`, foreign `azp`, multi-audience without `azp`
- `state` checked before the code is redeemed, non-string `code`
- cookies named `state` or `error` are ignored (only the query string counts)
- JWKS hygiene: OKP/unknown-curve keys are skipped, `use=enc` keys and
  `key_ops` without `verify` never verify a signature
- callback host vetting (`OidcClient::vetHost()`)

Run from the repository root (needs Docker; nothing is fetched at run time):

```sh
H=$(mktemp -d) && mkdir "$H/Oidc" \
  && cp -r src/opnsense/mvc/app/library/OPNsense/Oidc/* "$H/Oidc/" \
  && cp test/idtoken-harness.php "$H/t.php" \
  && docker run --rm --network none -v "$H:/h:ro" -w /h php:8.5-cli php -d error_reporting=E_ALL t.php
```

Expect `ALL PASSED (37 cases)`.
