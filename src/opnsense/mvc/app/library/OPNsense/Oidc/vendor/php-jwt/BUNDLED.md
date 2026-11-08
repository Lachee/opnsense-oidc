firebase/php-jwt v7.2.0 (BSD-3-Clause), bundled for the OPNsense OIDC plugin's
ID-token signature/time verification.

Source: https://github.com/firebase/php-jwt/archive/refs/tags/v7.2.0.tar.gz
sha256(tarball): 31466fbefb14eb1511603dc6e0b93d7469137f81d3117bf194c1e2d6d2c1aac0
Files: src/{JWT,JWK,Key,BeforeValidException,ExpiredException,
SignatureInvalidException,JWTExceptionWithPayloadInterface}.php, LICENSE, VERSION
(CachedKeySet.php omitted: needs a PSR-6 cache, unused.)
Requires PHP >= 8.0 and ext-openssl (both present on OPNsense 26.7).
Update: re-download a newer tag, verify, replace src/*, update this file.
