#!/usr/bin/env php
<?php
// Simple debug utility: discovery + JWKS fetch + optional ID token verification
require_once __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/OIDC/Client.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/OIDC/JWT.php';
require_once __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/OIDC/JWKSCache.php';

use OPNsense\OIDC\Client;
use OPNsense\OIDC\JWT;
use OPNsense\OIDC\JWKSCache;

if ($argc < 2) {
    fwrite(STDERR, "Usage: oidc-debug.php <issuer> [id_token]\n");
    exit(1);
}
$issuer = $argv[1];
$disc = Client::discover($issuer, true);
if (!$disc) {
    fwrite(STDERR, "Discovery failed\n");
    exit(1);
}
print_r($disc);
if (!empty($argv[2])) {
    $idToken = $argv[2];
    $parsed = JWT::parse($idToken);
    $jwksCache = new JWKSCache(sys_get_temp_dir() . '/oidc-debug');
    $jwks = $jwksCache->get(function () use ($disc) {
        return Client::httpGetJson($disc['jwks_uri']);
    });
    $jwk = Client::selectJwk($jwks, $parsed['header']);
    $valid = $jwk && JWT::verifyRS256($idToken, $jwk);
    echo "Signature valid: " . ($valid ? 'YES' : 'NO') . "\n";
    print_r($parsed['payload']);
}
