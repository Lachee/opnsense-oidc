<?php

namespace OPNsense\OIDC;

class Client
{
    /** Generate cryptographically random base64url string */
    public static function randomBytesBase64Url(int $length = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($length)), '+/', '-_'), '=');
    }

    public static function generatePkce(): array
    {
        $verifier = self::randomBytesBase64Url(64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        return ['verifier' => $verifier, 'challenge' => $challenge];
    }

    /** Basic HTTP GET returning JSON */
    public static function httpGetJson(string $url, int $timeout = 10, bool $verifyTLS = true): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => $verifyTLS,
            CURLOPT_SSL_VERIFYHOST => $verifyTLS ? 2 : 0,
        ]);
        $raw = curl_exec($ch);
        if ($raw === false) {
            curl_close($ch);
            return [];
        }
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code >= 200 && $code < 300) {
            $json = json_decode($raw, true);
            return is_array($json) ? $json : [];
        }
        return [];
    }

    /** Fetch OIDC discovery document */
    public static function discover(string $issuer, bool $verifyTLS = true): array
    {
        $issuer = rtrim($issuer, '/');
        $url = $issuer . '/.well-known/openid-configuration';
        return self::httpGetJson($url, 10, $verifyTLS);
    }

    /** Select JWKS key for header */
    public static function selectJwk(array $jwks, array $header): ?array
    {
        if (empty($jwks['keys']) || empty($header['kid'])) {
            return null;
        }
        foreach ($jwks['keys'] as $k) {
            if (($k['kid'] ?? null) === $header['kid']) {
                return $k;
            }
        }
        return null;
    }

    /** Token exchange via POST (authorization_code) */
    public static function exchangeCode(string $tokenEndpoint, array $params, int $timeout = 15, bool $verifyTLS = true): array
    {
        $ch = curl_init($tokenEndpoint);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($params),
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => $verifyTLS,
            CURLOPT_SSL_VERIFYHOST => $verifyTLS ? 2 : 0,
        ]);
        $raw = curl_exec($ch);
        if ($raw === false) {
            curl_close($ch);
            return [];
        }
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code >= 200 && $code < 300) {
            $json = json_decode($raw, true);
            return is_array($json) ? $json : [];
        }
        return [];
    }
}
