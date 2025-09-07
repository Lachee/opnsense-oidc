<?php

namespace OPNsense\OIDC;

use OPNsense\Base\ControllerBase;
use OPNsense\OIDC\Client;
use OPNsense\OIDC\JWKSCache;
use OPNsense\OIDC\JWT;

class IndexController extends ControllerBase
{
    public function loginAction()
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $config = $this->getConfig();
        if (empty($config['issuer'])) {
            http_response_code(500);
            echo 'OIDC not configured';
            return;
        }
        $disc = Client::discover($config['issuer'], (bool)($config['verify_tls'] ?? true));
        if (empty($disc['authorization_endpoint'])) {
            http_response_code(500);
            echo 'Discovery failed';
            return;
        }
        $pkce = Client::generatePkce();
        $_SESSION['oidc']['pkce_verifier'] = $pkce['verifier'];
        $state = bin2hex(random_bytes(16));
        $_SESSION['oidc']['state'] = $state;
        $nonce = bin2hex(random_bytes(16));
        $_SESSION['oidc']['nonce'] = $nonce;
        $authzEndpoint = $disc['authorization_endpoint'];
        $params = [
            'client_id' => $config['client_id'],
            'redirect_uri' => $config['redirect_uri'],
            'response_type' => 'code',
            'scope' => $config['scope'] ?? 'openid profile email',
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $pkce['challenge'],
            'code_challenge_method' => 'S256'
        ];
        $url = $authzEndpoint . '?' . http_build_query($params);
        header('Location: ' . $url);
        exit;
    }

    public function callbackAction()
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        $config = $this->getConfig();
        $verifyTLS = (bool)($config['verify_tls'] ?? true);
        $disc = Client::discover($config['issuer'], $verifyTLS);
        if (empty($disc['token_endpoint']) || empty($disc['jwks_uri'])) {
            echo 'Discovery failed';
            return;
        }
        if (empty($_GET['state']) || $_GET['state'] !== ($_SESSION['oidc']['state'] ?? null)) {
            echo 'Invalid state';
            return;
        }
        $code = $_GET['code'] ?? null;
        if (!$code) {
            echo 'Missing code';
            return;
        }
        // Exchange token (simplified)
        $tokenEndpoint = $disc['token_endpoint'];
        $post = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $config['redirect_uri'],
            'client_id' => $config['client_id'],
            'code_verifier' => $_SESSION['oidc']['pkce_verifier'] ?? ''
        ];
        if (!empty($config['client_secret'])) {
            $post['client_secret'] = $config['client_secret'];
        }
        $resp = Client::exchangeCode($tokenEndpoint, $post, 15, $verifyTLS);
        if (empty($resp['id_token'])) {
            echo 'Token exchange failed';
            return;
        }
        $jwt = $resp['id_token'];
        // Parse & verify
        try {
            $parsed = JWT::parse($jwt);
        } catch (\Throwable $e) {
            echo 'Invalid token';
            return;
        }
        $jwksCache = new JWKSCache('/var/cache/opnsense-oidc', (int)($config['jwks_cache_ttl'] ?? 3600));
        $jwks = $jwksCache->get(function () use ($disc, $verifyTLS) {
            return Client::httpGetJson($disc['jwks_uri'], 10, $verifyTLS);
        });
        $jwk = Client::selectJwk($jwks, $parsed['header']);
        if (!$jwk || !JWT::verifyRS256($jwt, $jwk)) {
            echo 'Signature verification failed';
            return;
        }
        $payload = $parsed['payload'];
        // Basic claim checks
        $now = time();
        if (($payload['exp'] ?? 0) < $now || ($payload['nbf'] ?? 0) > $now) {
            echo 'Token expired/not yet valid';
            return;
        }
        if (!empty($_SESSION['oidc']['nonce']) && ($payload['nonce'] ?? null) !== $_SESSION['oidc']['nonce']) {
            echo 'Nonce mismatch';
            return;
        }
        $aud = $payload['aud'] ?? null;
        if (is_array($aud) && !in_array($config['client_id'], $aud, true)) {
            echo 'Audience mismatch';
            return;
        } elseif (is_string($aud) && $aud !== $config['client_id']) {
            echo 'Audience mismatch';
            return;
        }
        // Required groups enforcement (if configured)
        if (!empty($config['required_groups'])) {
            $required = array_filter(array_map('trim', explode(',', $config['required_groups'])));
            if ($required) {
                $claimName = $config['groups_claim'] ?? 'groups';
                $userGroups = $payload[$claimName] ?? [];
                if (is_string($userGroups)) {
                    // try comma or space separation
                    if (strpos($userGroups, ',') !== false) {
                        $userGroups = array_map('trim', explode(',', $userGroups));
                    } else {
                        $userGroups = preg_split('/\s+/', trim($userGroups));
                    }
                }
                if (!is_array($userGroups)) {
                    $userGroups = [];
                }
                $missing = array_diff($required, $userGroups);
                if ($missing) {
                    echo 'Access denied: missing required group(s)';
                    return;
                }
            }
        }
        $_SESSION['oidc']['raw_id_token'] = $jwt;
        $username = $payload['preferred_username'] ?? ($payload['email'] ?? $payload['sub']);
        $_SESSION['oidc']['user'] = $username;
        $_SESSION['oidc']['claims'] = $payload;
        // Redirect to main login landing
        header('Location: /');
        exit;
    }

    private function curlJson(string $url, array $post): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($post),
            CURLOPT_TIMEOUT => 15,
        ]);
        $raw = curl_exec($ch);
        if ($raw === false) {
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

    private function getConfig(): array
    {
        // Attempt to load from model (if generated via configd). Fallback to placeholders.
        try {
            if (class_exists('OPNsense\\Core\\Config')) {
                // Model class might be generated under OPNsense\OIDC\OIDC\General or similar; since we defined \OIDC.xml,
                // for brevity we parse the raw config.
                $cfg = \OPNsense\Core\Config::getInstance()->object();
                if (!empty($cfg->OIDC)) {
                    $section = $cfg->OIDC; // Direct mapping (adjust if nested path differs)
                    return [
                        'issuer' => (string)($section->issuer_url ?? ''),
                        'client_id' => (string)($section->client_id ?? ''),
                        'client_secret' => (string)($section->client_secret ?? ''),
                        'redirect_uri' => (string)($section->redirect_uri ?? ''),
                        'scope' => (string)($section->scopes ?? 'openid profile email'),
                        'verify_tls' => ((string)($section->verify_tls ?? '1')) === '1',
                        'jwks_cache_ttl' => (int)($section->jwks_cache_ttl ?? 3600),
                        'username_claim' => (string)($section->username_claim ?? 'preferred_username'),
                        'groups_claim' => (string)($section->groups_claim ?? 'groups'),
                        'required_groups' => (string)($section->required_groups ?? ''),
                    ];
                }
            }
        } catch (\Throwable $e) {
            // ignore and fallback
        }
        return [
            'issuer' => 'https://example-idp',
            'client_id' => 'CHANGE_ME',
            'client_secret' => '',
            'redirect_uri' => 'https://firewall.example.com/oidc/callback',
            'scope' => 'openid profile email',
            'verify_tls' => true,
            'jwks_cache_ttl' => 3600,
            'username_claim' => 'preferred_username',
            'groups_claim' => 'groups',
            'required_groups' => '',
        ];
    }
}
