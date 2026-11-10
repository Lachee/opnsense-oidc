<?php

/**
 * Simple wrapper for Jumbojett\OpenIDConnectClient to load nessary components and respecting
 * OPNsense's session handling.
 *
 * Hardening:
 * - ID-token signature and time claims are verified with the bundled
 *   firebase/php-jwt (vendor/php-jwt), which binds each key to one algorithm.
 *   Only RS256/RS384/RS512 that the provider advertises are accepted.
 * - Small OIDC Core 3.1.3.7 checks php-jwt doesn't do: nonce/exp/iat required,
 *   azp checked; state checked BEFORE the code is redeemed; state, nonce and
 *   PKCE verifier are single-use.
 */

namespace OPNsense\Oidc;

require(__DIR__ . '/OpenIDConnectClient.php');

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use OPNsense\Auth\OIDC;
use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Response;
use OPNsense\Mvc\Session;

class OidcClient extends OpenIDConnectClient
{
    /** Asymmetric only: an ID token is never verified with the client secret (HS*). */
    private const ALLOWED_SIGNING_ALGS = ['RS256', 'RS384', 'RS512'];
    private const MAX_JWT_LENGTH = 16384;
    private const LEEWAY_SECONDS = 60;
    /** Outbound provider calls: bounded size and time, https only, no redirects. */
    private const MAX_RESPONSE_BYTES = 1048576;
    private const HTTP_CONNECT_TIMEOUT = 5;
    private const HTTP_TIMEOUT = 15;

    /** @var OIDC $auth */
    protected $auth;
    /** @var Session $session */
    protected $session;
    /** @var Request $request */
    protected $request;
    /** @var Response $response */
    protected $response;

    /** @var bool true while authenticate() validates the ID token from the token endpoint */
    private $validatingIdToken = false;

    /**
     * @param string $host vetted "name[:port]" for the redirect_uri (see vetHost()); never the raw Host header
     */
    public function __construct(OIDC $auth, Controller $controller, string $host, string $callback = '/api/oidc/auth/callback')
    {
        $this->phpseclib_autoload('ParagonIE\ConstantTime', '/usr/local/share/phpseclib/paragonie');
        $this->phpseclib_autoload('phpseclib3', '/usr/local/share/phpseclib');
        $this->phpseclib_autoload('Firebase\JWT', __DIR__ . '/vendor/php-jwt/src');

        parent::__construct(static::stripWellKnown($auth->oidcProviderUrl), $auth->oidcClientId, $auth->oidcClientSecret);

        $this->auth = $auth;
        $this->session = $controller->session;
        $this->request = $controller->request;
        $this->response = $controller->response;

        $this->setRedirectURL("{$this->request->getScheme()}://{$host}{$callback}");

        // PKCE via the library's built-in support; only sent when the provider
        // advertises S256 in its discovery document (Authentik does).
        $this->setCodeChallengeMethod('S256');
        $this->setLeeway(self::LEEWAY_SECONDS);
    }

    /**
     * Check state before the authorization code is redeemed at the token
     * endpoint, and make state/nonce/code_verifier single-use on every outcome.
     */
    public function authenticate(): bool
    {
        // The library reads its callback parameters from $_REQUEST. OPNsense's
        // php.ini sets variables_order "GPCS" and no request_order, so
        // $_REQUEST also holds cookies and they override the query string.
        // Only the query string may supply these parameters.
        foreach (['code', 'state', 'error', 'error_description', 'id_token', 'access_token'] as $param) {
            if (isset($_GET[$param])) {
                $_REQUEST[$param] = $_GET[$param];
            } else {
                unset($_REQUEST[$param]);
            }
        }

        $isCallback = isset($_REQUEST['code']);
        if ($isCallback) {
            $code = $_REQUEST['code'];
            $state = $_REQUEST['state'] ?? null;
            $expected = $this->getState();
            if (!is_string($code) || !is_string($state) || !is_string($expected)
                || $expected === '' || !hash_equals($expected, $state)
            ) {
                $this->clearFlowState();
                throw new OpenIDConnectClientException('Unable to determine state');
            }
        }

        $this->validatingIdToken = $isCallback;
        try {
            return parent::authenticate();
        } finally {
            $this->validatingIdToken = false;
            if ($isCallback) {
                $this->clearFlowState();
            }
        }
    }

    /**
     * Returns the Host header value normalised to "name[:port]" if its name is
     * one of $allowedNames (compared case-insensitively), else null.
     */
    public static function vetHost(string $hostHeader, array $allowedNames): ?string
    {
        $h = strtolower(trim($hostHeader));
        if (!preg_match('/^(\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)(?::([0-9]{1,5}))?$/', $h, $m)) {
            return null;
        }
        $name = $m[1];
        $port = $m[2] ?? '';
        if ($port !== '' && ((int)$port < 1 || (int)$port > 65535)) {
            return null;
        }
        foreach ($allowedNames as $allowed) {
            if (is_string($allowed) && $allowed !== '' && strtolower($allowed) === trim($name, '[]')) {
                return $port !== '' ? "{$name}:{$port}" : $name;
            }
        }
        return null;
    }

    private function clearFlowState(): void
    {
        $this->unsetState();
        $this->unsetNonce();
        $this->unsetCodeVerifier();
    }

    /**
     * Signature + exp/nbf/iat verification via firebase/php-jwt. Keys come
     * from the provider's jwks_uri (TLS-verified fetch) and are each bound to
     * one allowed asymmetric algorithm, so a token cannot choose HS* or none.
     */
    public function verifyJWTSignature(string $jwt): bool
    {
        if (strlen($jwt) > self::MAX_JWT_LENGTH || substr_count($jwt, '.') !== 2) {
            throw new OpenIDConnectClientException('Malformed JWT');
        }

        $advertised = (array)$this->getProviderConfigValue('id_token_signing_alg_values_supported', ['RS256']);
        $allowed = array_values(array_intersect(self::ALLOWED_SIGNING_ALGS, $advertised));
        if (count($allowed) === 0) {
            throw new OpenIDConnectClientException('Provider advertises no allowed signing algorithm');
        }

        $header = json_decode(JWT::urlsafeB64Decode(strstr($jwt, '.', true)), false);
        $alg = (is_object($header) && isset($header->alg) && is_string($header->alg)) ? $header->alg : '';
        if (!in_array($alg, $allowed, true)) {
            throw new OpenIDConnectClientException('Disallowed JWT signing algorithm');
        }

        $jwksUri = $this->getProviderConfigValue('jwks_uri');
        if (!is_string($jwksUri) || $jwksUri === '') {
            throw new OpenIDConnectClientException('Provider has no jwks_uri');
        }
        $jwks = json_decode($this->fetchURL($jwksUri), true);
        if (!is_array($jwks)) {
            throw new OpenIDConnectClientException('Invalid JWKS document');
        }

        // Only RSA signature keys are candidates. Encryption keys (use=enc)
        // must never verify a signature, and a key type php-jwt doesn't
        // support would otherwise make parseKeySet() throw and block every login.
        $candidates = array_values(array_filter(
            is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [],
            fn($k) => is_array($k)
                && ($k['kty'] ?? null) === 'RSA'
                && is_string($k['n'] ?? null) && is_string($k['e'] ?? null)
                && (!isset($k['use']) || $k['use'] === 'sig')
                && (!isset($k['key_ops']) || (is_array($k['key_ops']) && in_array('verify', $k['key_ops'], true)))
        ));
        if (count($candidates) === 0) {
            throw new OpenIDConnectClientException('JWKS has no RSA signing keys');
        }

        // Keys without their own "alg" are bound to the (already allow-listed)
        // header algorithm; keys that declare a different alg won't match.
        $keys = JWK::parseKeySet(['keys' => $candidates], $alg);

        JWT::$leeway = self::LEEWAY_SECONDS;
        try {
            JWT::decode($jwt, $keys);
        } catch (\Throwable $e) {
            throw new OpenIDConnectClientException('JWT verification failed: ' . $e->getMessage());
        }
        return true;
    }

    /**
     * OIDC Core 3.1.3.7 checks for the ID token that php-jwt does not cover
     * (nonce, presence of exp/iat, azp), then the library's iss/aud/sub/at_hash
     * checks.
     */
    protected function verifyJWTClaims($claims, ?string $accessToken = null): bool
    {
        if (!is_object($claims) || !isset($claims->iss, $claims->aud, $claims->sub) || !is_string($claims->iss)) {
            return false;
        }
        if ($this->validatingIdToken) {
            $nonce = $this->getNonce();
            if (!isset($claims->nonce) || !is_string($claims->nonce) || !is_string($nonce)
                || $nonce === '' || !hash_equals($nonce, $claims->nonce)
            ) {
                return false;
            }
            // Presence only; the values were validated by php-jwt in verifyJWTSignature().
            if (!isset($claims->exp) || !is_numeric($claims->exp) || !isset($claims->iat) || !is_numeric($claims->iat)) {
                return false;
            }
            $auds = is_array($claims->aud) ? $claims->aud : [$claims->aud];
            if (count($auds) > 1 && !isset($claims->azp)) {
                return false;
            }
            if (isset($claims->azp) && $claims->azp !== $this->getClientID()) {
                return false;
            }
        }
        return parent::verifyJWTClaims($claims, $accessToken);
    }

    /**
     * Replaces the library's fetchURL(): every discovery/JWKS/token/UserInfo
     * request must be https, is never redirected (a redirecting token endpoint
     * would otherwise re-POST the code and PKCE verifier elsewhere), can only
     * speak https even if it were, has a hard size cap and short timeouts so an
     * unauthenticated /login cannot pin a PHP worker for the library's 60 s.
     * TLS verification is unconditional (the library's setters are ignored).
     */
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = [])
    {
        $parts = parse_url($url);
        if (!is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
            throw new OpenIDConnectClientException('Provider endpoint is not an https URL');
        }

        $body = '';
        $ch = curl_init();
        if ($post_body !== null) {
            // Only form-encoded posts are used (token endpoint).
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post_body);
            $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        }
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_USERAGENT => $this->getUserAgent(),
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS_STR => 'https',
            CURLOPT_REDIR_PROTOCOLS_STR => 'https',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => self::HTTP_CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT => self::HTTP_TIMEOUT,
            CURLOPT_MAXFILESIZE => self::MAX_RESPONSE_BYTES,
            CURLOPT_WRITEFUNCTION => function ($ch, $data) use (&$body) {
                $body .= $data;
                // Returning a short count aborts the transfer (CURLE_WRITE_ERROR).
                return strlen($body) > self::MAX_RESPONSE_BYTES ? -1 : strlen($data);
            },
        ]);
        if (!empty($this->getCertPath())) {
            curl_setopt($ch, CURLOPT_CAINFO, $this->getCertPath());
        }

        $ok = curl_exec($ch);
        $info = curl_getinfo($ch);
        $this->responseCode = (int)($info['http_code'] ?? 0);
        $this->responseContentType = $info['content_type'] ?? null;
        $errno = curl_errno($ch);
        $error = curl_error($ch);

        if ($ok === false || $errno !== 0) {
            throw new OpenIDConnectClientException(sprintf('Curl error: (%d) %s', $errno, $error));
        }
        return $body;
    }

    public function getWellKnownClaims() {
        return $this->getWellKnownConfigValue('claims_supported');
    }

    public function getWellKnownScopes() {
        return $this->getWellKnownConfigValue('scopes_supported');
    }

    protected function startSession() {}

    protected function commitSession() {}

    protected function getSessionKey(string $key)
    {
        $result = $this->session->get($key, null);
        if (!is_string($result))
            return false;
        return unserialize($result, ['allowed_classes' => false]);
    }

    protected function setSessionKey(string $key, $value)
    {
        $this->session->set($key, serialize($value));
    }

    protected function unsetSessionKey(string $key)
    {
        $this->session->remove($key);
    }

    public function redirect(string $url)
    {
        $this->response->setHeader('Cache-Control', 'no-store');
        $this->response->redirect($url);
    }

    private static function stripWellKnown($providerUrl) {
        $position = strpos($providerUrl, '.well-known/');
        if ($position !== false)
            return substr($providerUrl, 0, $position);
        return $providerUrl;
    }

    private function phpseclib_autoload($namespace, $dir)
    {
        $split = '\\';
        $ns = trim($namespace, DIRECTORY_SEPARATOR . $split);

        return spl_autoload_register(
            function ($class) use ($ns, $dir, $split) {
                $prefix = $ns . $split;
                $base_dir = $dir . DIRECTORY_SEPARATOR;
                $len = strlen($prefix);
                if (strncmp($prefix, $class, $len)) {
                    return;
                }

                $relative_class = substr($class, $len);

                $file = $base_dir .
                    str_replace($split, DIRECTORY_SEPARATOR, $relative_class) .
                    '.php';

                if (file_exists($file)) {
                    require_once $file;
                }
            }
        );
    }
}
