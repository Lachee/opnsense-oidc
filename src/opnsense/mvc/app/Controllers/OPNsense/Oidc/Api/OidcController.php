<?php


namespace OPNsense\Oidc\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Oidc\Models\Oidc;
use OPNsense\Core\Config;

class OidcController extends ApiControllerBase
{
    private function logDebug($message)
    {
        $mdlOidc = new Oidc();
        $oidcNode = $mdlOidc->getNodeByReference('general');

        if ((string)$oidcNode->debug_logging == '1') {
            syslog(LOG_INFO, "OIDC: " . $message);
        }
    }

    private function discoverEndpoints($providerUrl)
    {
        $wellKnownUrl = rtrim($providerUrl, '/') . '/.well-known/openid-configuration';

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $wellKnownUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_USERAGENT => 'OPNsense OIDC Plugin/1.0',
            CURLOPT_HTTPHEADER => ['Accept: application/json']
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($httpCode !== 200) {
            $this->logDebug("Failed to discover OIDC endpoints: HTTP {$httpCode}");
            return false;
        }

        if ($error) {
            $this->logDebug("cURL error during discovery: {$error}");
            return false;
        }

        $discovery = json_decode($response, true);
        if (!$discovery) {
            $this->logDebug("Failed to parse OIDC discovery document");
            return false;
        }

        $this->logDebug("Successfully discovered OIDC endpoints");
        return $discovery;
    }

    public function authAction()
    {
        $mdlOidc = new Oidc();
        $oidcNode = $mdlOidc->getNodeByReference('general');

        if ((string)$oidcNode->enabled != '1') {
            return ['error' => 'OIDC authentication is not enabled'];
        }

        $providerUrl = (string)$oidcNode->provider_url;
        $clientId = (string)$oidcNode->client_id;
        $scopes = (string)$oidcNode->scopes;

        $discovery = $this->discoverEndpoints($providerUrl);
        if (!$discovery) {
            return ['error' => 'Failed to discover OIDC endpoints'];
        }

        // Generate state for CSRF protection
        $state = bin2hex(random_bytes(32));
        $_SESSION['oidc_state'] = $state;

        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $redirectUri = $protocol . '://' . $host . '/api/oidc/callback';

        $authParams = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $scopes,
            'state' => $state
        ];

        $authUrl = $discovery['authorization_endpoint'] . '?' . http_build_query($authParams);

        $this->logDebug("Redirecting to OIDC provider for authentication");

        return [
            'status' => 'redirect',
            'url' => $authUrl
        ];
    }

    public function callbackAction()
    {
        $mdlOidc = new Oidc();
        $oidcNode = $mdlOidc->getNodeByReference('general');

        if ((string)$oidcNode->enabled != '1') {
            $this->response->redirect('/');
            return;
        }

        $code = $this->request->getQuery('code');
        $state = $this->request->getQuery('state');
        $error = $this->request->getQuery('error');

        if ($error) {
            $this->logDebug("OIDC error: {$error}");
            $this->response->redirect('/?error=oidc_error');
            return;
        }

        if (!$code || !$state) {
            $this->logDebug("Missing code or state parameter");
            $this->response->redirect('/?error=invalid_request');
            return;
        }

        // Verify state to prevent CSRF
        if (!isset($_SESSION['oidc_state']) || $_SESSION['oidc_state'] !== $state) {
            $this->logDebug("Invalid state parameter - possible CSRF attack");
            $this->response->redirect('/?error=invalid_state');
            return;
        }

        unset($_SESSION['oidc_state']);

        $providerUrl = (string)$oidcNode->provider_url;
        $clientId = (string)$oidcNode->client_id;
        $clientSecret = (string)$oidcNode->client_secret;

        $discovery = $this->discoverEndpoints($providerUrl);
        if (!$discovery) {
            $this->response->redirect('/?error=discovery_failed');
            return;
        }

        // Exchange code for tokens
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $redirectUri = $protocol . '://' . $host . '/api/oidc/callback';

        $tokenData = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => $clientId,
            'client_secret' => $clientSecret
        ];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $discovery['token_endpoint'],
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($tokenData),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json'
            ]
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            $this->logDebug("Token exchange failed: HTTP {$httpCode}");
            $this->response->redirect('/?error=token_exchange_failed');
            return;
        }

        $tokens = json_decode($response, true);
        if (!$tokens || !isset($tokens['id_token'])) {
            $this->logDebug("Invalid token response");
            $this->response->redirect('/?error=invalid_token_response');
            return;
        }

        // Parse ID token
        $userInfo = $this->parseIdToken($tokens['id_token']);
        if (!$userInfo) {
            $this->logDebug("Failed to parse ID token");
            $this->response->redirect('/?error=invalid_id_token');
            return;
        }

        // Authenticate user
        $user = $this->authenticateUser($userInfo);
        if (!$user) {
            $this->logDebug("User authentication failed");
            $this->response->redirect('/?error=authentication_failed');
            return;
        }

        // Set session
        $sessionTimeout = (string)$oidcNode->session_timeout ?: 3600;
        $_SESSION['Username'] = $user['name'];
        $_SESSION['last_access'] = time();
        $_SESSION['session_timeout'] = $sessionTimeout;

        $this->logDebug("User {$user['name']} successfully authenticated via OIDC");

        // Redirect to main interface
        $this->response->redirect('/');
    }

    private function parseIdToken($idToken)
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            return false;
        }

        $payload = base64_decode(str_pad(
            strtr($parts[1], '-_', '+/'),
            strlen($parts[1]) % 4,
            '=',
            STR_PAD_RIGHT
        ));

        return json_decode($payload, true);
    }

    private function authenticateUser($userInfo)
    {
        $mdlOidc = new Oidc();
        $oidcNode = $mdlOidc->getNodeByReference('general');

        $username = $userInfo['preferred_username'] ?? $userInfo['email'] ?? $userInfo['sub'];
        $email = $userInfo['email'] ?? '';
        $name = $userInfo['name'] ?? $username;

        $this->logDebug("Authenticating user: {$username}");

        $config = Config::getInstance()->object();

        // Check if user exists
        $userExists = false;
        if (isset($config->system->user)) {
            foreach ($config->system->user as $user) {
                if ((string)$user->name === $username) {
                    $userExists = true;
                    $this->logDebug("Existing user found: {$username}");
                    return ['name' => $username, 'scope' => (string)$user->scope];
                }
            }
        }

        // Auto-create user if enabled
        if (!$userExists && (string)$oidcNode->auto_create_users === '1') {
            $this->logDebug("Auto-creating user: {$username}");

            if (!isset($config->system->user)) {
                $config->system->user = [];
            }

            $newUser = $config->system->addChild('user');
            $newUser->addChild('name', $username);
            $newUser->addChild('descr', 'OIDC User: ' . $name);
            $newUser->addChild('scope', 'user');
            $newUser->addChild('email', $email);

            // Set privileges based on group membership
            if (isset($userInfo['groups'])) {
                $groups = is_array($userInfo['groups']) ? $userInfo['groups'] : [$userInfo['groups']];

                $adminGroup = (string)$oidcNode->admin_group;
                $userGroup = (string)$oidcNode->user_group;

                if ($adminGroup && in_array($adminGroup, $groups)) {
                    $newUser->scope = 'system';
                    $this->logDebug("User {$username} granted admin privileges");
                } elseif ($userGroup && in_array($userGroup, $groups)) {
                    $newUser->scope = 'user';
                    $this->logDebug("User {$username} granted user privileges");
                }
            }

            Config::getInstance()->save();

            return ['name' => $username, 'scope' => (string)$newUser->scope];
        }

        $this->logDebug("User authentication failed: {$username}");
        return false;
    }

    public function statusAction()
    {
        $mdlOidc = new Oidc();
        $oidcNode = $mdlOidc->getNodeByReference('general');

        return [
            'enabled' => (string)$oidcNode->enabled === '1',
            'provider_url' => (string)$oidcNode->provider_url,
            'client_id' => (string)$oidcNode->client_id
        ];
    }
}
