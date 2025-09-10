<?php

namespace OPNsense\Oidc\Api;

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OIDC;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\Oidc\OidcClient;

/**
 * Class ServiceController
 * @package OPNsense\Cron
 */
class AuthController extends ApiControllerBase
{
    const ALLOW_USER_CREATION = false;

    public function doAuth()
    {
        return true;
    }

    public function iconAction()
    {
        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Missing authentication provider.";
        }

        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Not Found");
            return "Authentication provider not found.";
        }

        $url = $auth->oidcIconUrl;
        if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
            $this->response->setStatusCode(404, "Not Found");
            return "Invalid icon URL.";
        }
        // Proxy the image using cURL
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        $imageData = curl_exec($ch);
        $curlErr = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($imageData === false || $httpCode !== 200) {
            $this->response->setStatusCode(404, "Not Found");
            return "Unable to fetch icon. " . ($curlErr ?: "HTTP $httpCode");
        }

        $mimeType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $this->response->setHeader('Content-Type', $mimeType);
        $this->response->setHeader('Cache-Control', 'public, max-age=31536000, immutable'); // cache for 1 year, aggressive
        return $imageData;
    }

    /**
     * reconfigure HelloWorld
     */
    public function loginAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Already logged in.";
        }

        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Missing authentication provider.";
        }

        // $_SESSION['openid_connect_provider'] = $provider;
        $this->session->set('openid_connect_provider', $provider);
        $user = $this->authenticate($provider);

        $this->session->close();
        if ($user === false)
            return 'Redirecting...';
        return "Already logged in but session not setup. Please try again";
    }


    public function callbackAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Already logged in.";
        }

        $provider = $this->session->get('openid_connect_provider');
        if (empty($provider)) {
            $this->response->setStatusCode(404, "Authentication not found");
            return "Missing authentication provider. Please try the flow again.";
        }
        $this->session->remove('openid_connect_provider');

        // Check the OIDC flow
        $user = $this->authenticate($provider);
        if ($user === false) {
            $this->response->setStatusCode(400, "Authentication not found");
            return "Something went wrong while trying to login you in";
        }

        // Lookup existing local user
        $lookupUsername = $user->preferred_username ?? null;
        $lookupEmail    = $user->email ?? null;
        $localUser = $this->findLocalUser($lookupUsername, $lookupEmail);
        if ($localUser === false) {
            if (!self::ALLOW_USER_CREATION) {
                $this->response->setStatusCode(403, "User not found");
                return "No matching local account, and user creation disabled.";
            }

            // Create the user if allowed
            $localUser = $this->createLocalUser($lookupUsername, $lookupEmail);
            if ($localUser === false) {
                $this->response->setStatusCode(500, "User creation failed");
                return "Unable to create local account.";
            }
        }

        // Create the main login session and log the user in.
        $cnf = Config::getInstance()->object();
        $this->session->set('Username', $localUser['name']);
        $this->session->set('last_access', time());
        $this->session->set('protocol', strval($cnf->system->webgui->protocol));
        $this->session->set('oidc_user', $user);
        $this->session->close();
        $this->response->redirect('/');
        return 'Redirecting home...';
    }

    protected function authenticate($provider)
    {
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Authentication not found");
            return false;
        }

        /** @var OIDC $auth */
        $client = new OidcClient($auth, $this);
        $client->addScope(['openid', 'email', 'profile']);

        if (!$client->authenticate())
            return false;

        $user = $client->requestUserInfo();
        return $user;
    }

    /** Finds the local user that best matches the given username or email. */
    protected function findLocalUser($username, $email)
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return false;
        }

        foreach ($cnf->system->user as $user) {
            if (($username && (string)$user->name === $username) ||
                ($email && isset($user->email) && (string)$user->email === $email)
            ) {
                // return as array
                return [
                    'name'   => (string)$user->name,
                    'email'  => (string)$user->email,
                    'groups' => isset($user->groupname) ? explode(',', (string)$user->groupname) : []
                ];
            }
        }

        return false;
    }

    /** Creates a new local user. */
    protected function createLocalUser($username, $email)
    {
        if (!self::ALLOW_USER_CREATION)
            throw new \RuntimeException('Cannot create new users');

        // The following code was thrown together and not properly tested.
        throw new \RuntimeException('Not Yet Implemented / Tested.');

        $cnf = Config::getInstance()->object();
        $user = $cnf->system->user->addChild('user');
        $user->name     = $username;
        $user->descr    = "OIDC User";
        $user->scope    = "user";
        $user->disabled = "0";
        if (!empty($email)) {
            $user->email = $email;
        }
        // no password set, authentication handled via OIDC

        Config::getInstance()->save();
        return [
            'name'   => $username,
            'email'  => $email,
            'groups' => []
        ];
    }
}
