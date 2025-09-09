<?php

namespace OPNsense\Oidc\Api;

require_once("config.inc");

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OIDC;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Mvc\Session;
use OPNsense\Oidc\OidcClient;

/**
 * Class ServiceController
 * @package OPNsense\Cron
 */
class AuthController extends ApiControllerBase
{
    protected static $requestCount = 0;

    public function doAuth()
    {
        return true;
    }


    public function initialize()
    {
        parent::initialize();
    }

    /**
     * reconfigure HelloWorld
     */
    public function loginAction()
    {
        $session = new Session();

        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return ["error" => "missing provider"];
        }

        $session->set('openid_connect_provider', $provider);
        $success = $this->authenticate($provider, $session);
        return ['success' => $success];
    }

    public function callbackAction()
    {
        $session = new Session();

        $provider = $session->get('openid_connect_provider', '');
        if (empty($provider)) {
            $this->response->setStatusCode(404, "Authentication not found");
            // TODO: Redirect to login
            return "Missing authentication provider. Please try the flow again.";
        }

        $success = $this->authenticate($provider, $session);
        if (!$success) {
            $this->response->setStatusCode(400, "Authentication not found");
            return "Something went wrong while trying to login you in";
        }

        return "Welcome!";
    }

    protected function authenticate($provider, $session) {
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Authentication not found");
            return ["error" => "missing provider"];
        }

        /** @var OIDC $auth */
        $client = new OidcClient($auth, $session, $this);
        return $client->authenticate();
    }
}
