<?php

namespace OPNsense\Oidc\Api;

require_once("config.inc");

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OIDC;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

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

    /**
     * reconfigure HelloWorld
     */
    public function loginAction()
    {
        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return [ "error" => "missing provider" ];
        }

        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Authentication not found");
            return [ "error" => "missing provider" ];
        }

        /** @var OIDC $auth */
        if (empty($auth->oidcAuthorizationEndpoint))
            $auth->populateWithDiscovery(); // TODO: Figure out how to save this again
        

        $endpoint = $auth->oidcAuthorizationEndpoint;
        $params = [
            'response_type' => 'code',
            'client_id' => $auth->oidcClientId,
            'scope' => join(',', [ 'openid', 'email', 'profile' ]),
            'redirect_uri' =>  "{$this->request->getScheme()}://{$this->request->getHeader('HOST')}/api/oidc/auth/callback",
            'state' => rand(),
        ];

        $this->response->redirect("{$endpoint}?" . http_build_query($params));
        return [
            'endpoint' => $endpoint,
            'params' => $params,
        ];
    }

    public function callbackAction() {
        $code = $this->request->get('code');
        $state = $this->request->get('state');
        $iss = $this->request->get('iss');
        return [ 'error' => 'Not Yet Implemented' ];
    }
}
