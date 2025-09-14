<?php

namespace OPNsense\Oidc\Api;

use InvalidArgumentException;
use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OIDC;
use OPNsense\Auth\User;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Base\FieldTypes\ArrayField;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Oidc\OidcClient;
use RuntimeException;

/**
 * Class ServiceController
 * @package OPNsense\Cron
 */
class DiscoverController extends ApiControllerBase
{
    /** Tests the credentails and what are current available */
    public function availableAction()
    {
        // Prepare the auth
        $auth = null;
        if ($this->request->hasQuery('provider')) {
            $auth = (new AuthenticationFactory())->get($this->request->getQuery('provider'));
        } else if ($this->request->hasPost('oidc_provider_url')) {
            $auth = new OIDC();
            $auth->setProperties($this->request->getPost());
        }

        if ($auth === null || !$auth instanceof OIDC || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Authentication not found");
            return ["errorMessage" => "Authentication provider not found."];
        }

        // Test the client
        try {
            /** @var OIDC $auth */
            $client = new OidcClient($auth, $this);
            return [
                'issuer' => $client->getWellKnownIssuer(),
                'claims' => $client->getWellKnownClaims(),
                'scopes' => $client->getWellKnownScopes(),
            ];
        } catch (\Exception $e) {
            $this->response->setStatusCode(500, "Server Error");
            return ["errorMessage" => $e->getMessage()];
        }
    }
}
