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
        // Makes the firewall fetch a URL taken from the request: full admins
        // only, explicitly (the plugin ships no ACL.xml, so this endpoint is
        // only reachable through the page-all wildcard anyway).
        $this->throwNotFullAdmin();

        // Prepare the auth
        $auth = null;
        if ($this->request->hasQuery('provider')) {
            $provider = $this->request->getQuery('provider');
            $auth = is_string($provider) ? (new AuthenticationFactory())->get($provider) : null;
        } elseif ($this->request->hasPost('oidc_provider_url')) {
            $post = $this->request->getPost();
            $url = $post['oidc_provider_url'] ?? null;
            if (!is_string($url) || !filter_var($url, FILTER_VALIDATE_URL) || stripos($url, 'https://') !== 0) {
                $this->response->setStatusCode(400, "Bad Request");
                return ["errorMessage" => "Provider URL must be a valid https:// URL."];
            }
            $auth = new OIDC();
            $auth->setProperties(array_filter($post, 'is_string'));
        }

        if ($auth === null || !$auth instanceof OIDC || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Authentication not found");
            return ["errorMessage" => "Authentication provider not found."];
        }

        // Test the client
        try {
            /** @var OIDC $auth */
            // Metadata only: this client never redirects, so the host is a placeholder.
            $client = new OidcClient($auth, $this, 'localhost');
            return [
                'issuer' => $client->getWellKnownIssuer(),
                'claims' => $client->getWellKnownClaims(),
                'scopes' => $client->getWellKnownScopes(),
            ];
        } catch (\Throwable $e) {
            $this->response->setStatusCode(500, "Server Error");
            return ["errorMessage" => $e->getMessage()];
        }
    }
}
