<?php

namespace OPNsense\Oidc;

use OPNsense\Auth\Base;
use OPNsense\Oidc\Models\Oidc;

class OidcAuth extends Base
{
    private $config = null;

    public function __construct()
    {
        $mdlOidc = new Oidc();
        $this->config = $mdlOidc->getNodeByReference('general');
    }

    public function authenticate($username, $password)
    {
        // OIDC authentication is handled via web flow
        // This method is called for API authentication
        return false;
    }

    public function getLastAuthProperties()
    {
        return [];
    }

    public function setProperties($properties)
    {
        // Not used for OIDC
    }
}
