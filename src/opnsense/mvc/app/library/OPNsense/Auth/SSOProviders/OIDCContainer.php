<?php

namespace OPNsense\Auth\SSOProviders;

use OPNsense\Core\Config;
use Generator;

class OIDCContainer implements ISSOContainer
{
    public function listProviders(): \Generator
    {
        $authServers = Config::getInstance()->object()->system->authserver;
        if ($authServers == null)
            return;

        if (!is_array($authServers)) // If a user only has one auth server, it is not an array >:(
            $authServers = [$authServers];

        foreach ($authServers as $server) {
            if ((string)$server->type !== 'oidc')
                continue;

            $name = (string)$server->name;
            $opts = [
                'service' => 'WebGui',
                'name' => $name,
                'login_uri' => "/api/oidc/auth/login?provider={$name}",
            ];

            $customButton = (string)$server->oidc_custom_button;
            if (!empty($customButton)) {
                $opts['html_content'] = $customButton;
                $iconUrl = "/api/oidc/auth/icon?provider={$name}";
                $opts['html_content'] = str_replace('%icon%', $iconUrl, $opts['html_content']);
                $opts['html_content'] = str_replace('%name%', $name, $opts['html_content']);
                $opts['html_content'] = str_replace('%url%', $opts['login_uri'], $opts['html_content']);
            }

            yield new OIDC($opts);
        }
    }
}
