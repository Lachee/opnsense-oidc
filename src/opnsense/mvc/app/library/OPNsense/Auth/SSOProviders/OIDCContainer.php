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
            if ($server['type'] !== 'oidc')
                continue;

            $opts = [
                'service' => 'WebGui',
                'name' => $server['name'],
                'login_uri' => "/api/oidc/auth/login?provider={$server['name']}",
            ];

            if (!empty($server['oidc_custom_button'])) {
                $opts['html_content'] = $server['oidc_custom_button'];

                $iconUrl = "/api/oidc/auth/icon?provider={$server['name']}";
                $opts['html_content'] = str_replace('%icon%', $iconUrl, $opts['html_content']);
                $opts['html_content'] = str_replace('%name%', $opts['name'], $opts['html_content']);
                $opts['html_content'] = str_replace('%url%', $opts['login_uri'], $opts['html_content']);
            }

            yield new OIDC($opts);
        }
    }
}
