<?php

namespace OPNsense\Auth\SSOProviders;

use OPNsense\Core\Config;
use Generator;

class OIDCContainer implements ISSOContainer
{
    public function listProviders(): \Generator
    {
        $cnf = Config::getInstance()->object();
        if (!isset($cnf->system->authserver))
            return;

        // Only offer providers the administrator selected for the web GUI.
        $authmode = array_map('trim', explode(',', (string)($cnf->system->webgui->authmode ?? '')));

        foreach ($cnf->system->authserver as $server) {
            if ((string)$server->type !== 'oidc')
                continue;

            $name = (string)$server->name;
            if (!in_array($name, $authmode, true))
                continue;

            $opts = [
                // Explicit id: Provider defaults it to '', which made every OIDC
                // server share one key in AuthenticationFactory::listServers().
                'id' => $name,
                'service' => 'WebGui',
                'name' => $name,
                'login_uri' => '/api/oidc/auth/login?provider=' . rawurlencode($name),
            ];

            $customButton = (string)$server->oidc_custom_button;
            if (!empty($customButton)) {
                // Single-pass substitution with HTML-encoded values.
                $iconUrl = '/api/oidc/auth/icon?provider=' . rawurlencode($name);
                $opts['html_content'] = strtr($customButton, [
                    '%icon%' => htmlspecialchars($iconUrl, ENT_QUOTES),
                    '%name%' => htmlspecialchars($name, ENT_QUOTES),
                    '%url%'  => htmlspecialchars($opts['login_uri'], ENT_QUOTES),
                ]);
            }

            yield new OIDC($opts);
        }
    }
}
