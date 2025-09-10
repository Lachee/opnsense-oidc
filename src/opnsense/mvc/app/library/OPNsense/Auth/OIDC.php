<?php

/*
 * Copyright (C) 2015-2023 Deciso B.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Auth;

use OPNsense\Core\Config;

/**
 * Class Local user database connector (using legacy xml structure).
 * @package OPNsense\Auth
 */
class OIDC extends Local implements IAuthConnector
{
    public $oidcProviderUrl = null;

    public $oidcClientId = null;

    public $oidcClientSecret = null;

    public $oidcAuthorizationEndpoint = null;
    public $oidcTokenEndpoint = null;
    public $oidcUserInfoEndpoint = null;

    public $oidcCustomButton = null;
    public $oidcIconUrl = null;


    /**
     * type name in configuration
     * @return string
     */
    public static function getType()
    {
        return 'oidc';
    }

    /**
     * user friendly description of this authenticator
     * @return string
     */
    public function getDescription()
    {
        return gettext('OpenID Connect');
    }

    /**
     * set connector properties
     * @param array $config connection properties
     */
    public function setProperties($config)
    {
        $confMap = [
            'oidc_provider_url' => 'oidcProviderUrl',
            'oidc_client_id' => 'oidcClientId',
            'oidc_client_secret' => 'oidcClientSecret',
            'oidc_custom_button' => 'oidcCustomButton',
            'oidc_authorization_endpoint' => 'oidcAuthorizationEndpoint',
            'oidc_token_endpoint' => 'oidcTokenEndpoint',
            'oidc_userinfo_endpoint' => 'oidcUserInfoEndpoint',
            'oidc_icon_url' => 'oidcIconUrl',
        ];

        // >> map properties 1-on-1
        foreach ($confMap as $confSetting => $objectProperty) {
            if (!empty($config[$confSetting]) && property_exists($this, $objectProperty)) {
                $this->$objectProperty = $config[$confSetting];
            }
        }
    }

    /**
     * retrieve configuration options
     * @return array
     */
    public function getConfigurationOptions()
    {
        $callbackURL = gettext("Set your callback URL to <code>https://<ip of opnsense>/api/oidc/auth/callback</code>.");
        $options = [
            'oidc_provider_url' => [
                'name' => gettext('Provider URL'),
                'help' => gettext('The full URL to the discovery json. It is usually in the /.well-known/. ') . $callbackURL,
                'type' => 'text',
                'validate' => fn($value) => filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Discovery needs a valid URL.')],

            ],
            'oidc_client_id' => [
                'name' => gettext('Client ID'),
                'help' => gettext('The Client ID'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Client ID must not be empty.')]
            ],
            'oidc_client_secret' => [
                'name' => gettext('Client Secret'),
                'help' => gettext('The Client Secret'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Client Secret must not be empty. "Public Clients" are not supported.')]
            ],
            'oidc_icon_url' => [
                'name' => gettext('Icon URL'),
                'help' => gettext('URL to an icon representing the OIDC provider. This should be a small image (16x16 or 32x32) in either PNG or SVG format. This image will be proxied.'),
                'type' => 'text',
                'validate' => fn($value) => empty($value) || filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Icon URL needs a valid URL.')],
            ],
            'oidc_custom_button' => [
                'name' => gettext('Custom Button'),
                'help' => gettext('Custom HTML Button. The templated <code>%name%</code>, <code>%url%</code>, and <code>%icon%</code> are available.'),
                'type' => 'text',
                'validate' => fn($value) => [],
            ],

            // Not Used: Discovery is only supported at the moment
            // 'oidc_authorization_endpoint' => [
            //     'name' => gettext('Authorization Endpoint'),
            //     'help' => gettext('URL endpoint for the authorization. This is provided on discovery. ') . $callbackURL,
            //     'type' => 'text',
            //     'validate' => fn($value) => empty($value) || filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Discovery needs a valid URL.')],
            // ],
            // 'oidc_token_endpoint' => [
            //     'name' => gettext('Token Endpoint'),
            //     'help' => gettext('URL endpoint for the token. This is provided on discovery.'),
            //     'type' => 'text',
            //     'validate' => fn($value) => empty($value) || filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Discovery needs a valid URL.')],
            // ],
            // 'oidc_userinfo_endpoint' => [
            //     'name' => gettext('User Info Endpoint'),
            //     'help' => gettext('URL endpoint for the user info. This is provided on discovery.'),
            //     'type' => 'text',
            //     'validate' => fn($value) => empty($value) || filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Discovery needs a valid URL.')],
            // ],
        ];

        return $options;
    }

    /**
     * unused
     * @return array mixed named list of authentication properties
     */
    public function getLastAuthProperties()
    {
        return [];
    }

    /**
     * authenticate user against local database (in config.xml)
     * @param string|SimpleXMLElement $username username (or xml object) to authenticate
     * @param string $password user password
     * @return bool authentication status
     */
    protected function _authenticate($username, $password)
    {
        $userObject = $this->getUser($username);
        if ($userObject != null) {
            if (!empty((string)$userObject->disabled)) {
                // disabled user
                return false;
            }
            if (
                !empty($userObject->expires)
                && strtotime("-1 day") > strtotime(date("m/d/Y", strtotime((string)$userObject->expires)))
            ) {
                // expired user
                return false;
            }
            if (password_verify($password, (string)$userObject->password)) {
                // password ok, return successfully authentication
                return true;
            }
        }

        return false;
    }
}
