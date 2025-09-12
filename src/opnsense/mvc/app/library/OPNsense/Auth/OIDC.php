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
    public $oidcCreateUsers = false;

    public $oidcDefaultGroups = [];

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
        return "<i class='fa fa-key-o fa-fw fa-brands fa-openid'></i> " . gettext('OpenID Connect');
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
            'oidc_create_users' => 'oidcCreateUsers',
        ];

        // >> map properties 1-on-1
        foreach ($confMap as $confSetting => $objectProperty) {
            if (!empty($config[$confSetting]) && property_exists($this, $objectProperty)) {
                $this->$objectProperty = $config[$confSetting];
            }
        }

        $this->oidcDefaultGroups = explode(',', $config['oidc_default_groups']);
    }

    /**
     * retrieve configuration options
     * @return array
     */
    public function getConfigurationOptions()
    {

        $callbackURL = gettext("Set your callback URL to <code>https://{opnsense-ip}/api/oidc/auth/callback</code>.");
        $options = [
            // Configuration
            'oidc_provider_url' => [
                'name' => gettext('Provider URL'),
                'help' => gettext('URL to the OpenID Connect provider. The provider must contain a <code>/.well-known/openid-configuration</code>.') . ' ' . $callbackURL,
                'type' => 'text',
                'validate' => fn($value) => filter_var($value, FILTER_VALIDATE_URL) ? [] : [gettext('Discovery needs a valid URL.')],

            ],
            'oidc_client_id' => [
                'name' => gettext('Client ID'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Client ID must not be empty.')]
            ],
            'oidc_client_secret' => [
                'name' => gettext('Client Secret'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Client Secret must not be empty. "Public Clients" are not supported.')]
            ],

            // Advance
            'oidc_create_users' => [
                'name' => gettext('Automatic user creation'),
                'help' => gettext(
                    "To be used in combination with synchronize or default groups, allow the authenticator to create new local users after " .
                        "successful login with group memberships returned for the user."
                ),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'oidc_default_groups' => [
                'name' => gettext('Default groups'),
                'help' => gettext("Group(s) to add by default when creating users"),
                'type' => 'text',
                'default' => join(',', $this->oidcDefaultGroups)
            ],

            // Decorative
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
            '__oidc_script' => [
                'name' => '',
                'help' => "<style>{$this->getConfigurationStyle()}</style><script>{$this->getConfigurationScript()}</script>"
            ]
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

    public function preauth($username)
    {
        return false;
    }

    public function authenticate($username, $password)
    {
        return false;
    }

    protected function getConfigurationScript()
    {
        $availableGroups = [];
        foreach (config_read_array('system', 'group') as $group)
            $availableGroups[$group['name']] = $group['name'];
        $availableGroupsJson = json_encode($availableGroups);
        
        // These are a hack to get the UI to behave. 
        return <<<JS
// Handle custom group selector
$('[name=oidc_default_groups]')
    .attr({ type: 'hidden' })
    .after(
        $('<select>')
            .attr('id', 'oidc_default_groups_select')
            .attr('multiple', true)
            .attr('class', 'selectpicker')
            .on('change', function() {
                const selected = $(this).val() || [];
                $('[name=oidc_default_groups]').val(selected.join(','));
            })
            .append(
                Object.entries($availableGroupsJson).map(([key, value]) =>
                    $('<option>').val(key).text(value).attr({ selected: $('[name=oidc_default_groups]').val().split(',').includes(key) })
                )
            )
    );

// Handle changing field types
$('[name=oidc_custom_button]').attr({ rows: 10 })
$('[name=oidc_client_secret]').attr({ type: 'password' });
$('[name=oidc_custom_button]').each((i, elm) => {
    const ta = $('<textarea>');
    $.each(elm.attributes, (_, attr) => ta.attr(attr.name, attr.value));
    ta.data($(elm).data());
    ta.val($(elm).val());
    $(elm).replaceWith(ta);
});
JS;
    }

    protected function getConfigurationStyle()
    {
        return <<<CSS
        .auth_oidc:has(.oidc-icon) input { 
            float: left;
        }
        .oidc-icon {
            width: 32px;
            height: 32px;
        }
        .auth_oidc:has(#help_for_field_oidc___oidc_script)
         {
            display: none !important;
        }
CSS;
    }
}
