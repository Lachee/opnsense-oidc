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
    public $oidcMatchEmail = false;
    /** Off by default: unset/unticked means email_verified is required. */
    public $oidcAllowUnverifiedEmail = false;
    public $oidcForceLogin = false;
    public $oidcUsernameClaim = 'preferred_username';
    public $oidcDefaultGroups = [];
    public $oidcScopes = [
        'openid',
        'email',
        'profile',
    ];

    public $oidcAuthorizationEndpoint = null;
    public $oidcTokenEndpoint = null;
    public $oidcUserInfoEndpoint = null;

    public $oidcCustomButton = null;
    public $oidcIconUrl = null;
    /** @var string comma-separated "localuser=subject" pairs; see getSubjectBindings() */
    public $oidcSubjectBinding = '';


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
            'oidc_username_claim' => 'oidcUsernameClaim',
            'oidc_match_email' => 'oidcMatchEmail',
            'oidc_allow_unverified_email' => 'oidcAllowUnverifiedEmail',
            'oidc_force_login' => 'oidcForceLogin',
            'oidc_subject_binding' => 'oidcSubjectBinding',
        ];

        // >> map properties 1-on-1
        foreach ($confMap as $confSetting => $objectProperty) {
            if (!empty($config[$confSetting]) && property_exists($this, $objectProperty)) {
                $this->$objectProperty = $config[$confSetting];
            }
        }

        $this->oidcDefaultGroups = array_filter(explode(',', $config['oidc_default_groups'] ?? ''));
        if (!empty($config['oidc_scopes'])) {
            $this->oidcScopes = explode(',', $config['oidc_scopes']);
        }
    }

    /**
     * Parses the subject binding setting into [localuser => subject].
     * @return array<string,string>
     */
    public function getSubjectBindings(): array
    {
        $bindings = [];
        foreach (preg_split('/[\s,]+/', (string)$this->oidcSubjectBinding, -1, PREG_SPLIT_NO_EMPTY) as $pair) {
            $parts = explode('=', $pair, 2);
            if (count($parts) === 2 && $parts[0] !== '' && $parts[1] !== '') {
                $bindings[$parts[0]] = $parts[1];
            }
        }
        return $bindings;
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
                'help' => gettext('URL to the OpenID Connect provider. Either the root or the <code>/.well-known/openid-configuration</code> path.') . ' ' . $callbackURL,
                'type' => 'text',
                'validate' => fn($value) => (filter_var($value, FILTER_VALIDATE_URL) && stripos((string)$value, 'https://') === 0)
                    ? [] : [gettext('Discovery needs a valid https:// URL.')],

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
            'oidc_username_claim' => [
                'name' => gettext('Username claim'),
                'help' => gettext('The claim to use as local username. The claim must be provided by the OpenID Connect provider. Usually this is <code>preferred_username</code> or <code>email</code>. With <code>email</code>, the address must be marked <code>email_verified</code> unless "Allow unverified email" is ticked.'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Username claim must not be empty.')]
            ],
            'oidc_scopes' => [
                'name' => gettext('Scopes'),
                'help' => gettext('Scopes to request during authentication. The <code>openid</code> scope is required.'),
                'type' => 'text',
                'default' => join(',', $this->oidcScopes),
                'validate' => fn($value) => [],
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
            'oidc_match_email' => [
                'name' => gettext('Match by email'),
                'help' => gettext('Also match local accounts by the email claim when the username claim does not match. Only addresses the provider marks <code>email_verified</code> are used unless "Allow unverified email" is ticked. Only enable this if users cannot change their email address at the provider.'),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'oidc_allow_unverified_email' => [
                'name' => gettext('Allow unverified email'),
                'help' => gettext('By default the email claim is only used (for "Match by email", for new accounts, and as the username when the username claim is <code>email</code>) when the provider marks it <code>email_verified</code>. Tick this only for a provider that never sends <code>email_verified</code> and does not let users set their own address.'),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'oidc_force_login' => [
                'name' => gettext('Require fresh login'),
                'help' => gettext('Send prompt=login so the provider re-authenticates the user on every firewall login instead of reusing an existing provider session.'),
                'type' => 'checkbox',
                'validate' => fn($value) => [],
            ],
            'oidc_subject_binding' => [
                'name' => gettext('Subject binding'),
                'help' => gettext('Optional. Comma-separated <code>localuser=subject</code> pairs. When set, each local account can only be signed into by the provider subject (<code>sub</code> claim) bound to it, and accounts not listed are refused. The subject is written to the system log (<code>oidc</code>) on every OIDC login attempt. With "Automatic user creation", only bound names are created.'),
                'type' => 'text',
                'validate' => fn($value) => empty($value) || preg_match('/^\s*[^=\s,]+=[^=\s,]+(\s*[,\s]\s*[^=\s,]+=[^=\s,]+)*\s*$/', (string)$value)
                    ? [] : [gettext('Use comma-separated localuser=subject pairs.')],
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
                'help' => gettext('https URL to a small icon representing the OIDC provider (16x16 or 32x32; PNG, JPEG, GIF or WebP, max 256 KB). The image is proxied for the login page.'),
                'type' => 'text',
                'validate' => fn($value) => empty($value) || (filter_var($value, FILTER_VALIDATE_URL) && stripos((string)$value, 'https://') === 0) ? [] : [gettext('Icon URL needs a valid https:// URL.')],
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

    /**
     * IAuthConnector contract: preauth() returns the connector so callers can
     * chain ->authenticate() (CaptivePortal AccessController does). Returning
     * false would turn a misconfigured zone into a fatal error.
     */
    public function preauth($config)
    {
        return $this;
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
        // Inlined into a <script> element: escape <, >, &, quotes.
        $availableGroupsJson = json_encode($availableGroups, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

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
$('[name=oidc_client_secret]').attr({ type: 'password', autocomplete: 'off' });
$('[name=oidc_custom_button]').each((i, elm) => {
    const ta = $('<textarea>');
    $.each(elm.attributes, (_, attr) => ta.attr(attr.name, attr.value));
    ta.data($(elm).data());
    ta.val($(elm).val());
    $(elm).replaceWith(ta);
});

// Test button
$(function() {
    $('#submit').after(
        $('<button>')
        .attr({ class: 'btn btn-primary auth_options auth_oidc', style: 'margin-left: 10px' })
        .text('Test')
        .on('click', async (e) => {
            e.preventDefault();

            const data = {};
            $('[name^=oidc_]').each((i, e) => data[$(e).attr('name')] = $(e).val()); 

            $.ajax({
                type: "POST",
                url: '/api/oidc/discover/available',
                data,
                success: function (data) {
                    if (data.errorMessage) {
                        BootstrapDialog.show({
                            title: 'OpenID Connect Test - Failed',
                            message: $('<p>').text(String(data.errorMessage || 'Unknown error has occured.')),
                            type: BootstrapDialog.TYPE_DANGER
                        });
                        return;
                    }

                    // Provider-supplied values are rendered as text, never HTML.
                    const box = $('<div>').append($('<p>').text('Successfully connected to the well-known.'));
                    const list = (title, items) => {
                        if (!Array.isArray(items) || items.length === 0) return;
                        box.append($('<h5>').text(title));
                        const ul = $('<ul>');
                        items.forEach(i => ul.append($('<li>').text(String(i))));
                        box.append(ul);
                    };
                    list('Claims', data.claims);
                    list('Scopes', data.scopes);
                    box.append($('<hr>'), $('<p>').text('This does not test the client secret or id.'));
                    BootstrapDialog.show({
                        title: 'OpenID Connect Test - Success',
                        message: box,
                        type: BootstrapDialog.TYPE_SUCCESS
                    });
                },
                error: function(jqXHR) {
                    BootstrapDialog.show({
                        title: 'OpenID Connect Test - Failed',
                        message: $('<p>').text(String(jqXHR.responseJSON?.errorMessage || jqXHR.responseText || 'Request failed.')),
                        type: BootstrapDialog.TYPE_DANGER
                    });
                }
            });
        })
    );
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
