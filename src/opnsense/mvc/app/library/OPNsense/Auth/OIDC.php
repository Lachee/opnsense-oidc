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
class OIDC extends Base implements IAuthConnector
{
    /**
     * @var string Discovery URL
     */
    public $oidcDiscoveryUrl = null;

    public $oidcClientId = null;

    public $oidcClientSecret = null;

    public $caseInSensitiveUsernames = true;

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
            'oidc_discovery_url' => 'oidcDiscoveryUrl',
            'oidc_client_id' => 'oidcClientId',
            'oidc_client_secret' => 'oidcClientSecret',
        ];

        // >> map properties 1-on-1
        foreach ($confMap as $confSetting => $objectProperty) {
            if (!empty($config[$confSetting]) && property_exists($this, $objectProperty)) {
                $this->$objectProperty = $config[$confSetting];
            }
        }

        // >> translate config settings
        // ( eg map Secure to https:// and Unsecure to http:// )

        if (!empty($config['caseInSensitiveUsernames'])) {
            $this->caseInSensitiveUsernames = true;
        }
    }

    /**
     * retrieve configuration options
     * @return array
     */
    public function getConfigurationOptions()
    {
        $options = [
            'radius_secret' => [
                'name' => gettext('Client ID'),
                'help' => gettext('The Client ID'),
                'type' => 'text',
                'validate' => fn($value) => !empty($value) ? [] : [gettext('Client ID must not be empty.')]
            ],
            'oidc_discovery_url' => [
                'name' => gettext('Discovery URL'),
                'help' => gettext('The full URL to the discovery json. It is usually in the /.well-known/.'),
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
            'caseInSensitiveUsernames' => [
                "name" => gettext("Match case insensitive"),
                "help" => gettext("Allow mixed case input when gathering local user settings."),
                "type" => "checkbox",
                "validate" => fn($value) => [],
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
     * check if password meets policy constraints
     * @param string $username username to check
     * @param string $old_password current password
     * @param string $new_password password to check
     * @return array of unmet policy constraints
     */
    public function checkPolicy($username, $old_password, $new_password)
    {
        $result = [];
        $configObj = Config::getInstance()->object();
        if (!empty($configObj->system->webgui->enable_password_policy_constraints)) {
            if (!empty($configObj->system->webgui->password_policy_length)) {
                if (strlen($new_password) < $configObj->system->webgui->password_policy_length) {
                    $result[] = sprintf(
                        gettext("Password must have at least %d characters"),
                        $configObj->system->webgui->password_policy_length
                    );
                }
            }
            if (!empty($configObj->system->webgui->password_policy_complexity)) {
                $pwd_has_upper = preg_match_all('/[A-Z]/', $new_password, $o) > 0;
                $pwd_has_lower = preg_match_all('/[a-z]/', $new_password, $o) > 0;
                $pwd_has_number = preg_match_all('/[0-9]/', $new_password, $o) > 0;
                $pwd_has_special = preg_match_all('/[!@#$%^&*()\-_=+{};:,<.>]/', $new_password, $o) > 0;
                if ($old_password == $new_password) {
                    // equal password is not allowed
                    $result[] = gettext("Current password equals new password");
                }
                if (($pwd_has_upper + $pwd_has_lower + $pwd_has_number + $pwd_has_special) < 3) {
                    // passwords should at least contain 3 of the 4 available character types
                    $result[] = gettext("Password should contain at least 3 of the 4 different character groups" .
                        " (lowercase, uppercase, number, special)");
                } elseif (strpos($new_password, $username) !== false) {
                    $result[] = gettext("The username may not be a part of the password");
                }
            }
        }
        return $result;
    }

    /**
     * check if the user should change his or her password,
     * calculated by the time difference of the last pwd change
     * and other criteria through checkPolicy() if password was
     * given
     * @param string $username username to check
     * @param string $password password to check
     * @return boolean
     */
    public function shouldChangePassword($username, $password = null)
    {
        $configObj = Config::getInstance()->object();
        if (!empty($configObj->system->webgui->enable_password_policy_constraints)) {
            $userObject = $this->getUser($username);
            if ($userObject != null) {
                if (!empty($configObj->system->webgui->password_policy_duration)) {
                    $now = microtime(true);
                    $pwdChangedAt = empty($userObject->pwd_changed_at) ? 0 : $userObject->pwd_changed_at;
                    if (abs($now - $pwdChangedAt) / 60 / 60 / 24 >= $configObj->system->webgui->password_policy_duration) {
                        return true;
                    }
                }
                if (!empty($configObj->system->webgui->password_policy_compliance)) {
                    /* if compliance is required make sure the user has a SHA-512 hash as password */
                    if (strpos((string)$userObject->password, '$6$') !== 0) {
                        return true;
                    }
                }
            }
        }
        if ($password != null) {
            /* not optimal, modify "old_password" to avoid equal check */
            if (count($this->checkPolicy($username, '~' . $password, $password))) {
                return true;
            }
        }
        return false;
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
