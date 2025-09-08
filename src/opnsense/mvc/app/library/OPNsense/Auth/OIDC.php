<?php

namespace OPNsense\Auth;

class OIDC extends Base implements IAuthConnector {
    
    /**
     * @return string type of this authenticator
     */
    public static function getType() {
        return 'oidc';
    }

    /**
     * set connector properties
     * @param array $config set configuration for this connector to use
     */
    public function setProperties($config) {}

    /**
     * after authentication, you can call this method to retrieve optional return data from the authenticator
     * @return mixed named list of authentication properties, may be returned by the authenticator
     */
    public function getLastAuthProperties() {
        return [];
    }

    /**
     * after authentication, you can call this method to retrieve optional authentication errors
     * @return array of auth errors
     */
    public function getLastAuthErrors() {
        return [];
    }

    /**
     * set session-specific pre-authentication metadata for the authenticator
     * @param array $config set configuration for this connector to use
     * @return IAuthConnector
     */
    public function preauth($config) {
        return $this;
    }

    /**
     * authenticate user
     * @param string $username username to authenticate
     * @param string $password user password
     * @return bool
     */
    public function authenticate($username, $password) {
        return false;
    }
}