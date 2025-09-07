<?php

namespace OPNsense\Auth;

class OIDC
{
    protected $name;
    private $claims = [];
    public function __construct($name = null)
    {
        $this->name = $name ?? 'OIDC';
    }
    public function getAuthType()
    {
        return 'oidc';
    }
    public function authenticate($username, $password)
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        if (!empty($_SESSION['oidc']['user']) && $_SESSION['oidc']['user'] === $username) {
            $this->claims = $_SESSION['oidc']['claims'] ?? [];
            return true;
        }
        return false;
    }
    public function getUserClaims()
    {
        return $this->claims;
    }
}
