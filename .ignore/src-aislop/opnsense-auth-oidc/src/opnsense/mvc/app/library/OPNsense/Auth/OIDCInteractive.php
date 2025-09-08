<?php

namespace OPNsense\Auth;

/*
 * Minimal OIDC interactive backend.
 * OPNsense core expects an authenticate($username,$password) method.
 * For interactive OIDC we ignore the provided password and rely on the
 * session populated by the OIDC callback controller.
 *
 * NOTE: Remove/adjust this class if core provides an abstract Base or Interface
 * for auth backends. This standalone version avoids extending LDAP (which may
 * not be available inside this isolated plugin tree during development).
 */

class OIDCInteractive
{
    /** @var string */
    protected $name;
    /** @var array|null */
    private $oidcSessionClaims = null;

    public function __construct($name = null)
    {
        $this->name = $name ?? 'OIDC';
    }

    public function getAuthType()
    {
        return 'oidc';
    }

    /**
     * Authenticate by validating an existing OIDC session established via browser flow.
     * @param string $username user attempting login (entered / auto-filled by UI)
     * @param string $password ignored (interactive flow)
     * @return bool
     */
    public function authenticate($username, $password)
    {
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }
        if (!empty($_SESSION['oidc']['user']) && $_SESSION['oidc']['user'] === $username) {
            $this->oidcSessionClaims = $_SESSION['oidc']['claims'] ?? [];
            return true;
        }
        return false;
    }

    public function getUserClaims(): array
    {
        return $this->oidcSessionClaims ?? [];
    }
}
