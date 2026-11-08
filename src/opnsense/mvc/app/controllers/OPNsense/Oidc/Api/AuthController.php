<?php

namespace OPNsense\Oidc\Api;

use InvalidArgumentException;
use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OIDC;
use OPNsense\Auth\User;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Base\FieldTypes\ArrayField;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Oidc\OidcClient;
use RuntimeException;

/**
 * Class AuthController
 * @package OPNsense\Oidc
 */
class AuthController extends ApiControllerBase
{
    const ALLOW_USER_CREATION = true;
    const SESSION_AUTH_PROVIDER = 'openid_connect_provider';

    public function doAuth()
    {
        return true;
    }

    /**
     * Plain-text response. Never echo request- or IdP-supplied data back to
     * the browser. Exception details go to the "oidc" logger (LOG_LOCAL4),
     * NOT the audit/LOG_AUTH facility: every LOG_AUTH line is parsed by
     * OPNsense's lockout_handler, so request-controlled text there could add
     * or reset sshlockout entries.
     */
    private function fail(int $status, string $publicMessage, ?\Throwable $e = null)
    {
        if ($e !== null) {
            $this->getLogger('oidc')->warning(sprintf(
                'OIDC login error (%s) from %s',
                self::clean($e->getMessage(), 512),
                $this->clientAddress()
            ));
        }
        $this->response->setStatusCode($status);
        $this->response->setHeader('Content-Type', 'text/plain; charset=UTF-8');
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setHeader('Cache-Control', 'no-store');
        return $publicMessage;
    }

    /**
     * True while core would still honour this session (same idle timeout as
     * authgui.inc / ControllerRoot::doAuth()). An idle-expired session is
     * dropped here the way ControllerRoot::doAuth() drops it, so a stale tab
     * can use the login button instead of getting "Already logged in".
     */
    private function isLoggedIn(): bool
    {
        if ($this->session->get('Username') == null) {
            return false;
        }
        $cnf = Config::getInstance()->object();
        $timeout = !empty($cnf->system->webgui->session_timeout)
            ? (int)$cnf->system->webgui->session_timeout * 60 : 14400;
        $last = $this->session->get('last_access');
        if (!is_numeric($last) || (int)$last >= time() - $timeout) {
            return true;
        }
        foreach (['Username', 'last_access', 'user_shouldChangePassword'] as $key) {
            $this->session->remove($key);
        }
        return false;
    }

    /**
     * Audit line on the same facility core authentication uses. Callers must
     * pass untrusted values through clean() and end the message with
     * "from <client ip>" so lockout_handler (which takes the last IP-looking
     * token) attributes it to the real client.
     */
    private function audit(int $priority, string $message)
    {
        openlog("audit", LOG_ODELAY, LOG_AUTH);
        syslog($priority, $message);
        closelog();
    }

    /** Printable-ASCII, length-capped rendering of an untrusted value for logs. */
    private static function clean($value, int $max = 128): string
    {
        $s = is_scalar($value) ? (string)$value : gettype($value);
        return substr(preg_replace('/[^\x20-\x7E]/', '?', $s), 0, $max);
    }

    private function clientAddress(): string
    {
        return self::clean($this->request->getClientAddress() ?? '-', 64);
    }

    /**
     * The Host the browser used, if it is one of the firewall's configured
     * names (System > Settings > General hostname.domain, or Alternate
     * Hostnames under Administration). The redirect_uri is built from it, so
     * an arbitrary Host header must never reach the provider or the token
     * request. Returns null when the Host is not a configured name.
     */
    private function callbackHost(): ?string
    {
        $cnf = Config::getInstance()->object();
        $names = [];
        $hostname = strtolower(trim((string)($cnf->system->hostname ?? '')));
        $domain = strtolower(trim((string)($cnf->system->domain ?? '')));
        if ($hostname !== '') {
            $names[] = $domain !== '' ? "{$hostname}.{$domain}" : $hostname;
        }
        foreach (preg_split('/[\s,]+/', (string)($cnf->system->webgui->althostnames ?? ''), -1, PREG_SPLIT_NO_EMPTY) as $alt) {
            $names[] = strtolower($alt);
        }
        return OidcClient::vetHost((string)$this->request->getHeader('HOST'), $names);
    }

    /** True if the provider is selected as a WebGui authentication server. */
    private function isEnabledForWebGui(string $provider): bool
    {
        $cnf = Config::getInstance()->object();
        $authmode = (string)($cnf->system->webgui->authmode ?? '');
        return in_array($provider, array_map('trim', explode(',', $authmode)), true);
    }

    /**
     * Proxies the admin-configured provider icon for the (unauthenticated)
     * login page. Hardened: only providers enabled for the web GUI, https only,
     * no redirects, short timeouts, size cap, raster images only, and a
     * sandboxing CSP so nothing fetched can execute on the GUI origin.
     */
    public function iconAction()
    {
        $provider = $this->request->get('provider');
        if (!is_string($provider) || $provider === '') {
            return $this->fail(400, "Missing authentication provider.");
        }
        $auth = $this->getAuthProvider($provider);
        if ($auth === null || !$this->isEnabledForWebGui($provider)) {
            return $this->fail(404, "Authentication provider not found.");
        }
        $url = (string)$auth->oidcIconUrl;
        if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL) || stripos($url, 'https://') !== 0) {
            return $this->fail(404, "Invalid icon URL.");
        }

        $max = 262144;
        $body = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS_STR => 'https',
            CURLOPT_REDIR_PROTOCOLS_STR => 'https',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_MAXFILESIZE => $max,
            CURLOPT_WRITEFUNCTION => function ($ch, $data) use (&$body, $max) {
                $body .= $data;
                return strlen($body) > $max ? -1 : strlen($data);
            },
        ]);
        $ok = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $mimeType = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);

        if ($ok === false || $httpCode !== 200 || $body === '') {
            return $this->fail(404, "Unable to fetch icon.");
        }

        // Raster images only; anything else (HTML, SVG with script, ...) would
        // be served from the firewall's own origin.
        $allowed = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/x-icon', 'image/vnd.microsoft.icon'];
        $baseType = strtolower(trim(explode(';', $mimeType)[0]));
        if (!in_array($baseType, $allowed, true)) {
            return $this->fail(415, "Unsupported icon type.");
        }

        $this->response->setHeader('Content-Type', $baseType);
        $this->response->setHeader('X-Content-Type-Options', 'nosniff');
        $this->response->setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
        $this->response->setHeader('Cache-Control', 'public, max-age=86400');
        return $body;
    }

    public function loginAction()
    {
        if ($this->isLoggedIn()) {
            return $this->fail(400, "Already logged in.");
        }

        // The login endpoint only starts a flow; callback parameters belong to
        // /api/oidc/auth/callback and are never processed here.
        foreach (['code', 'state', 'error', 'id_token', 'access_token'] as $param) {
            if ($this->request->hasQuery($param) || $this->request->hasPost($param)) {
                return $this->fail(400, "Unexpected parameters.");
            }
        }

        $provider = $this->request->get('provider');
        if (!is_string($provider) || $provider === '') {
            return $this->fail(400, "Missing authentication provider.");
        }

        $auth = $this->getAuthProvider($provider);
        if ($auth === null) {
            return $this->fail(404, "Authentication provider not found.");
        }
        if (!$this->isEnabledForWebGui($provider)) {
            $this->audit(LOG_WARNING, sprintf(
                "OIDC login refused for provider %s (not enabled for WebGui) from %s",
                self::clean($provider),
                $this->clientAddress()
            ));
            return $this->fail(403, "This authentication provider is not enabled for the web GUI.");
        }
        $host = $this->callbackHost();
        if ($host === null) {
            $this->getLogger('oidc')->warning(sprintf(
                'OIDC login refused: Host %s is not a configured name of this firewall, from %s',
                self::clean($this->request->getHeader('HOST'), 64),
                $this->clientAddress()
            ));
            return $this->fail(400, "Open the web GUI by its configured host name to sign in with OpenID Connect "
                . "(System > Settings > General, or add the name to Alternate Hostnames under System > Settings > Administration).");
        }
        $this->session->set(self::SESSION_AUTH_PROVIDER, $provider);

        try {
            $user = $this->authenticate($auth, $host);
        } catch (\Throwable $e) {
            return $this->fail(500, "Unable to authenticate. See the system log for details.", $e);
        }

        $this->session->close();
        if ($user === false) {
            return 'Redirecting...';
        }

        return "Already logged in but session not setup. Please try again";
    }


    public function callbackAction()
    {
        if ($this->isLoggedIn()) {
            return $this->fail(400, "Already logged in.");
        }

        // Get the provider from the session
        $provider = $this->session->get(self::SESSION_AUTH_PROVIDER);
        if (!is_string($provider) || $provider === '') {
            return $this->fail(404, "Missing authentication provider. Please try the flow again.");
        }
        $this->session->remove(self::SESSION_AUTH_PROVIDER);

        // Provider-reported errors: log only a sanitized error code.
        if ($this->request->has('error')) {
            $this->getLogger('oidc')->warning(sprintf(
                'OIDC provider returned error (%s) from %s',
                self::clean($this->request->get('error'), 64),
                $this->clientAddress()
            ));
            return $this->fail(400, "The identity provider reported an error. Please try again.");
        }
        if (!is_string($this->request->get('code')) || !is_string($this->request->get('state'))) {
            return $this->fail(400, "Invalid callback. Please try the flow again.");
        }

        $auth = $this->getAuthProvider($provider);
        if ($auth === null) {
            return $this->fail(404, "Authentication provider not found. Please try the flow again.");
        }
        if (!$this->isEnabledForWebGui($provider)) {
            return $this->fail(403, "This authentication provider is not enabled for the web GUI.");
        }
        // Must be the same vetted host the flow started on, or the token
        // request's redirect_uri won't match the authorization request.
        $host = $this->callbackHost();
        if ($host === null) {
            return $this->fail(400, "Invalid callback host. Please try the flow again.");
        }

        try {
            $user = $this->authenticate($auth, $host);
            if ($user === false) {
                return $this->fail(400, "Something went wrong while trying to log you in.");
            }
        } catch (\Throwable $e) {
            return $this->fail(500, "Unable to authenticate. See the system log for details.", $e);
        }

        // Lookup existing local user
        $lookupUsername = $user->{$auth->oidcUsernameClaim} ?? null;
        if ($lookupUsername !== null && !is_string($lookupUsername)) {
            $lookupUsername = null;
        }
        // By default only an address the provider says it verified is used,
        // for matching and for new accounts; an unverified one could be
        // anybody's. "Allow unverified email" turns this off per server.
        $emailVerified = $auth->oidcAllowUnverifiedEmail || (isset($user->email_verified)
            && ($user->email_verified === true || $user->email_verified === 'true'));
        $claimEmail  = ($emailVerified && isset($user->email) && is_string($user->email)) ? $user->email : null;
        $lookupEmail = $auth->oidcMatchEmail ? $claimEmail : null;
        $localUser = $this->findLocalUser($lookupUsername, $lookupEmail);
        if ($localUser === false) {
            if (!self::ALLOW_USER_CREATION || !$auth->oidcCreateUsers) {
                $this->audit(LOG_WARNING, sprintf(
                    "user %s could not authenticate for WebGui [using OIDC provider %s] (no matching local account) from %s",
                    self::clean($lookupUsername),
                    self::clean($provider),
                    $this->clientAddress()
                ));
                return $this->fail(403, "No matching local account, and user creation disabled.");
            }

            // Create the user if allowed
            $localUser = $this->createLocalUser($lookupUsername, $claimEmail, $user->name ?? '',  $auth->oidcDefaultGroups);
            if ($localUser === false) {
                return $this->fail(500, "Unable to create local account.");
            }
        }

        // Same account checks core applies to password logins; mirrors
        // OPNsense\Auth\Local::_authenticate() (Local.php ~l.156-162 in 26.7).
        // Core exposes no public "may this account log in" check to call.
        $username = (string)$localUser->name;
        $subject = (string)($user->sub ?? '');
        $refusal = $this->accountRefusal($localUser) ?? $this->subjectRefusal($auth, $username, $subject);
        if ($refusal !== null) {
            $this->audit(LOG_WARNING, sprintf(
                "user %s could not authenticate for WebGui [using OIDC provider %s, subject %s] (%s) from %s",
                self::clean($username),
                self::clean($provider),
                self::clean($subject),
                $refusal,
                $this->clientAddress()
            ));
            return $this->fail(403, "This account cannot sign in with OpenID Connect.");
        }
        // Parity with authgui.inc:181 — OIDC extends Local, so the local
        // password-policy duration/compliance rules apply to the mapped account.
        $shouldChangePassword = $auth->shouldChangePassword($username);

        // New session identifier on privilege change, as core does in
        // authgui.inc. OPNsense's Mvc\Session starts and aborts the PHP
        // session before dispatch, so it must be reopened to regenerate.
        // Fail closed if regeneration is not possible.
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (session_status() !== PHP_SESSION_ACTIVE || !session_regenerate_id(true)) {
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_abort();
            }
            return $this->fail(500, "Unable to establish a new session.");
        }
        session_write_close();
        // Don't carry pre-login CSRF tokens into the authenticated session.
        $this->session->remove('$PHALCON/CSRF$');
        $this->session->remove('$PHALCON/CSRF/KEY$');

        $cnf = Config::getInstance()->object();
        $this->session->set('Username', strval($username));
        $this->session->set('last_access', time());
        $this->session->set('protocol', strval($cnf->system->webgui->protocol));
        if ($shouldChangePassword) {
            $this->session->set('user_shouldChangePassword', '1');
        }
        // Keep only the subject identifiers, as an array (Session::get() is typed string|array|null).
        $this->session->set('oidc_user', ['sub' => (string)($user->sub ?? ''), 'provider' => $provider]);
        $this->session->close();

        $this->audit(LOG_NOTICE, sprintf(
            "user %s authenticated successfully for WebGui [using OIDC provider %s, subject %s] from %s",
            self::clean($username),
            self::clean($provider),
            self::clean($subject),
            $this->clientAddress()
        ));
        if (empty($cnf->system->webgui->quietlogin)) {
            // The exact line core emits (authgui.inc); lockout_handler resets
            // the client's failure counter on it and log alerting keys on it.
            $this->audit(LOG_NOTICE, sprintf(
                "Successful login for user '%s' from: %s",
                self::clean($username),
                $this->clientAddress()
            ));
        }

        $this->response->setHeader('Cache-Control', 'no-store');
        $this->response->redirect('/');
        return 'Redirecting home...';
    }

    /** Returns a reason string if the local account may not log in, else null. */
    protected function accountRefusal($localUser): ?string
    {
        if (!empty((string)$localUser->disabled)) {
            return 'account disabled';
        }
        if (!empty((string)$localUser->expires)
            && strtotime("-1 day") > strtotime(date("m/d/Y", strtotime((string)$localUser->expires)))
        ) {
            return 'account expired';
        }
        // The built-in system account (root) is never reachable through an
        // external identity provider.
        if ((string)$localUser->scope === 'system' || (string)$localUser->uid === '0' || (string)$localUser->name === 'root') {
            return 'system account';
        }
        return null;
    }

    /**
     * Subject binding (optional, per server): when the server lists
     * "localuser=subject" pairs, a local account is only reachable by the
     * provider subject bound to it, and unlisted accounts are refused. The
     * username and email claims can usually be changed at the provider; `sub`
     * cannot. Returns a reason string on refusal, else null.
     */
    protected function subjectRefusal(OIDC $auth, string $username, string $subject): ?string
    {
        $bindings = $auth->getSubjectBindings();
        if (count($bindings) === 0) {
            return null;
        }
        if (!isset($bindings[$username])) {
            return 'account has no subject binding';
        }
        if ($subject === '' || !hash_equals($bindings[$username], $subject)) {
            return 'subject not bound to this account';
        }
        return null;
    }

    protected function getAuthProvider($provider): OIDC|null
    {
        if (!is_string($provider) || $provider === '') {
            return null;
        }
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            return null;
        }
        return $auth;
    }

    protected function authenticate($auth, string $host)
    {
        /** @var OIDC $auth */
        $client = new OidcClient($auth, $this, $host);
        $client->addScope($auth->oidcScopes);
        if ($auth->oidcForceLogin) {
            // Ask the provider to re-authenticate the user instead of reusing
            // an existing provider session.
            $client->addAuthParam(['prompt' => 'login']);
        }

        if (!$client->authenticate())
            return false;

        $user = $client->requestUserInfo();

        // OIDC Core 5.3.2: the UserInfo `sub` MUST match the ID Token `sub`.
        $idSub = $client->getVerifiedClaims('sub');
        if (!is_object($user) || !isset($user->sub) || $idSub === null || (string)$user->sub !== (string)$idSub) {
            throw new RuntimeException('UserInfo subject does not match the ID token subject.');
        }
        return $user;
    }

    /** Finds the local user that best matches the given username or email. */
    protected function findLocalUser($username, $email)
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return false;
        }

        // Username match takes precedence over email match.
        if (is_string($username) && $username !== '') {
            foreach ($cnf->system->user as $user) {
                if ((string)$user->name === $username) {
                    return $user;
                }
            }
        }

        // Email match (opt-in): only when exactly one local account carries it.
        if (is_string($email) && $email !== '') {
            $matches = [];
            foreach ($cnf->system->user as $user) {
                if (!empty((string)$user->email) && (string)$user->email === $email) {
                    $matches[] = $user;
                }
            }
            if (count($matches) === 1) {
                return $matches[0];
            }
        }

        return false;
    }


    /** Creates a new local user. */
    protected function createLocalUser($username, $email, $displayName = '', $sync_groups = [])
    {
        if (!self::ALLOW_USER_CREATION)
            return false;

        if (empty($username))
            return false;

        // Create the user using a Model
        $mdl = new User();

        /** @var ArrayField $users */
        $users = $mdl->user;
        $user = $users->add();
        $user->name     = $username;
        $user->email    = $email ?? '';
        $user->descr    = $displayName ?? $username;
        $user->comment  = "Created with OpenID Connect";
        $user->password = 'DEADBEEF';
        $user->scrambled_password = "1";
        $user->scope    = "user";
        $user->disabled = "0";

        if (!$mdl->serializeToConfig())
            return false;

        Config::getInstance()->save();
        (new Backend())->configdpRun('auth sync user', [$user->name]);

        // Set the group
        if (count($sync_groups) > 0) {
            $cnf = Config::getInstance()->object();
            foreach ($cnf->system->group as $group) {
                $groupName = strtolower((string)$group->name);
                if (!in_array($groupName, $sync_groups))
                    continue;

                $members = [];
                foreach ($group->member as $member) {
                    $members = array_merge($members, explode(',', $member));
                }

                if (in_array((string)$user->uid, $members)) {
                    // Already in group
                } else {
                    syslog(LOG_NOTICE, sprintf(
                        'User: policy change for %s link group %s',
                        self::clean($username),
                        self::clean((string)$group->name)
                    ));
                    $group->member = implode(',', array_merge($members, [(string)$user->uid]));
                }
            }
            Config::getInstance()->save();
            (new Backend())->configdpRun("auth user changed", [$user->name]);
        }

        Config::getInstance()->forceReload();
        return $user;
    }
}
