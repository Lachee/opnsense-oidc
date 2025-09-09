<?php

namespace OPNsense\Oidc\Api;

require_once("config.inc");

use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OIDC;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Config;
use OPNsense\Oidc\OidcClient;

/**
 * Class ServiceController
 * @package OPNsense\Cron
 */
class AuthController extends ApiControllerBase
{
    const ALLOW_USER_CREATION = false;

    public function doAuth()
    {
        return true;
    }

    public function initialize()
    {
        parent::initialize();
    }

    /**
     * reconfigure HelloWorld
     */
    public function loginAction()
    {
        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return ["error" => "missing provider"];
        }

        // $_SESSION['openid_connect_provider'] = $provider;
        $this->session->set('openid_connect_provider', $provider);
        $user = $this->authenticate($provider);
        if ($user === false)
            return ['msg' => 'redirecting'];

        return ['msg' => 'already logged in', 'user' => $user];
    }

    public function testAction()
    {
        $cnf = Config::getInstance()->object();

        // $_SESSION('Username', 'root');
        // $_SESSION('last_access', time());
        // $_SESSION['protocol'] = $cnf->system->webgui->protocol;
        
        $this->session->set('Username', 'root');
        $this->session->set('last_access', time());
        $this->session->set('protocol', $cnf->system->webgui->protocol);

        // Redirect to dashboard
        // $acl = new \OPNsense\Core\ACL();
        // $url = $acl->getLandingPage($_SESSION['Username']);
        // $this->response->redirect("/$url");
        $this->response->redirect('/ui/core/dashboard');
        return 'ok.';
    }

    public function callbackAction()
    {
        // $provider = $_SESSION['openid_connect_provider'];
        $provider = $this->session->get('openid_connect_provider');
        if (empty($provider)) {
            $this->response->setStatusCode(404, "Authentication not found");
            // TODO: Redirect to login
            return "Missing authentication provider. Please try the flow again.";
        }

        $user = $this->authenticate($provider);
        if ($user === false) {
            $this->response->setStatusCode(400, "Authentication not found");
            return "Something went wrong while trying to login you in";
        }

        // Lookup existing local user
        $lookupUsername = $user->preferred_username ?? null;
        $lookupEmail    = $user->email ?? null;
        $localUser = $this->findLocalUser($lookupUsername, $lookupEmail);

        if ($localUser === false) {
            if (!self::ALLOW_USER_CREATION) {
                $this->response->setStatusCode(403, "User not found");
                return "No matching local account, and user creation disabled.";
            }

            // Create the user if allowed
            $localUser = $this->createLocalUser($lookupUsername, $lookupEmail);
            if ($localUser === false) {
                $this->response->setStatusCode(500, "User creation failed");
                return "Unable to create local account.";
            }
        }


        // Create the main login session and log the user in.
        $cnf = Config::getInstance()->object();
        // $_SESSION['Username'] = $localUser['name'];
        // $_SESSION['last_access'] = time();        
        $this->session->set('Username', 'root');
        $this->session->set('last_access', time());

        // if (!isset($cnf->system->webgui->quietlogin)) {
            // $this->getLogger('audit')->notice(sprintf("OpenIDConnect login for user '%s' from: %s", $localUser['name'], $_SERVER['REMOTE_ADDR']), LOG_NOTICE);
        // }

        $this->response->redirect('/ui/core/dashboard');
        return 'ok.';
    }

    protected function authenticate($provider)
    {
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Authentication not found");
            return ["error" => "missing provider"];
        }

        /** @var OIDC $auth */
        $client = new OidcClient($auth, $this);
        $client->addScope(['openid', 'email', 'profile']);

        if (!$client->authenticate())
            return false;

        $user = $client->requestUserInfo();
        return $user;
    }



    protected function findLocalUser($username, $email)
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return false;
        }

        foreach ($cnf->system->user as $user) {
            if (($username && (string)$user->name === $username) ||
                ($email && isset($user->email) && (string)$user->email === $email)
            ) {
                // return as array
                return [
                    'name'   => (string)$user->name,
                    'email'  => (string)$user->email,
                    'groups' => isset($user->groupname) ? explode(',', (string)$user->groupname) : []
                ];
            }
        }

        return false;
    }

    protected function createLocalUser($username, $email)
    {
        $cnf = Config::getInstance()->object();

        $user = $cnf->system->user->addChild('user');
        $user->name     = $username;
        $user->descr    = "OIDC User";
        $user->scope    = "user";
        $user->disabled = "0";
        if (!empty($email)) {
            $user->email = $email;
        }
        // no password set, authentication handled via OIDC

        Config::getInstance()->save();
        \write_config("Created OIDC user $username");

        return [
            'name'   => $username,
            'email'  => $email,
            'groups' => []
        ];
    }
}
