<?php

/**
 * Simple wrapper for Jumbojett\OpenIDConnectClient to load nessary components and respecting
 */

namespace OPNsense\Oidc;

require(__DIR__ . '/OpenIDConnectClient.php');

use Jumbojett\OpenIDConnectClient;
use OPNsense\Auth\OIDC;
use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Response;
use OPNsense\Mvc\Session;

class OidcClient extends OpenIDConnectClient
{
    /** @var OIDC $auth */
    protected $auth;
    /** @var Request $request */
    protected $request;
    /** @var Response $response */
    protected $response;

    public function __construct(OIDC $auth, Controller $controller, string $callback = '/api/oidc/auth/callback')
    {
        $this->phpseclib_autoload('ParagonIE\ConstantTime', '/usr/local/share/phpseclib/paragonie');
        $this->phpseclib_autoload('phpseclib3', '/usr/local/share/phpseclib');
        parent::__construct($auth->oidcProviderUrl, $auth->oidcClientId, $auth->oidcClientSecret);
        $this->auth = $auth;
        $this->request = $controller->request;
        $this->response = $controller->response;

        $this->setRedirectURL("{$this->request->getScheme()}://{$this->request->getHeader('HOST')}{$callback}");
    }

    public function redirect(string $url)
    {
        $this->response->redirect($url);
    }

    private function phpseclib_autoload($namespace, $dir)
    {
        $split = '\\';
        $ns = trim($namespace, DIRECTORY_SEPARATOR . $split);

        return spl_autoload_register(
            function ($class) use ($ns, $dir, $split) {
                $prefix = $ns . $split;
                $base_dir = $dir . DIRECTORY_SEPARATOR;
                $len = strlen($prefix);
                if (strncmp($prefix, $class, $len)) {
                    return;
                }

                $relative_class = substr($class, $len);

                $file = $base_dir .
                    str_replace($split, DIRECTORY_SEPARATOR, $relative_class) .
                    '.php';

                if (file_exists($file)) {
                    require_once $file;
                }
            }
        );
    }
}