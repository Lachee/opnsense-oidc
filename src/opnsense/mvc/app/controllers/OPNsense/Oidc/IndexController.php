<?php

namespace OPNsense\Oidc;

/**
 * Class IndexControllerc
 * @package OPNsense\Oidc
 */
class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        // pick the template to serve to our users.
        $this->view->pick('OPNsense/Oidc/index');
        // fetch form data "general" in
        $this->view->generalForm = $this->getForm("general");
    }
}
