<?php


namespace OPNsense\Oidc\Controllers;

use OPNsense\Base\IndexController as BaseController;
use OPNsense\Oidc\Models\Oidc;
use OPNsense\Core\Config;

class IndexController extends BaseController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm("general");
        $this->view->pick('OPNsense/Oidc/index');

        // Generate redirect URI for display
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'];
        $this->view->redirectUri = $protocol . '://' . $host . '/api/oidc/callback';
    }

    public function getAction()
    {
        $result = array();
        if ($this->request->isGet()) {
            $mdlOidc = new Oidc();
            $result['oidc'] = $mdlOidc->getNodes();
        }
        return $result;
    }

    public function setAction()
    {
        $result = array("result" => "failed");
        if ($this->request->isPost()) {
            $mdlOidc = new Oidc();
            $mdlOidc->setNodes($this->request->getPost("oidc"));

            $validationMessages = $mdlOidc->performValidation();
            if (empty($validationMessages)) {
                $mdlOidc->serializeToConfig();
                Config::getInstance()->save();
                $result["result"] = "saved";
            } else {
                $result["validations"] = $validationMessages;
            }
        }
        return $result;
    }
}
