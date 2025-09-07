<?php
/* Register OIDC auth backend */
if (!isset($authFactory) || !is_array($authFactory)) {
    $authFactory = [];
}
$authFactory['oidc'] = [
    'description' => 'OIDC Interactive',
    'classname' => 'OPNsense\\Auth\\OIDC'
];
