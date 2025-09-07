<?php
/*
 * OPNsense OIDC Authentication Plugin
 * 
 * Plugin Structure:
 * /usr/local/opnsense/mvc/app/plugins/OPNsense/Oidc/
 * ├── Api/
 * │   └── OidcController.php
 * ├── Controllers/
 * │   └── IndexController.php
 * ├── Models/
 * │   ├── Oidc.php
 * │   └── Oidc.xml
 * └── src/
 *     └── opnsense/
 *         └── mvc/
 *             └── app/
 *                 └── plugins/
 *                     └── OPNsense/
 *                         └── Oidc/
 *                             └── OidcAuth.php
 */


// ==================== FILE: Controllers/IndexController.php ====================

// ==================== FILE: Api/OidcController.php ====================

// ==================== FILE: src/opnsense/mvc/app/plugins/OPNsense/Oidc/OidcAuth.php ====================

/* 
 * Additional files needed:
 * 
 * 1. /usr/local/opnsense/mvc/app/views/OPNsense/Oidc/index.volt
 * 2. /usr/local/opnsense/service/conf/actions.d/actions_oidc.conf
 * 3. Menu registration in /usr/local/opnsense/mvc/app/config/ACL_Legacy_Page_Map.php
 */

// ==================== VOLT TEMPLATE: views/OPNsense/Oidc/index.volt ====================
?>


<?php
// ==================== INSTALLATION INSTRUCTIONS ====================
/*
 * Installation Instructions for OPNsense OIDC Plugin:
 * 
 * 1. Create plugin directory structure:
 *    mkdir -p /usr/local/opnsense/mvc/app/plugins/OPNsense/Oidc/{Api,Controllers,Models,views/OPNsense/Oidc}
 * 
 * 2. Place the files:
 *    - Models/Oidc.xml and Oidc.php in Models/
 *    - Controllers/IndexController.php in Controllers/
 *    - Api/OidcController.php in Api/
 *    - index.volt template in views/OPNsense/Oidc/
 * 
 * 3. Register the plugin menu in /usr/local/opnsense/mvc/app/models/OPNsense/Base/Menu/MenuSystem.xml:
 *    <Services>
 *        <OIDC VisibleName="OIDC Authentication" url="/ui/oidc/"/>
 *    </Services>
 * 
 * 4. Add ACL permissions in /usr/local/opnsense/mvc/app/config/ACL_Legacy_Page_Map.php
 * 
 * 5. Restart web server:
 *    service nginx restart
 *    configctl webgui restart
 * 
 * Usage:
 * - Configure OIDC settings in Services -> OIDC Authentication
 * - Users can initiate OIDC login via /api/oidc/auth
 * - Add "Login with OIDC" button to main login page
 */
?>