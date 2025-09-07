# Installation
Installation Instructions for OPNsense OIDC Plugin:

1. Create plugin directory structure:
   mkdir -p /usr/local/opnsense/mvc/app/plugins/OPNsense/Oidc

2. Copy this repo into that folder, such that the README.md would be `/usr/local/opnsense/mvc/app/plugins/OPNsense/Oidc/README.md`

3. Register the plugin menu in /usr/local/opnsense/mvc/app/models/OPNsense/Base/Menu/MenuSystem.xml:
   <Services>
       <OIDC VisibleName="OIDC Authentication" url="/ui/oidc/"/>
   </Services>

4. Add ACL permissions in /usr/local/opnsense/mvc/app/config/ACL_Legacy_Page_Map.php

5. Restart web server:
   service nginx restart
   configctl webgui restart

Usage:
- Configure OIDC settings in Services -> OIDC Authentication
- Users can initiate OIDC login via /api/oidc/auth
- Add "Login with OIDC" button to main login page
