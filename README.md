# Installation

Package `net-mgmt/oidc`

# Development
## VScode
To get VSCode to behave correctly with the OPNSense PHP, we will need to tell the language server where to find the classes we use.
I use [Intelephense](https://intelephense.com/) for work, and this is easy to configure with the `includePaths` setting. 

There are several parts we need:
1. [opnsense/core](https://github.com/opnsense/core)
   - This handles all the core functionality with OPNSense
2. [phalcon/ide-stubs](https://github.com/phalcon/ide-stubs)
   - OPNSense uses the [Phalcon](https://docs.phalcon.io/3.4/introduction/) framework, and this is a stubs library specifically for this use case. 

Once these are cloned into a repository, you can configure Intelephense to use them:
```json
{
    "intelephense.environment.includePaths": [
        "D:\\opnsense\\core\\src\\opnsense\\mvc",
        "D:\\opnsense\\ide-stubs\\src"
    ]
}
```


## AI Slop
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
