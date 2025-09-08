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
        "D:\\projects\\opnsense\\core\\src\\opnsense\\mvc",
        "D:\\projects\\opnsense\\core\\src\\etc\\inc",
        "D:\\projects\\opnsense\\core\\src\\www",
        "D:\\projects\\opnsense\\ide-stubs\\src"
    ],
    "explorer.compactFolders": false,
    "files.associations": {
        "*.inc": "php",
    }
}
```

## Setup on OPNSense
Here are the steps i have gotten to work with setup.

1. Clone [opnsense/plugins](https://github.com/opnsense/plugins) to `/usr/plugins`
2. Clone [opnsense/tools](https://github.com/opnsense/tools) to `/usr/tools`
3. `cd /usr/tools` and `make update`
4. `make plugins` (this might not be required. This will take a long time and tends to crash at libpam. I abort at this time )
5. Clone your project to `~/project-name`
6. Copy the project's content to `/usr/plugins/devel/project-name`
7. Build with `cd /usr/plugins/devel/project-name && make package`
8. Install `pkg add /usr/plugins/devel/project-name/work/pkg/*.pkg`

# AI Slop
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
