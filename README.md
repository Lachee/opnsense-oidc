# Installation
Package `net-mgmt/oidc`

# Configuration
## Provider Url
This is a link to the provider. The URL will need to have `/.well-known/openid-connect` available for automatic discovery.

## Client ID
The provided ID from your OIDC provider

## Client Secret
The secret from your OIDC provider

## Icon Url
An optional URL that will be proxied for the login button. You can access it at `/api/oidc/auth/icon?provider=<name>`

## Custom Button 
When provided, the button will be replaced with the custom one. 
There are several templates available:
- `%name%` Name of the provider 
- `%url%` URL that will start the auth flow
- `%icon%` The proxied icon image (useful to avoid CORS).

As an example, here is one that makes a nice big icon next to the login button
```html
<a href="%url%" class="btn btn-primary"><img src="%icon%" style="height: 2em"> Login with %name%</a> 
<style>.login-sso-link-container { display: flex; justify-content: end; margin-top: 15px; margin-right: 9px; }</style>
```

| Before | After |
|--------|-------|
| ![old login](https://i.lu.je/2025/firefox_laeaoIMkWI.png) | ![new login](https://i.lu.je/2025/firefox_q6dNnOaA8b.png) |

# Provider Setup
## PocketID / Generic OIDC
- Set the Client ID and Client Secret
- Set the provider url to the first part of the discovery url
- Set the callback to `https://<ip>/api/oidc/auth/callback`

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
