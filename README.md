<h1 align=center>blueprint-login</h1>

TAK Server based login blueprint.

Using this blueprint with `@openaddresses/batch-schema` will provide a login
route and authentication middleware for all requests

## Installation

```
npm i @tak-ps/blueprint-login
```

## Example Usage

```
import Blueprintlogin from '@tak-ps/blueprint-login'

await schema.blueprint(new BlueprintLogin({
    secret: config.SigningSecret,
    unsafe: config.unsafe ? config.UnsafeSigningSecret : undefined, // Allow local test token
    group: 'Human readable Group Name',
    api: '<WebTak Root URL>'
}));
```
