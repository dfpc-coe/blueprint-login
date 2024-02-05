# CHANGELOG

## Emoji Cheatsheet
- :pencil2: doc updates
- :bug: when fixing a bug
- :rocket: when making general improvements
- :white_check_mark: when adding tests
- :arrow_up: when upgrading dependencies
- :tada: when adding new features

## Version History

### v4.3.0

- :tada: Include Token for validation

### v4.2.0

- :tada: Expose enums for access fields and make the difference between user and resource stricter

### v4.1.0

- :rocket: Remove optional `token` and just use `Profile.auth` in CloudTAK

### v4.0.0

- :rocket: Return Class and differentiate between resource vs User

### v3.0.2

- :bug: TAK Product Center rolled back the breaking OAuth endpoint in 5.0r38

### v3.0.1

- :bug: Update OAuth API Endpoint (5.X TAK Release)

### v3.0.0

- :bug: Use jwt.sub property to parse email (5.X TAK Release)

### v2.6.2

- :bug: Fix type errors

### v2.6.1

- :rocket: Reduce use of `any` type
- :arrow_up: Update to latest typescript defs

### v2.6.0

- :rocket: Use `POST` for login grant

### v2.5.0

- :arrow_up: Update deps to support latest undici

### v2.4.0

- :tada: Export the token parser so that it can be used for alternate protocols

### v2.3.0

- :tada: Emit `login` event when a successful login occurs

### v2.2.3

- :bug: Fix Bug where query tokens couldn't be parsed due to the header codepath always being chosen

### v2.2.2

- :bug: Fix syntax bug

### v2.2.1

- :bug: Include `layer` property in parsed token

### v2.2.0

- :tada: Include email field from TAK JWT token

### v2.1.0

- :tada: Include WebTAK token in JWT Wrapper

### v2.0.3

- :arrow_up: Fix complaints about types in batch-error library

### v2.0.2

- :bug: test dist inclusion

### v2.0.1

- :bug: fix release script by including build step

### v2.0.0

- :rocket: Migrate to typescript

### v1.1.0

- :bug: Apply schema definition to `body` param in schema

### v1.0.0

- :tada: Initial Commit
