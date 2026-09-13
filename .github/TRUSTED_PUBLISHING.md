# npm Trusted Publishing

The `publish` job uses GitHub Actions OIDC, Node 24 and npm 11.15.0.
It publishes the tested tarball and requires the existing `npm-publish`
environment approval. Build and test runtime coverage remains unchanged.
No `NPM_TOKEN` or `NODE_AUTH_TOKEN` is used by this workflow.

## npm configuration

In the settings for `@mudraid/sidecar` on npm, add a GitHub Actions Trusted Publisher:

| Field | Value |
| --- | --- |
| Organization or user | `MudraID` |
| Repository | `mudraid-sidecar` |
| Workflow filename | `publish.yml` |
| Environment name | `npm-publish` |
| Allowed actions | Enable direct publishing with `npm publish` |

Keep account 2FA enabled. Enter the filename only, without `.github/workflows/`.
The package must already exist and the configuring user must have write access.
An initial package publication requires an interactive npm login and 2FA, or a
separately approved bootstrap credential; this OIDC-only workflow cannot create
its own npm trust relationship. Do not publish a placeholder to reserve a name.

## Verification and retirement of tokens

1. Land this workflow and its matching source copy before the next mirror.
2. Run **Publish** with `publish` unchecked to validate the candidate without uploading.
3. After npm trust is configured, dispatch an approved, unpublished version with
   `publish=true`, and approve the `npm-publish` environment in GitHub.
4. Verify the npm version, tarball integrity and provenance, then record the
   upload receipt through the existing release process.
5. Only after a successful OIDC publication, disallow traditional publishing
   tokens in npm package settings and retire unused publishing secrets/tokens.
   Check other consumers before deleting a shared credential.

A dry run or presence of OIDC environment variables does not prove npm trust.
`npm whoami` also does not validate OIDC. The actual publish performs the exchange.

Official reference: https://docs.npmjs.com/trusted-publishers/
