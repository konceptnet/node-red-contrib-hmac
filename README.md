# node-red-contrib-hmac

[![npm version](https://img.shields.io/npm/v/node-red-contrib-hmac.svg)](https://www.npmjs.com/package/node-red-contrib-hmac)
[![CI](https://github.com/konceptnet/node-red-contrib-hmac/actions/workflows/ci.yml/badge.svg)](https://github.com/konceptnet/node-red-contrib-hmac/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/npm/l/node-red-contrib-hmac.svg)](LICENSE)

A Node-RED node that verifies the **HMAC signature** of incoming webhooks.
Constant-time comparison, `sha1` / `sha256` / `sha512`, `hex` / `base64`, optional
prefix stripping (e.g. GitHub's `sha256=`). Zero runtime dependencies.

## Install

From the Node-RED palette manager search for `node-red-contrib-hmac`,
or in your Node-RED userDir:

```bash
npm install node-red-contrib-hmac
```

## The `hmac verify` node

A **gate with two outputs**:

1. **valid** — the message passes through (`msg.hmacValid === true`)
2. **invalid / error** — the message is routed here (`msg.hmacValid === false`)

### Configuration

| Field | Description |
|---|---|
| Algorithm | `sha1`, `sha256` (default), `sha512` |
| Secret | the shared secret, stored **encrypted** as a credential |
| Secret env | (optional) name of an env var to read the secret from if Secret is empty |
| Payload | message property holding the body to sign (default `payload`) |
| Signature | message property holding the provided signature (default `req.headers.x-signature`) |
| Encoding | `hex` (default) or `base64` |
| Strip prefix | optional string removed from the signature before compare (e.g. `sha256=`) |

### ⚠️ Raw body matters

The HMAC must be computed over the **raw** request body. If an upstream node already
parsed the JSON, re-serializing `msg.payload` can yield different bytes and the
signature will not match. Feed the raw body (e.g. `msg.req.rawBody`).

## License

MIT © konceptnet
