module.exports = function (RED) {
  "use strict";
  const crypto = require("crypto");

  function toBuffer(value) {
    if (Buffer.isBuffer(value)) return value;
    if (typeof value === "string") return Buffer.from(value, "utf8");
    if (value === undefined || value === null) return Buffer.alloc(0);
    // Object: JSON serialization (see README "raw body" gotcha — prefer the raw bytes).
    return Buffer.from(JSON.stringify(value), "utf8");
  }

  function constantTimeEqual(a, b) {
    const ba = Buffer.from(String(a), "utf8");
    const bb = Buffer.from(String(b), "utf8");
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  }

  function HmacVerifyNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.algorithm = config.algorithm || "sha256";
    node.payloadProp = config.payloadProp || "payload";
    node.payloadPropType = config.payloadPropType || "msg";
    node.signatureProp = config.signatureProp || "req.headers.x-signature";
    node.signaturePropType = config.signaturePropType || "msg";
    node.encoding = config.encoding || "hex";
    node.prefix = config.prefix || "";
    node.secretEnv = config.secretEnv || "";

    node.on("input", function (msg, send, done) {
      send = send || function () { node.send.apply(node, arguments); };
      done = done || function (err) { if (err) { node.error(err, msg); } };

      try {
        const secret =
          (node.credentials && node.credentials.secret) ||
          (node.secretEnv ? process.env[node.secretEnv] : undefined);

        if (!secret) {
          throw new Error(
            "hmac-verify: no secret (set a credential or a secret env var)"
          );
        }

        const payload = RED.util.evaluateNodeProperty(
          node.payloadProp, node.payloadPropType, node, msg
        );

        let signature = RED.util.evaluateNodeProperty(
          node.signatureProp, node.signaturePropType, node, msg
        );
        signature = signature === undefined || signature === null ? "" : String(signature);
        if (node.prefix && signature.startsWith(node.prefix)) {
          signature = signature.slice(node.prefix.length);
        }

        const digest = crypto
          .createHmac(node.algorithm, secret)
          .update(toBuffer(payload))
          .digest(node.encoding);

        const valid = constantTimeEqual(digest, signature);
        msg.hmacValid = valid;

        if (valid) {
          node.status({ fill: "green", shape: "dot", text: "valid" });
          send([msg, null]);
        } else {
          node.status({ fill: "red", shape: "ring", text: "invalid" });
          send([null, msg]);
        }
        done();
      } catch (err) {
        node.status({ fill: "red", shape: "ring", text: "error" });
        msg.hmacValid = false;
        send([null, msg]);
        done(err);
      }
    });
  }

  RED.nodes.registerType("hmac-verify", HmacVerifyNode, {
    credentials: { secret: { type: "password" } }
  });
};
