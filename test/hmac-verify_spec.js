const helper = require("node-red-node-test-helper");
const hmacNode = require("../hmac-verify.js");
const crypto = require("crypto");

helper.init(require.resolve("node-red"));

// Reusable flow fixture: hmac-verify (n1) wired to two helper sinks.
function flow(overrides) {
  return [
    Object.assign(
      {
        id: "n1",
        type: "hmac-verify",
        name: "test",
        algorithm: "sha256",
        payloadProp: "payload",
        payloadPropType: "msg",
        signatureProp: "signature",
        signaturePropType: "msg",
        encoding: "hex",
        prefix: "",
        secretEnv: "",
        wires: [["okOut"], ["badOut"]]
      },
      overrides
    ),
    { id: "okOut", type: "helper" },
    { id: "badOut", type: "helper" }
  ];
}

const SECRET = "topsecret";
function sign(body, algo = "sha256", enc = "hex") {
  return crypto.createHmac(algo, SECRET).update(body).digest(enc);
}

describe("hmac-verify node", function () {
  beforeEach(function (done) {
    helper.startServer(done);
  });
  afterEach(function (done) {
    helper.unload();
    helper.stopServer(done);
  });

  it("routes a valid signature to output 1 with hmacValid=true", function (done) {
    helper.load(hmacNode, flow(), { n1: { secret: SECRET } }, function () {
      const n1 = helper.getNode("n1");
      const ok = helper.getNode("okOut");
      const bad = helper.getNode("badOut");
      bad.on("input", () => done(new Error("should not reach invalid output")));
      ok.on("input", function (msg) {
        try {
          require("chai").expect(msg.hmacValid).to.equal(true);
          done();
        } catch (e) {
          done(e);
        }
      });
      n1.receive({ payload: "hello", signature: sign("hello") });
    });
  });

  it("routes an invalid signature to output 2 with hmacValid=false", function (done) {
    helper.load(hmacNode, flow(), { n1: { secret: SECRET } }, function () {
      const n1 = helper.getNode("n1");
      const ok = helper.getNode("okOut");
      const bad = helper.getNode("badOut");
      ok.on("input", () => done(new Error("should not reach valid output")));
      bad.on("input", function (msg) {
        try {
          require("chai").expect(msg.hmacValid).to.equal(false);
          done();
        } catch (e) {
          done(e);
        }
      });
      n1.receive({ payload: "hello", signature: "deadbeef" });
    });
  });
});
