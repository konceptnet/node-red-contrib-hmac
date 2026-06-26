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

  it("with no secret, calls node.error and routes to output 2", function (done) {
    // Load with no credentials and no env var.
    helper.load(hmacNode, flow(), {}, function () {
      const n1 = helper.getNode("n1");
      const bad = helper.getNode("badOut");
      let errored = false;
      n1.error = function () { errored = true; }; // spy
      bad.on("input", function (msg) {
        try {
          require("chai").expect(msg.hmacValid).to.equal(false);
          require("chai").expect(errored).to.equal(true);
          done();
        } catch (e) {
          done(e);
        }
      });
      n1.receive({ payload: "hello", signature: "anything" });
    });
  });

  it("supports sha512", function (done) {
    helper.load(hmacNode, flow({ algorithm: "sha512" }), { n1: { secret: SECRET } }, function () {
      const n1 = helper.getNode("n1");
      helper.getNode("okOut").on("input", () => done());
      helper.getNode("badOut").on("input", () => done(new Error("sha512 valid sig rejected")));
      n1.receive({ payload: "hello", signature: sign("hello", "sha512") });
    });
  });

  it("supports base64 encoding", function (done) {
    helper.load(hmacNode, flow({ encoding: "base64" }), { n1: { secret: SECRET } }, function () {
      const n1 = helper.getNode("n1");
      helper.getNode("okOut").on("input", () => done());
      helper.getNode("badOut").on("input", () => done(new Error("base64 valid sig rejected")));
      n1.receive({ payload: "hello", signature: sign("hello", "sha256", "base64") });
    });
  });

  it("strips a configured prefix (e.g. sha256=)", function (done) {
    helper.load(hmacNode, flow({ prefix: "sha256=" }), { n1: { secret: SECRET } }, function () {
      const n1 = helper.getNode("n1");
      helper.getNode("okOut").on("input", () => done());
      helper.getNode("badOut").on("input", () => done(new Error("prefixed valid sig rejected")));
      n1.receive({ payload: "hello", signature: "sha256=" + sign("hello") });
    });
  });

  it("does not crash on a length-mismatched signature", function (done) {
    helper.load(hmacNode, flow(), { n1: { secret: SECRET } }, function () {
      const n1 = helper.getNode("n1");
      helper.getNode("okOut").on("input", () => done(new Error("short sig accepted")));
      helper.getNode("badOut").on("input", function (msg) {
        require("chai").expect(msg.hmacValid).to.equal(false);
        done();
      });
      n1.receive({ payload: "hello", signature: "ab" }); // far shorter than a real digest
    });
  });
});
