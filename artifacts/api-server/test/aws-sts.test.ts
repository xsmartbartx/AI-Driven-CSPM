// The real AWS SDK talking to a local mock of STS: what we send, and how failures are turned into safe messages.
process.env["AWS_ACCESS_KEY_ID"] = "test-access-key-id"; // dummy values: they only sign requests to the local mock
process.env["AWS_SECRET_ACCESS_KEY"] = "test-secret-access-key";
process.env["AWS_EC2_METADATA_DISABLED"] = "true";
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createAwsConnector } from "../src/services/aws/connector.ts";
import { AwsError } from "../src/services/aws/types.ts";

const calls: { body: URLSearchParams; auth?: string }[] = [];
let mode: "ok" | "other-account" | "denied" | "throttle" = "ok";
const xml = (s: string) => `<?xml version="1.0"?>${s}`;
const srv = createServer((req, res) => {
  let b = "";
  req.on("data", (c) => (b += c));
  req.on("end", () => {
    calls.push({ body: new URLSearchParams(b), auth: req.headers.authorization });
    if (mode === "denied") {
      res.writeHead(403, { "content-type": "text/xml" });
      return void res.end(xml(`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User: arn:aws:iam::999999999999:user/ops-secret is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::111122223333:role/R</Message></Error><RequestId>r1</RequestId></ErrorResponse>`));
    }
    if (mode === "throttle") {
      res.writeHead(400, { "content-type": "text/xml" });
      return void res.end(xml(`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error><RequestId>r2</RequestId></ErrorResponse>`));
    }
    const acct = mode === "other-account" ? "444455556666" : "111122223333";
    res.writeHead(200, { "content-type": "text/xml" });
    res.end(xml(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>session-key</AccessKeyId><SecretAccessKey>session-secret</SecretAccessKey><SessionToken>session-token</SessionToken><Expiration>2031-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>role-id:nexora-cspm</AssumedRoleId><Arn>arn:aws:sts::${acct}:assumed-role/NexoraCSPMReadOnly/nexora-cspm</Arn></AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>r3</RequestId></ResponseMetadata></AssumeRoleResponse>`));
  });
});
const ready = new Promise<string>((r) => srv.listen(0, () => r(`http://127.0.0.1:${(srv.address() as any).port}`)));
after(() => srv.close());

const target = { accountId: "111122223333", roleArn: "arn:aws:iam::111122223333:role/NexoraCSPMReadOnly", externalId: "nx-abcdefghijklmnopqrstuvwx", region: "eu-west-1" };

test("assume-role sends the role, the External ID, a 15-minute session, signed", async () => {
  mode = "ok";
  calls.length = 0;
  const aws = createAwsConnector("123456789012", { stsEndpoint: await ready });
  await aws.verify(target);
  assert.equal(calls.length, 1);
  const p = calls[0]!.body;
  assert.deepEqual([p.get("Action"), p.get("RoleArn"), p.get("ExternalId"), p.get("DurationSeconds")], ["AssumeRole", target.roleArn, target.externalId, "900"]);
  assert.match(calls[0]!.auth ?? "", /^AWS4-HMAC-SHA256 /);
});

test("a role that belongs to a different account than the user entered is refused", async () => {
  mode = "other-account";
  const aws = createAwsConnector("123456789012", { stsEndpoint: await ready });
  await assert.rejects(() => aws.verify(target), (e: any) => e instanceof AwsError && e.code === "account_mismatch");
});

test("AccessDenied becomes a friendly message with the trust-policy hint, without AWS's raw text", async () => {
  mode = "denied";
  const aws = createAwsConnector("123456789012", { stsEndpoint: await ready });
  await assert.rejects(() => aws.verify(target), (e: any) => {
    assert.ok(e instanceof AwsError);
    assert.equal(e.code, "assume_denied");
    assert.match(e.message, /trust policy allows account 123456789012/);
    assert.equal(/ops-secret|999999999999|111122223333/.test(e.message), false); // no ARNs or account ids from AWS's message
    return true;
  });
});

test("throttling is reported as such", async () => {
  mode = "throttle";
  const aws = createAwsConnector("123456789012", { stsEndpoint: await ready });
  await assert.rejects(() => aws.verify(target), (e: any) => e instanceof AwsError && e.code === "throttled");
});
