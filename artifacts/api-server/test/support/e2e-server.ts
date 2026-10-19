// TEST SUPPORT ONLY: the API with a fake AWS connector, used by the Playwright suite so the cloud-account screens can be
// exercised without AWS. It is not part of the production bundle (the build starts from src/index.ts) and refuses to run in production.
import { openDb } from "@workspace/db";
import { createApp } from "../../src/app";
import { config } from "../../src/config";
import { AwsError, type AwsConnector } from "../../src/services/aws/types";

if (config.prod) throw new Error("e2e-server must never run in production");

const fakeAws: AwsConnector = {
  enabled: true,
  principalAccountId: "123456789012",
  async verify(t) {
    if (t.accountId === "000000000000") throw new AwsError("assume_denied", "NEXORA could not assume the role. Check that the role exists and trusts account 123456789012 with this External ID.");
  },
  async collect(t) {
    const a = t.accountId;
    return {
      complete: true,
      notes: ["IAM: only customer-managed policies attached to something are checked."],
      resources: [
        { type: "s3_bucket", name: `${a}-public-assets`, public_read: true, encrypted: true, environment: "production" },
        { type: "s3_bucket", name: `${a}-private-logs`, public_read: false, encrypted: true },
        { type: "security_group", name: `bastion (sg-0abc)`, ingress: [{ cidr: "0.0.0.0/0", port: 22 }], environment: "production" },
        { type: "iam_policy", name: `${a}:Everything`, statements: [{ effect: "Allow", actions: ["*"], resources: ["*"] }] },
        { type: "database", name: `${a}/${t.region}/orders`, publicly_accessible: false, encrypted: false },
      ],
    };
  },
};

const db = await openDb({ dataDir: ":memory:" });
createApp(db, { aws: fakeAws }).listen(config.port, () => console.log(`e2e api on ${config.port}`));
