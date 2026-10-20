import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import { S3Client } from "@aws-sdk/client-s3";
import { EC2Client } from "@aws-sdk/client-ec2";
import { IAMClient } from "@aws-sdk/client-iam";
import { RDSClient } from "@aws-sdk/client-rds";
import { collectWithClients, type AwsClients } from "./collect";
import { AwsError, type AwsConnector, type AwsTarget } from "./types";

const name = (e: any): string => String(e?.name ?? e?.Code ?? "Error");

/** Turn an AWS SDK failure into something safe to show. Raw AWS messages can contain ARNs and account ids: never forwarded. */
export function friendlyAwsError(e: unknown, principalAccountId: string): AwsError {
  if (e instanceof AwsError) return e;
  const n = name(e);
  if (/^(AccessDenied|AccessDeniedException)$/.test(n))
    return new AwsError("assume_denied", `NEXORA could not assume the role. Check that the role exists, that its trust policy allows account ${principalAccountId} with this External ID, and that the account and role name are right.`);
  if (/Credential|NoCredentials|CredentialsProvider|ExpiredToken|InvalidClientTokenId|UnrecognizedClient|SignatureDoesNotMatch/.test(n))
    return new AwsError("platform_credentials", "NEXORA's own AWS credentials are not working on the server. This is not a problem with your account; the operator needs to fix it.");
  if (/Throttl|TooManyRequests|RequestLimitExceeded/.test(n)) return new AwsError("throttled", "AWS is rate limiting the requests. Try again in a minute.");
  if (/Timeout|ECONN|ENOTFOUND|EAI_AGAIN|NetworkingError/.test(n)) return new AwsError("network", "Could not reach AWS. Try again shortly.");
  return new AwsError("aws_error", `AWS returned an error (${n}). Try again; if it persists, check the role setup.`);
}

export function createAwsConnector(principalAccountId: string, opts: { stsEndpoint?: string } = {}): AwsConnector {
  const assume = async (t: AwsTarget) => {
    const sts = new STSClient({ region: t.region, ...(opts.stsEndpoint ? { endpoint: opts.stsEndpoint } : {}), maxAttempts: 2 });
    try {
      const r = await sts.send(new AssumeRoleCommand({
        RoleArn: t.roleArn, ExternalId: t.externalId, RoleSessionName: "nexora-cspm", DurationSeconds: 900, // 15 minutes: nothing is stored
      }));
      const c = r.Credentials;
      // the role must really belong to the account the user said it does
      if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken || !r.AssumedRoleUser?.Arn?.includes(`:${t.accountId}:`))
        throw new AwsError("account_mismatch", "The role belongs to a different AWS account than the one you entered.");
      return { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken };
    } catch (e) { throw friendlyAwsError(e, principalAccountId); }
  };
  return {
    enabled: true,
    principalAccountId,
    async verify(t) { await assume(t); },
    async collect(t) {
      const credentials = await assume(t);
      const cfg = { region: t.region, credentials };
      const clients: AwsClients = { s3: new S3Client({ ...cfg, followRegionRedirects: true }), ec2: new EC2Client(cfg), iam: new IAMClient({ ...cfg, region: "us-east-1" }), rds: new RDSClient(cfg) };
      try { return await collectWithClients(clients, { accountId: t.accountId, region: t.region }); }
      catch (e) { throw friendlyAwsError(e, principalAccountId); }
    },
  };
}

export const disabledAwsConnector: AwsConnector = {
  enabled: false, principalAccountId: "",
  async verify() { throw new AwsError("aws_not_configured", "AWS connections are not enabled on this server."); },
  async collect() { throw new AwsError("aws_not_configured", "AWS connections are not enabled on this server."); },
};
