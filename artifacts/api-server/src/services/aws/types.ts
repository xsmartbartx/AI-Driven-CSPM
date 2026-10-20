import type { Resource } from "@workspace/cspm-engine";

/** An error that is safe to show to the user: a stable code and a plain sentence. Raw AWS messages never reach clients. */
export class AwsError extends Error {
  constructor(public code: string, message: string) { super(message); }
}

export interface AwsTarget { accountId: string; roleArn: string; externalId: string; region: string }
export interface CollectResult {
  resources: Resource[];
  /** What could not be checked (denied permission, a failing service, truncation). Shown to the user. */
  notes: string[];
  /** false when anything is missing, so the scan must not conclude that unseen resources were deleted */
  complete: boolean;
}

/** Everything the API needs from AWS. Real implementation: connector.ts. Tests inject a fake. */
export interface AwsConnector {
  enabled: boolean;
  /** NEXORA's own AWS account id, which the customer's role must trust */
  principalAccountId: string;
  /** Assume the role and confirm it belongs to the expected account. Throws AwsError. */
  verify(t: AwsTarget): Promise<void>;
  collect(t: AwsTarget): Promise<CollectResult>;
}

export const REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "ca-west-1", "sa-east-1", "mx-central-1",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
  "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5",
  "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-east-1", "me-south-1", "me-central-1", "af-south-1", "il-central-1",
] as const;
