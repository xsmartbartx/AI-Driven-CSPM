// What the customer deploys in their AWS account: a read-only role that trusts NEXORA with an ExternalId.
// The permission list is the single source of truth for the template, the docs and the tests.

/** Every action is List/Get/Describe. No wildcards, no write, no data access (no s3:GetObject, no secrets, no logs). */
export const READ_ONLY_ACTIONS = [
  "s3:ListAllMyBuckets", "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicyStatus", "s3:GetBucketAcl",
  "s3:GetEncryptionConfiguration", "s3:GetBucketTagging",
  "ec2:DescribeSecurityGroups",
  "iam:ListPolicies", "iam:GetPolicyVersion",
  "rds:DescribeDBInstances",
] as const;

export const DEFAULT_ROLE_NAME = "NexoraCSPMReadOnly";
const ROLE_NAME = /^[\w+=,.@-]{1,64}$/;
export const isAccountId = (s: string) => /^\d{12}$/.test(s);
export const isRoleName = (s: string) => ROLE_NAME.test(s);
export const roleArnFor = (accountId: string, roleName: string) => `arn:aws:iam::${accountId}:role/${roleName}`;

/** CloudFormation template to paste into the customer's console. Trust is limited to our account AND the ExternalId. */
export function cloudFormationTemplate(o: { principalAccountId: string; externalId: string; roleName: string }): string {
  if (!isAccountId(o.principalAccountId) || !/^[\w-]{16,128}$/.test(o.externalId) || !isRoleName(o.roleName)) throw new Error("invalid template input");
  return `AWSTemplateFormatVersion: "2010-09-09"
Description: Read-only access for NEXORA CSPM (list/get/describe only; no data access, no changes)
Resources:
  NexoraCspmRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ${o.roleName}
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: arn:aws:iam::${o.principalAccountId}:root
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: ${o.externalId}
      Policies:
        - PolicyName: NexoraCspmReadOnly
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
${READ_ONLY_ACTIONS.map((a) => `                  - ${a}`).join("\n")}
                Resource: "*"
Outputs:
  RoleArn:
    Value: !GetAtt NexoraCspmRole.Arn
`;
}
