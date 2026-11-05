---
layout: post
title: "Investigating GitHub Actions Access to an AWS Role"
date: 2026-11-04
tagline: "One STS record, eight questions, and the places where the evidence runs out"
image: /IMG/110426.png
tags: [Incident Response, Identity, AWS, GitHub]
---

You are handed one record. It is an `AssumeRoleWithWebIdentity` event in a production AWS account, the role in it is named something like `example-deploy-role`, and the subject value starts with `repo:`. Somewhere in a GitHub organization you do not administer, a workflow job got an hour of credentials in your account. The ticket says "confirm scope."

Three questions follow, and they are not the same question: which GitHub execution obtained this session, why did AWS admit it, and what did it actually do? Each one is answered by different evidence, held in a different system, with different retention. Working them in order is most of the job, and most of the work is knowing exactly what each field means and where it stops meaning anything.

This walkthrough follows that path from the AWS side back to GitHub and forward again to resource activity. By the end you should be able to write a scope statement that separates what the records establish from what they merely suggest - the difference between a finding and a guess.

_Editorial Note: every account number, role ID, access key label, repository, run number and timestamp below is invented for this article. Account `111122223333` and bucket `amzn-s3-demo-bucket` are AWS documentation placeholders, not claimed to be reserved or real. No AWS account, GitHub organization or token was queried, minted or decoded in writing it. The synthetic records are trimmed to an allowlist of investigative fields: illustrations of field semantics, not observed evidence of anything._

<br>

**Start from a successful issuance, not from the event name**

An `eventName` of `AssumeRoleWithWebIdentity` tells you a request arrived. It does not tell you a session existed. The operation [returns a set of temporary security credentials](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) consisting of an access key ID, a secret access key and a security token, so the thing you need in front of you is the *response*, not just the request.

That is unusually available here. CloudTrail normally redacts `responseElements` for read-only operations, but the STS role-assumption operations are a documented exception: for `AssumeRole`, `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity`, [CloudTrail includes the full `responseElements` except `secretAccessKey`](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html). Read that twice before you export anything. The secret access key is excluded; the session token is not, and AWS's own published example event shows a `sessionToken` placeholder in the response object. Treat the raw record as credential-bearing material, pull an allowlist of fields into your case notes, and leave the rest where it is.

Here is the shape of what you keep.

```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "WebIdentityUser",
    "principalId": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com:sts.amazonaws.com:repo:example-org/example-repo:environment:prod",
    "userName": "repo:example-org/example-repo:environment:prod",
    "identityProvider": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
  },
  "eventTime": "2026-04-14T09:12:47Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRoleWithWebIdentity",
  "awsRegion": "us-west-2",
  "requestParameters": {
    "roleArn": "arn:aws:iam::111122223333:role/example-deploy-role",
    "roleSessionName": "700001-2",
    "durationSeconds": 3600
  },
  "responseElements": {
    "credentials": {
      "accessKeyId": "SYNTHETIC_SESSION_KEY_01",
      "expiration": "Apr 14, 2026, 10:12:47 AM"
    },
    "subjectFromWebIdentityToken": "repo:example-org/example-repo:environment:prod",
    "assumedRoleUser": {
      "assumedRoleId": "SYNTHETIC_ROLE_ID_01:700001-2",
      "arn": "arn:aws:sts::111122223333:assumed-role/example-deploy-role/700001-2"
    },
    "provider": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
    "audience": "sts.amazonaws.com"
  },
  "additionalEventData": {
    "identityProviderConnectionVerificationMethod": "IAMTrustStore"
  },
  "eventID": "00000000-0000-4000-8000-00000000f001",
  "readOnly": true,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "111122223333",
  "eventCategory": "Management"
}
```

_Editorial Note: synthetic and deliberately incomplete. The `secretAccessKey` and `sessionToken` fields are omitted rather than redacted, and `SYNTHETIC_SESSION_KEY_01` and `SYNTHETIC_ROLE_ID_01` are nonfunctional labels, not key-shaped strings._

Four fields carry most of the weight. `subjectFromWebIdentityToken` is, [for OpenID Connect ID tokens, the value the identity provider returned as the token's `sub` claim](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) - that is your GitHub identity string. `audience` is [the intended audience, also known as client ID, of the web identity token](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html). `assumedRoleUser` gives you the session ARN and assumed role ID. `credentials.accessKeyId` is the key the session will sign with, and it is your join key for the next step.

Two temporal traps. CloudTrail's `eventTime` is [the date and time the request was completed, in coordinated universal time](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) - a completion stamp, not a start stamp, and the acquisition time of the credentials only in the loose sense. Record it separately from the time you pulled the record. And `eventID` is [a GUID generated by CloudTrail to uniquely identify each event](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html). It identifies an event. It is not a session identifier, and there is no arithmetic that turns it into a GitHub run ID.

Note `provider` here. The STS API reference defines the response `Provider` as [the issuing authority of the web identity token, containing the value of the `iss` field for OpenID Connect ID tokens](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) - which would be the issuer URL. AWS's own OIDC CloudTrail example instead shows `provider` holding an IAM OIDC-provider ARN, and `userIdentity.identityProvider` likewise, while the CloudTrail identity reference says that for a `WebIdentityUser` the `identityProvider` field [is the issuer name of the web identity federation provider](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html). Those two representations do not agree, and I have not found a document that reconciles them. So do not hard-code an expected format: copy what your record contains, verbatim, and corroborate it against the account's IAM OIDC provider objects. The `identityProviderConnectionVerificationMethod` value under `additionalEventData` is a useful companion - it records [whether AWS verified the connection using its library of trusted root CAs (`IAMTrustStore`) or a configured certificate thumbprint (`Thumbprint`)](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html).

Finally, `readOnly` is `true` on this event, and it is worth saying what that does not mean. It classifies *this control-plane operation* as non-mutating. The credentials it handed out are a different thing, and every request made with them gets evaluated on its own against whatever policies applied at that moment - a later section's problem. Do not filter STS issuance out of an investigation because a read-only flag made it look boring.

<br>

<img width="1448" height="1086" alt="Forensic Cloud Credential Timeline" src="https://github.com/user-attachments/assets/efdb3ff1-6f07-4f3c-9877-8a55924a8f19" />

<br>

**Join the session to downstream requests, and know when you cannot**

The strongest available link between issuance and use is the access key. In a CloudTrail `userIdentity`, `accessKeyId` is [the access key ID that was used to sign the request, and for temporary credentials it is the access key ID of the temporary credentials](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html). So `responseElements.credentials.accessKeyId` from the issuance event should appear as `userIdentity.accessKeyId` on requests made with that session.

```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "SYNTHETIC_ROLE_ID_01:700001-2",
    "arn": "arn:aws:sts::111122223333:assumed-role/example-deploy-role/700001-2",
    "accountId": "111122223333",
    "accessKeyId": "SYNTHETIC_SESSION_KEY_01",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "principalId": "SYNTHETIC_ROLE_ID_01",
        "arn": "arn:aws:iam::111122223333:role/example-deploy-role",
        "accountId": "111122223333",
        "userName": "example-deploy-role"
      },
      "webIdFederationData": {},
      "attributes": {
        "creationDate": "2026-04-14T09:12:47Z",
        "mfaAuthenticated": "false"
      }
    }
  },
  "eventTime": "2026-04-14T09:13:22Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutObject",
  "awsRegion": "us-west-2",
  "requestParameters": {
    "bucketName": "amzn-s3-demo-bucket",
    "key": "deploy/example.txt"
  },
  "responseElements": null,
  "eventID": "00000000-0000-4000-8000-00000000f002",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": false,
  "recipientAccountId": "111122223333",
  "eventCategory": "Data"
}
```

Three identifier checks sit alongside the key match, then one timing check that needs care. The session ARN matches `responseElements.assumedRoleUser.arn`. The `principalId` is the assumed role ID plus session name, matching `assumedRoleId`. `sessionContext.sessionIssuer` names the issuing role, with its own stable `principalId`, `arn` and `accountId`.

Then `sessionContext.attributes.creationDate`, which is [the date and time when the temporary security credentials were issued](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html). Do not require it to equal the issuance record's `eventTime`: they are not the same quantity, the other being [the date and time the request was completed](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html). What you want is compatibility at the precision your records actually carry, with a `creationDate` at or just before the issuance `eventTime`. In the two synthetic records here they are byte-identical because I set them that way - a convenience of the example, not a matching rule to code against. A few seconds of daylight is not a reason to reject a join the access key already supports.

And none of these four are independent witnesses. They are fields AWS derived from one role assumption and carried into two records, so they corroborate the key match rather than replacing it.

Now the counterexamples, because this is where investigations quietly go wrong.

- **The issuance `principalId` is not the downstream `principalId`.** On the STS event the identity type is `WebIdentityUser`, whose `principalId` is documented as [a combination of the issuer, application ID, and user ID](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html). On the S3 event the type is `AssumedRole` and the `principalId` is the assumed role ID plus session name. Those are different namespaces; joining one to the other returns nothing.
- **The access key can be absent.** For security reasons `accessKeyId` [might not be present, or might be displayed as an empty string](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html). When that happens you fall back to session ARN plus time window, which is weaker - say so rather than quietly promoting it to the same confidence.
- **The session name is caller-controlled and reusable.** `RoleSessionName` is simply [an identifier for the assumed role session](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) supplied by the requester, and it is what gets embedded in the ARN and assumed role ID. If two jobs in one run use the same name, the session ARNs are identical and only the access key and timestamps separate them.
- **A credential match is not a person.** For `AssumeRoleWithWebIdentity`, CloudTrail records the role's subsequent API calls with [role identity only, no user](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html). You have established which credential set signed the request; who or what drove it is a separate question, answered on the GitHub side and imperfectly.

Bound the activity window with the issuance time and the expiration from the response, then look for anything signed by that key inside it. Session duration matters here: the default is [3600 seconds, and the ceiling is the role's own maximum session duration setting, which can be one to twelve hours](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html).

<br>

**Identify the GitHub run, attempt and job**

The subject in the record - `repo:example-org/example-repo:environment:prod` - tells you the repository and the job context. It does not tell you which run. For that you need GitHub-side evidence, and the fastest lead is the session name, if whoever built the workflow was thoughtful enough to make it mean something. In this case it is `700001-2`, which the workflow set from the run ID and attempt number. That is a lead, not proof; the value is caller-supplied.

Take the lead to the documented read routes. `GET /repos/{owner}/{repo}/actions/runs/{run_id}` [gets a specific workflow run](https://docs.github.com/en/rest/actions/workflow-runs), `GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}` [gets a specific workflow run attempt](https://docs.github.com/en/rest/actions/workflow-runs), and `GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs` [lists jobs for that attempt](https://docs.github.com/en/rest/actions/workflow-jobs). GitHub documents all three as usable by [anyone with read access to the repository](https://docs.github.com/en/rest/actions/workflow-runs) - which is true, and is not the whole requirement. Against a private repository the same pages add that [OAuth app tokens and personal access tokens (classic) need the `repo` scope](https://docs.github.com/en/rest/actions/workflow-jobs). That sentence covers classic tokens; I haven't verified the fine-grained-token requirements here. Confirm the requirements for your token type with whoever administers the organization before a case is on the clock.

```json
{
  "run": {
    "id": 700001,
    "run_attempt": 2,
    "run_number": 184,
    "workflow_id": 4410077,
    "path": ".github/workflows/deploy.yml",
    "event": "push",
    "head_branch": "main",
    "head_sha": "9f1c2ad4e6b8c0d2f4a6b8c0d2e4f6a8b0c2d4e6",
    "run_started_at": "2026-04-14T09:11:40Z",
    "previous_attempt_url": "https://api.github.com/repos/example-org/example-repo/actions/runs/700001/attempts/1",
    "actor": { "login": "example-author", "id": 500101 },
    "triggering_actor": { "login": "example-releaser", "id": 500102 },
    "referenced_workflows": [],
    "repository": { "id": 600200, "full_name": "example-org/example-repo" }
  },
  "job": {
    "id": 9900012345,
    "run_id": 700001,
    "run_attempt": 2,
    "name": "publish",
    "status": "completed",
    "conclusion": "success",
    "started_at": "2026-04-14T09:12:03Z",
    "completed_at": "2026-04-14T09:13:51Z",
    "runner_name": "GitHub Actions 42",
    "head_branch": "main",
    "steps": [
      { "number": 2, "name": "configure aws credentials", "started_at": "2026-04-14T09:12:44Z", "completed_at": "2026-04-14T09:12:49Z" },
      { "number": 3, "name": "upload build output", "started_at": "2026-04-14T09:12:49Z", "completed_at": "2026-04-14T09:13:40Z" }
    ]
  }
}
```

_Editorial Note: a synthetic composite of fields from two separate documented responses, trimmed to what the correlation needs. It is not a verbatim API response, and GitHub did not log any of it into CloudTrail - you gather it yourself and record that you did._

The correlation you are building is a timeline overlap, not a cryptographic binding. Step 2 ran from `09:12:44` to `09:12:49`; the STS issuance completed at `09:12:47`; the S3 write completed at `09:13:22`, inside step 3. Two AWS activity stamps, each landing inside the step that would have produced it - that is what you hoped for and worth writing down. The expiration at `10:12:47` is not a third one and does not fall inside the job at all; it is a lifetime bound that outlives the job by about an hour, which deserves its own line, because a credential that outlives the execution stays usable after it. Be careful how you describe the two that do fit. These are two systems each recording their own timestamps at their own precision, and unless you have established what time source both were using, containment is what you have - not agreement between synchronized clocks, and not independent confirmations of one fact. It stays circumstantial, and if a second job in the same window assumed the same role, you have two candidates and should report two.

<br>

<img width="1448" height="1086" alt="Forensic Cloud Credential Timeline" src="https://github.com/user-attachments/assets/7ef17c47-76f5-4e0d-b7b0-bbe2b0b3a3be" />

<br>

Some identity semantics worth getting right before you write any of this down:

- **Re-runs keep the run ID.** `github.run_id` is [a unique number for each workflow run within a repository, and this number does not change if you re-run the workflow run](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts). `github.run_attempt` [begins at 1 for the first attempt and increments with each re-run](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts). A run ID alone is therefore ambiguous across attempts, which is why the attempt-scoped job route exists.
- **A run and attempt still are not one execution.** The pair does not identify a single job, a single matrix leg, or a single STS call: a workflow can assume the same role from several jobs, and a job can assume it more than once. So enumerate the attempt's job list completely before ruling any job out. It is paginated - [30 results per page by default, 100 maximum](https://docs.github.com/en/rest/actions/workflow-jobs) - and the response carries a `total_count` to reconcile against the rows you collected. Excluding a competing candidate on the strength of page one is how the second candidate disappears from the report.
- **The numeric job ID is not `github.job`.** The REST `job.id` is an integer; `github.job` is the workflow's job key, `publish` in this example. Keep both, and label them.
- **Actor and triggering actor can differ, and the privilege story is counterintuitive.** GitHub documents that [re-runs use the privileges of `github.actor`, even if the actor initiating the re-run (`github.triggering_actor`) has different privileges](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts). That is GitHub execution context. It says nothing about AWS effective permissions, and neither login proves a human sat at a keyboard. Keep the numeric account IDs next to the logins, because logins are renameable.

One more thing about that action's retry behavior, because it produces a specific false lead. The pinned README for the AWS credentials action states that on a failed STS call it retries [with exponential backoff twelve times by default](https://raw.githubusercontent.com/aws-actions/configure-aws-credentials/e3dd6a429d7300a6a4c196c26e071d42e0343502/README.md), configurable through `retry-max-attempts` or disabled with `disable-retry`. So a cluster of STS records seconds apart has an innocent explanation available to it. Available is not the same as established: that explanation only holds if that action, at a revision carrying that behavior, is what actually ran, and it competes with a workflow that assumes the role repeatedly across jobs, steps or matrix legs.

What it does not compete with is credential reuse. Each `AssumeRoleWithWebIdentity` call requires another token presentation: the operation's `WebIdentityToken` parameter - [the OAuth 2.0 access token or OpenID Connect ID token that is provided by the identity provider](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) - is required. Someone using credentials already issued produces downstream calls signed by that access key, not a second assumption. The record type narrows what happened; it still does not tell you who presented the token. Establish the executed revision and check `run_attempt` before you settle it either way. A retry story is a hypothesis you test, not a reason to stop counting.

<br>

**Establish what executed, not what the branch says today**

The repository's `main` branch as it stands right now is not evidence about April. Four different things are commonly confused here, and they answer four different questions.

```yaml
name: deploy
on:
  push:
    branches: [main]
permissions:
  id-token: write
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: prod
    steps:
      - uses: actions/checkout@v6
      - name: configure aws credentials
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
        with:
          role-to-assume: arn:aws:iam::111122223333:role/example-deploy-role
          role-session-name: ${{ github.run_id }}-${{ github.run_attempt }}
          aws-region: us-west-2
      - name: upload build output
        run: aws s3 cp ./build/example.txt s3://amzn-s3-demo-bucket/deploy/example.txt
```

_Editorial Note: an illustrative fragment showing the fields this investigation reads. It is not a deployment template and has not been executed. The pinned action commit is the one GitHub's own AWS guide uses in its example workflow; inspecting that README is not an audit of the action's compiled code._

The workflow definition's own revision is `github.workflow_sha`, [the commit SHA for the workflow file](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts). The triggering commit is `github.sha`, and GitHub is explicit that [the value of this commit SHA depends on the event that triggered the workflow](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts) - for an unmerged pull request the documented `ref` is a merge ref, and `pull_request_target` events carry [the `ref` from the base branch](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts). What the job actually checked out is a third thing, decided by the checkout step. And the action revisions and any reusable workflows are a fourth; the run response carries `referenced_workflows` entries with their own `path`, `sha` and `ref` - exactly what you want when a caller workflow is doing the real work.

Be careful about promising yourself a field you may never have. `workflow_sha` is a documented context value and an [OIDC token claim](https://docs.github.com/en/actions/reference/security/oidc); it is not a documented member of the REST workflow run response schema, which carries `path`, `workflow_id` and `head_sha` instead. Get the definition's revision from retained run evidence rather than assuming an API hands it over.

Tags are moving pointers. `actions/checkout@v6` is a tag, and resolving that tag today tells you what it points at today. The revision that ran in April has to come from evidence retained from April, and the attempt logs are the usual place to look: GitHub documents a [redirect URL to download an archive of log files for a specific workflow run attempt](https://docs.github.com/en/rest/actions/workflow-runs), and that link expires after one minute, so follow the redirect programmatically rather than pasting it into a browser tab you will get back to in a moment.

Two things that endpoint does not promise. It does not promise the logs are still there - retention is a separate setting, and [deleting all logs for a workflow run](https://docs.github.com/en/rest/actions/workflow-runs) is its own documented route, so absence of logs is not evidence about what ran. And it does not promise that every executed revision was ever written into them; a step that resolves an action to a commit without printing it leaves you nothing to read. When it is unrecoverable, record it as unrecoverable from retained evidence. Do not solve the gap with a fresh run or a fresh OIDC token; a new token is evidence about now.

And resist the urge to dump the whole `github` context into the job log to fill in blanks. GitHub warns that [certain contexts should be treated as untrusted input](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts), and `github.token` is [a token to authenticate on behalf of the GitHub App installed on your repository](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts) - a third credential, distinct from the OIDC JWT and the AWS session. Three credentials, three blast radii, and only one is what you are investigating.

While we are on that: `id-token: write` is the permission that lets the job get the JWT at all, and GitHub is blunt that [this setting only enables fetching and setting the OIDC token; it does not grant write access to other resources](https://docs.github.com/en/actions/reference/security/oidc). Seeing it in a workflow file is not a finding.

<br>

<img width="863" height="569" alt="GitHub AWS Evidence Correlation Flowchart" src="https://github.com/user-attachments/assets/f34d9679-69af-44fa-9daa-841403c443f5" />

<br>

**Work out why AWS admitted the subject - at the time, not today**

Now the trust layer. Three things had to be true: an OIDC provider had to exist and validate the token, the role's trust policy had to allow this principal and action, and its conditions had to match the presented claims.

The provider is account-local. AWS notes that [OIDC IdPs used in a role trust policy must be in the same account as the role that trusts it](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html), and the provider registration carries the issuer URL and the audience list. GitHub's AWS guide says to register the `token.actions.githubusercontent.com` issuer as the provider URL and to use [`sts.amazonaws.com` as the audience if you are using the official action](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws). That is not GitHub's own default: GitHub's OIDC reference says the `aud` claim [is by default the URL of the repository owner](https://docs.github.com/en/actions/reference/security/oidc), and the action's README states that [by default the audience is `sts.amazonaws.com`](https://raw.githubusercontent.com/aws-actions/configure-aws-credentials/e3dd6a429d7300a6a4c196c26e071d42e0343502/README.md), with a documented [`sts.amazonaws.com.cn` example for a China-region audience](https://raw.githubusercontent.com/aws-actions/configure-aws-credentials/e3dd6a429d7300a6a4c196c26e071d42e0343502/README.md). So an `audience` of `sts.amazonaws.com` in your record is the AWS action's convention in the commercial partition, and any other value - an owner URL, a different partition's endpoint - is worth a second look.

Then the trust policy, which is not the same document as the role's permissions. AWS separates them explicitly: one is [the trust policy that specifies who can assume the role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html), the other is [the permissions policy that specifies the AWS actions and resources](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html) the assumed identity may use. Conflating them produces confident wrong answers in both directions.

Here is the trust document this synthetic case stipulates was in force from 2026-02-03. Note what that sentence is doing: in a real investigation a dated historical policy is an artifact you have to go and find, and stipulating one is the move you are not allowed to make.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GitHubDeploy",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:*"
        }
      }
    }
  ]
}
```

And here is the `Role.AssumeRolePolicyDocument` extracted from a `GetRole` capture taken on 2026-09-19, five months after the session. One field out of that response, not the response - and decoded conditionally rather than reflexively. AWS notes that [policies returned by this operation are URL-encoded compliant with RFC 3986](https://docs.aws.amazon.com/cli/latest/reference/iam/get-role.html) and, in the same note, that [some SDKs do this decoding automatically](https://docs.aws.amazon.com/cli/latest/reference/iam/get-role.html). So look at what you actually got back and decode only if it is still encoded; running a decode over an already-decoded document is how a `+` inside a value quietly becomes a space.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GitHubDeploy",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:example-org/example-repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

If you only had the second document you would reach a contradiction: the job ran on `main`, the current policy allows exactly `main`, and yet the recorded subject is an environment subject that this policy does not match. The trap is temporal. `GetRole` [retrieves information about the specified role](https://docs.aws.amazon.com/cli/latest/reference/iam/get-role.html) as it stands when you ask, and the `CreateDate` it returns is [when the role was created](https://docs.aws.amazon.com/cli/latest/reference/iam/get-role.html) - not when the trust policy last changed. The change itself is a separate, findable event: `UpdateAssumeRolePolicy` [updates the policy that grants an IAM entity permission to assume a role](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAssumeRolePolicy.html).

Finding those events is necessary. It is not sufficient. Reconstructing the policy *this way* - a dated baseline carried forward through the changes recorded after it - needs four things, and a gap in any one of them leaves this particular reconstruction incomplete rather than merely approximate: a dated baseline document you actually hold, the *successful* change events between that baseline and the issuance, a coverage statement establishing that your search would have surfaced those events had they existed, and the identity of the role itself. That is a requirement list for this route, not a claim that it is the only credible one; the alternatives below have their own, different requirements. On that last point, `GetRole` returns `RoleId`, [the stable and unique string identifying the role](https://docs.aws.amazon.com/cli/latest/reference/iam/get-role.html), which is what tells you whether a role deleted and recreated under the same ARN is the same role. Every ARN in your notes looks identical either way.

Two things you must not do with this. First, do not describe the current narrow policy as the explanation for an earlier environment-subject issuance. It is a later state of the same role, and what the pair establishes is that the scope changed somewhere between those two dates. Calling the tightening a remediation asserts a cause and a motive you have not evidenced - an unrelated cleanup, a template rollout or a different incident entirely all produce the same pair of documents. Second, do not describe an absent change event as proof nothing changed. That depends on collection coverage, which is the last section of this article.

One more place people stop too early. IAM not versioning a document is a statement about IAM, not about the world. A trust policy or an inline policy may still be recoverable from a configuration-management snapshot, a change-management record, or the repository that defines the infrastructure - and if you go there, keep the distinction between a committed definition and the deployed state. A merged commit is a proposed change with a date on it; whether it was ever applied to that role, and when, the commit cannot answer.

<br>

**The subject format question, and a matrix that settles it**

GitHub builds the default subject by concatenating workflow metadata, and the precedence rules are the part people get wrong. The subject [includes the environment name when the job references an environment](https://docs.github.com/en/actions/reference/security/oidc). It [includes the branch name only if the job doesn't reference an environment, and if the workflow is not triggered by a pull request event](https://docs.github.com/en/actions/reference/security/oidc). And it includes [the `pull_request` string when the workflow is triggered by a pull request event, but only if the job doesn't reference an environment](https://docs.github.com/en/actions/reference/security/oidc).

Those are mutually exclusive suffixes. A job on `main` that declares `environment: prod` produces `repo:example-org/example-repo:environment:prod`. It does not produce a subject containing both the branch and the environment, and GitHub's AWS guide agrees from the other direction: if you use a workflow with an environment, [the `sub` field must reference the environment name](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws). That rule is why a `main`-branch job here does not match a `main`-branch condition, and it is the first thing to check whenever a recorded subject and a written condition look like they ought to agree and do not.

The matching itself is ordinary string comparison, not a regex engine. `StringEquals` is [exact matching, case sensitive](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String). `StringLike` is [case-sensitive matching whose values can include multi-character match wildcards (`*`) and single-character match wildcards (`?`) anywhere in the string](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String). And absence is not neutrality: [if the key that you specify in a policy condition is not present in the request context, the values do not match and the condition is false](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html).

<br>

<img width="877" height="389" alt="GitHub OIDC Subject Matching" src="https://github.com/user-attachments/assets/40fe9b6b-e45c-4e58-bea0-0749b1d3680d" />

<br>

Apply both `Condition` blocks above to the same claim pairs:

| Claims presented | Narrow (`StringEquals` on main) | Broad (`StringLike` on repo) |
| --- | --- | --- |
| `aud` `sts.amazonaws.com`, `sub` `repo:example-org/example-repo:ref:refs/heads/main` | match | match |
| `aud` `sts.amazonaws.com`, `sub` `repo:example-org/example-repo:ref:refs/heads/feature` | no match | match |
| `aud` `sts.amazonaws.com`, `sub` `repo:example-org/example-repo:pull_request` | no match | match |
| `aud` `sts.amazonaws.com`, `sub` `repo:example-org/example-repo:environment:prod` | no match | match |
| `aud` `sts.amazonaws.com`, `sub` `repo:example-org/other-repo:ref:refs/heads/main` | no match | no match |
| `aud` `sts.amazonaws.com.cn`, `sub` `repo:example-org/example-repo:ref:refs/heads/main` | no match | no match |
| `aud` `sts.amazonaws.com`, `sub` `repo:Example-Org/example-repo:ref:refs/heads/main` | no match | no match |
| `aud` `sts.amazonaws.com`, `sub` key absent from request context | no match | no match |

_Editorial Note: every row uses the legacy default subject format, which this case stipulates for the April repository - no subject customization, no immutable-format transition, and an issuance date preceding the July 15, 2026 transition date GitHub documents. I computed these results offline with ordinary case-sensitive string and prefix-glob matching against the two `Condition` blocks printed above, treating each key as single-valued and feeding both policies the identical `aud` and `sub` values per row. That is a consistency check on the article's own examples, not an IAM authorization simulation and not a claim about any real policy. The broad policy is shown because it explains row four, not as a recommendation._

Row four is the whole point: the environment job fails the exact-branch condition and satisfies the repository wildcard, which is how a historical broad policy explains an issuance that today's narrow policy would refuse. Row seven is the quiet one - a single capitalized character in an organization name breaks both policies, because both operators are case sensitive.

Row eight is the abstract case - the key is simply not in the request context - and it is in the table because IAM's documented answer there is *false*, not *skip this condition*. Be precise about what row eight is not, because this is where the subject-format story gets misremembered. A format migration does not remove the `sub` key. An immutable-ID subject or a customized template still arrives as a `sub` claim; the claim is present, it just carries a value that no longer matches a condition written against the older literal string. That failure has row five's shape - a value mismatch - not row eight's. Expect the key, check the value.

Which brings up formats. As read today, GitHub documents that [repositories created after July 15, 2026 now use an immutable default subject format that includes both the owner ID and repository ID](https://docs.github.com/en/actions/reference/security/oidc), shaped `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`. Repositories created earlier [keep the previous format unless you opt in](https://docs.github.com/en/actions/reference/security/oidc), and [repository renames and transfers after July 15, 2026 also move to the immutable subject format](https://docs.github.com/en/actions/reference/security/oidc). The rollout [does not include GitHub Enterprise Server](https://docs.github.com/en/actions/reference/security/oidc).

Do not turn that into date arithmetic. Establish the format your investigation actually saw from the recorded subject and the dated configuration, because opt-in, renames and transfers all move a repository between formats without changing its creation date. The IDs address namespace reuse - they stop a recycled name from producing a previously-issued subject - and that is all they address. They are not evidence of code integrity or an attribution to a person, the human-readable names are still in the string, and an ID-bearing subject sails straight through a condition wildcarded broadly enough to ignore the segment the IDs live in.

Subject customization complicates this further. A template [results in a new format for the entire `sub` claim](https://docs.github.com/en/actions/reference/security/oidc), which can carry [the value of the `job_workflow_ref` claim](https://docs.github.com/en/actions/reference/security/oidc) for enforcing a reusable workflow. If a template was in force, the default rules above do not describe your subject at all. Where immutable IDs apply, GitHub notes they [are always included in the `repo` segment even when you customize claims](https://docs.github.com/en/actions/reference/security/oidc).

What you cannot do is condition on arbitrary GitHub claims in AWS. The token carries `run_id`, `run_attempt`, `workflow_ref`, `job_workflow_ref`, `runner_environment` and more as [custom claims provided by GitHub](https://docs.github.com/en/actions/reference/security/oidc), but GitHub's AWS guide states flatly that [support for custom claims for OIDC is unavailable in AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws). If you catch yourself writing `token.actions.githubusercontent.com:run_id` into a report, you have invented a condition key.

Two closing notes on this layer. IAM does enforce a minimum: when GitHub's OIDC IdP is the trusted principal, IAM checks at trust-policy creation or update time that [the condition key `token.actions.githubusercontent.com:sub` is present and that its value is not solely a wildcard character or null](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html). That is a floor, not evidence of appropriate scoping. And environments are a separate control surface: AWS recommends [using deployment branches and tags to restrict which branches and tags can deploy to the environment](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html). An `environment:prod` subject proves the job referenced an environment named `prod`. It does not prove a branch restriction or a required review existed at the time, let alone that one was satisfied. Those are separate artifacts: the environment's historical configuration, and the run's own approval history, which has a documented read route in `GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals` - [the review history for a workflow run](https://docs.github.com/en/rest/actions/workflow-runs), returning the environments involved, a state, the reviewing user and their comment. An empty review history and an unprotected environment look identical in the subject and nothing alike in the report.

<br>

**Separate what the session could do from what it did**

Successful issuance says AWS accepted the identity. It says nothing about resource permissions. Pick one concrete question: could this session perform `s3:PutObject` on `arn:aws:s3:::amzn-s3-demo-bucket/deploy/example.txt`?

For that you read the role's permissions, which live in more than one place. Inline documents come from `GetRolePolicy`; for attached managed policies you [use `GetPolicy` to determine the policy's default version, then use `GetPolicyVersion` to retrieve the policy document](https://docs.aws.amazon.com/cli/latest/reference/iam/get-role-policy.html). Getting that two-step wrong is a common way to read the wrong document entirely.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WriteDeployPrefix",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/deploy/*"
    }
  ]
}
```

Versioning has its own temporal trap, symmetrical to the trust-policy one. A managed policy's default version is [the operative version](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html), a managed policy [can have up to five versions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html), older versions can be deleted, and [IAM does not support versioning for inline policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html) at all. So today's default version is not necessarily April's default version, and for an inline policy there is no revision history inside IAM to walk - the same fact about IAM, with the same external alternatives, as in the trust-policy section. Track `CreatePolicyVersion` and `SetDefaultPolicyVersion` events with their outcomes. And the `"Version": "2012-10-17"` string at the top of every document is the policy language version, not a revision date - it will be identical on documents written years apart.

The evaluation itself is not a single lookup. [By default, all requests are implicitly denied](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html), requests [must be explicitly allowed by a policy or set of policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html), and [an explicit deny overrides an explicit allow](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html). The policies in scope for the deny sweep are broad: [AWS Organizations SCPs and RCPs, resource-based policies, identity-based policies, IAM permissions boundaries, and session policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html). Session policies matter directly here, because [passing policies to this operation returns new temporary credentials whose permissions are the intersection of the role's identity-based policy and the session policies](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html), and the AWS credentials action exposes both [inline and managed session policy inputs](https://raw.githubusercontent.com/aws-actions/configure-aws-credentials/e3dd6a429d7300a6a4c196c26e071d42e0343502/README.md).

But do not reach for "effective permissions are the intersection of everything" as a universal rule, because there is a documented exception that runs the other way. Within the same account, a resource-based policy that grants permissions to an IAM role *session* ARN grants them directly to that session, and [permissions granted directly to a session are not limited by an implicit deny in an identity-based policy, a permissions boundary, or session policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html). A bucket policy naming `arn:aws:sts::111122223333:assumed-role/example-deploy-role/700001-2` can therefore allow something the role's own identity policy never mentions. That exception covers implicit denies only. Explicit denies and applicable organization controls still bite.

So you get three honest verdicts, not one. Before the first one can mean anything, though, I have to say what this synthetic case stipulates. The moment that matters is when AWS evaluated the request, which is not when the credentials were issued - and `09:13:22` does not name that moment either, because it is a completion stamp. It closes the interval rather than marking a point inside it. So the stipulation has to cover that whole interval, from the request through the completion it records:

- the identity policy fragment above was attached to the role and was the operative document then;
- the bucket is a same-account general purpose bucket using SSE-S3, and the write is one ordinary object;
- no session policy was passed on the assumption, and no permissions boundary applied to the role;
- any applicable SCPs and RCPs permitted the action - a stipulation about this invented account, not a suggestion that organizations generally lack such controls;
- no resource-based policy or other applicable policy carried an explicit deny reaching this action and resource;
- no KMS, ACL, tagging, Object Lock, access point or VPC endpoint condition was in play, and no bucket policy granted anything directly to the session ARN.

Those six lines are stipulations for an illustration, asserted across that interval rather than at an instant. They are not retained facts, and the reason to write them out rather than wave at them is that each one is a document you either hold or do not:

- **Allowed under stated assumptions.** `s3:PutObject` on `arn:aws:s3:::amzn-s3-demo-bucket/deploy/example.txt` is permitted given that baseline. The named object, not the prefix - the allow statement is wider than the object, but your verdict should not inherit that width, because every object you fold into it is one more request context you are silently asserting the baseline held for.
- **Denied.** An applicable explicit deny covers the action and resource: the session was admitted to AWS and still could not do this thing. Issuance and authorization are sequential stages with different inputs and different policy documents behind them, not one decision taken twice.
- **Undetermined.** You have the trust policy and the issuance, but a material policy document from the relevant time is unavailable. Undetermined is a real finding and belongs in the report as one. Reconstructing the missing policy from whatever would explain the outcome is circular reasoning in a lab coat.

Then, separately, look at what actually happened - and notice that the excerpt printed earlier cannot answer that by itself. An allowlisted excerpt with no error fields is not the same artifact as a complete record with no error fields; the first is equally consistent with my having dropped them on the way in. I checked the underlying synthetic record before excerpting it, found no error fields, and this example stipulates that the operation succeeded. That is a statement about a fixture I built; in your case it is a check you run against the complete record, before an outcome goes anywhere near the report.

Where to look. Errors appear in the record's `errorCode`, [the AWS service error if the request returns an error](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html), and some services put [error information as part of `responseElements`](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) instead. The standard record reference does not define a general HTTP status field carried by every event, so do not invent one and do not read the absence of error fields as a recorded HTTP 200. That is a statement about the common record shape: where a particular service does surface status in its own records, cite it. Once you do have a complete record with no reported error, S3's own semantics carry you a useful distance - [if the action is successful, the service sends back an HTTP 200 response](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html), and [Amazon S3 never adds partial objects; if you receive a success response, Amazon S3 added the entire object to the bucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html). So a clean record supports "the object write completed", not "something half-landed in the bucket".

And keep the ladder straight. What the policy permitted, what the API returned, whether the deployment was approved, and whether the object's contents were benign are four separate claims. A complete, error-free record settles the second, within the limits of what was collected, and says nothing about the third or fourth.

<br>

**Establish coverage before you claim absence**

Every "we found no evidence of X" is really a statement about your collection. Get the coverage story written down before the conclusions.

The console's Event history is the narrowest surface. AWS states that [an event history search is limited to a single AWS account, only returns events from a single AWS Region, and cannot query multiple attributes](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html), and that [it does not show data events, Insights events, or network activity events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html). The API behind it is bounded the same way: you can [look up events that occurred in a Region within the last 90 days](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html), and the attribute list [can contain only one item](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html).

That 90-day bound is the first thing to check against your own dates, and here it decides the shape of the entire section. The issuance is dated 2026-04-14. Ninety days ran out in July, so no lookup run today reaches it and no parameter on the command fixes that. What follows is therefore the command the responder on duty ran on 2026-04-15, while the event was still inside the window - writing the response into the case's evidence store, where it has been sitting ever since.

```bash
# Run 2026-04-15, while the event was still inside the 90-day window.
# Pre-provisioned read-only profile. No credential or sign-in commands here.
aws cloudtrail lookup-events \
  --profile ir-readonly-111122223333 \
  --region us-west-2 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity \
  --start-time 2026-04-14T00:00:00Z \
  --end-time 2026-04-15T00:00:00Z \
  --output json \
  > /cases/2026-0414-deploy-role/evidence/sts-lookup-us-west-2.json
```

_Editorial Note: printed for reading, not for running, and the profile name is invented. The point is that the command names a deliberate, recorded configuration instead of inheriting whatever the shell happened to hold - not that the string proves anything about the account behind it. A profile authorizes exactly what the credentials behind it authorize; it is not standing permission to sweep an organization, and whose account you may read is a question for your own authorization process._

Inheriting an old case means inheriting that file, the trail's S3 objects, or a CloudTrail Lake event data store whose retention still covers April. No query recovers activity nobody recorded.

`--profile` selects a named configuration explicitly, so the capture records a deliberate choice rather than ambient credentials - but a profile name is a label, not a binding. Nothing about the string `ir-readonly-111122223333` establishes that the profile resolves to account `111122223333`, or that it is read-only. Confirm which account you are actually reading, under your own authorization, and write down what you confirmed.

`--region` is the one that genuinely pins something: it selects the Region explicitly and [overrides config and environment settings](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html), because a capture that does not say which Region it came from is not evidence. The time bounds are inclusive at both ends - `--start-time` returns [only events that occur after or at the specified time](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html), `--end-time` [only events that occur before or at the specified time](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html) - and they are written in UTC to match `eventTime`. There is exactly one lookup attribute, because one is all the API accepts.

There is deliberately no `--no-paginate` and no `--max-items`: `lookup-events` is a paginated operation and [multiple API calls may be issued in order to retrieve the entire data set of results](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html), so leaving the CLI's automatic pagination alone is what gets you the whole set rather than the first slice. If you have seen the number 50 attached to this API, that is the service's page size, not a result cap: AWS describes `--page-size` as [the size of each page to get in the AWS service call, which does not affect the number of items returned in the command's output](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html). Do not report fifty as a ceiling.

Redirecting to a file is deliberate for the reason given earlier: the response carries full STS `responseElements`. It belongs in the case's restricted evidence directory - not a repository, not a synced drive, not terminal scrollback - and that exact path is the input the filter below opens.

Note also what this command is not for: it looks up management events, so the `PutObject` from earlier will never appear in its output. That is the second coverage trap below.

Because you can only filter on one attribute, narrowing to a specific role happens locally - and it happens on parsed structure, not on text. The `CloudTrailEvent` field is [a JSON string that contains a representation of the event returned](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html), so it arrives as an escaped blob. Grepping that blob for an ARN matches role names inside unrelated fields and misses anything the escaping mangles.

Most of the filter below is not filtering. It is the difference between *no matching events* and *this input cannot tell me whether there were matching events* - the one distinction in this article that a script can quietly get wrong on your behalf.

```python
import json
import sys

ROLE = "arn:aws:iam::111122223333:role/example-deploy-role"
CAPTURE = "/cases/2026-0414-deploy-role/evidence/sts-lookup-us-west-2.json"

ABSENT = "-"
MALFORMED = "<malformed>"


def usable(value):
    """A consumed field is usable only as a non-blank string."""
    return isinstance(value, str) and bool(value.strip())


def render(value):
    """Escape one consumed value for printing. Returns (text, malformed)."""
    if value is None:
        return ABSENT, False
    if not usable(value):
        return MALFORMED, True
    return json.dumps(value, ensure_ascii=True), False


def classify(item):
    """Bucket one Events row. Returns (verdict, reason, record)."""
    if not isinstance(item, dict):
        return "unreadable", "row is not an object", None
    blob = item.get("CloudTrailEvent")
    if isinstance(blob, dict):
        record = blob
    elif isinstance(blob, str):
        try:
            record = json.loads(blob)
        except ValueError:
            return "unreadable", "CloudTrailEvent is not valid JSON", None
    else:
        return "unreadable", "CloudTrailEvent missing or not a JSON string", None
    if not isinstance(record, dict):
        return "unreadable", "CloudTrailEvent did not decode to an object", None
    source = record.get("eventSource")
    name = record.get("eventName")
    if not usable(source) or not usable(name):
        return ("indeterminate",
                "eventSource or eventName absent, blank or not a string", record)
    if source != "sts.amazonaws.com" or name != "AssumeRoleWithWebIdentity":
        return "out_of_scope", "a different well-formed service or operation", record
    params = record.get("requestParameters")
    if not isinstance(params, dict):
        return "indeterminate", "requestParameters absent or not an object", record
    role_arn = params.get("roleArn")
    if not usable(role_arn):
        return "indeterminate", "roleArn absent, blank or not a string", record
    if role_arn != ROLE:
        return "other_role", "roleArn names a different role", record
    return "match", "", record


def excerpt(record):
    """Output allowlist. Never widen this to the whole responseElements object."""
    response = record.get("responseElements")
    response = response if isinstance(response, dict) else {}
    creds = response.get("credentials")
    creds = creds if isinstance(creds, dict) else {}
    raw_key = creds.get("accessKeyId")
    raw_code = record.get("errorCode")
    has_message = record.get("errorMessage") is not None

    if raw_key is None:
        key_state = "absent"
    else:
        key_state = "present" if usable(raw_key) else "malformed"
    if raw_code is None:
        # A message with no code is an error signal this script cannot read.
        code_state = "malformed" if has_message else "unreported"
    else:
        code_state = "reported" if usable(raw_code) else "malformed"

    conflict = code_state == "reported" and key_state == "present"
    if code_state == "malformed" or key_state == "malformed" or conflict:
        outcome = "outcome-unclear"
    elif code_state == "reported":
        outcome = "rejected"
    elif key_state == "present":
        outcome = "issued"
    else:
        outcome = "outcome-unclear"

    event_time, bad_time = render(record.get("eventTime"))
    event_id, bad_id = render(record.get("eventID"))
    subject, bad_subject = render(response.get("subjectFromWebIdentityToken"))
    key, _ = render(raw_key)
    if code_state == "reported":
        code = json.dumps(raw_code, ensure_ascii=True)
    elif code_state == "malformed":
        code = MALFORMED
    else:
        code = ABSENT
    return {
        "eventTime": event_time,
        "eventID": event_id,
        "errorCode": code,
        "subject": subject,
        "accessKeyId": key,
        "outcome": outcome,
        "unresolved": any((bad_time, bad_id, bad_subject, conflict,
                           key_state == "malformed", code_state == "malformed")),
    }


try:
    with open(CAPTURE, encoding="utf-8") as fh:
        payload = json.load(fh)
except (OSError, ValueError) as exc:
    # Type only. A path or parse message can echo capture contents into a log.
    print("capture unusable ({}); no coverage claim rests on this run".format(
        type(exc).__name__), file=sys.stderr)
    sys.exit(2)

if not isinstance(payload, dict) or not isinstance(payload.get("Events"), list):
    print("capture is not a LookupEvents response envelope", file=sys.stderr)
    sys.exit(2)

counts = {"match": 0, "other_role": 0, "out_of_scope": 0,
          "indeterminate": 0, "unreadable": 0}
unresolved = 0

for index, item in enumerate(payload["Events"]):
    verdict, reason, record = classify(item)
    counts[verdict] += 1
    if verdict == "match":
        row = excerpt(record)
        if row["unresolved"]:
            unresolved += 1
        print("row {} match {} {} {} sub={} key={} err={}".format(
            index, row["eventTime"], row["eventID"], row["outcome"],
            row["subject"], row["accessKeyId"], row["errorCode"]))
    elif verdict in ("indeterminate", "unreadable"):
        print("row {} {}: {}".format(index, verdict, reason), file=sys.stderr)

print("rows={} match={} other_role={} out_of_scope={} "
      "indeterminate={} unreadable={} unresolved={}".format(
          len(payload["Events"]), counts["match"], counts["other_role"],
          counts["out_of_scope"], counts["indeterminate"],
          counts["unreadable"], unresolved))

incomplete = bool(counts["indeterminate"] or counts["unreadable"] or unresolved)
if "NextToken" in payload:
    if usable(payload["NextToken"]):
        print("PARTIAL: NextToken set, further pages were not collected",
              file=sys.stderr)
    else:
        print("PARTIAL: NextToken present but not a usable page token; "
              "completeness is unconfirmed, not disproved", file=sys.stderr)
    incomplete = True

sys.exit(1 if incomplete else 0)
```

_Editorial Note: this parses JSON and compares strings. It is not an IAM decision, not a schema validation, and it contacts nothing. While writing this section I ran the exact block above offline against 50 synthetic in-memory inputs - well-formed rows, wrong-service and wrong-role rows, absent and wrong-typed discriminators, blank and wrong-typed role ARNs, malformed envelopes and rows, nested objects planted in the fields it prints, conflicting error-and-credential combinations, and several `NextToken` shapes - with the file read faked and both output streams captured. That establishes how this code behaves on those inputs and nothing whatever about AWS._

Four deliberate choices in there, all of them about refusing to round an unknown down to a known. It validates `eventSource` and `eventName` as non-blank strings before comparing them, so a row whose discriminators are missing, null or some other type becomes indeterminate rather than a confident exclusion - while a row naming a genuinely different service or operation stays an ordinary out-of-scope miss. It keeps *this record does not concern your role* separate from *this record cannot tell me either way*, so an absent, blank or wrong-typed `roleArn` is indeterminate, and one malformed row does not silently take the rest of the file down with it. It type-checks and escapes every value it prints, so a nested object where a timestamp should be prints as `<malformed>` rather than stringifying a credential object into your notes, and a value carrying newlines cannot forge a second output row. And it reads `NextToken` by presence and shape rather than truthiness: a present, non-blank string means pages you did not collect, because AWS is explicit that [if the token does not appear, there are no more results to return](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html), while a present token of any other shape means completeness is unconfirmed rather than disproved.

The output is an allowlist, same discipline as the case notes: event time, event ID, outcome, subject, access key ID, error code, each one rendered as a fixed indicator or an escaped string and never as a stringified container. Failure messages are fixed strings and never echo record, message or exception content. The outcome handling makes four distinctions: a usable key with no reported error is issuance evidence in this record's documented context; a reported error with no key is a recorded rejection; a key and an error together, a malformed error field, or an `errorMessage` with no `errorCode` is unclear rather than either; and an absent key stays unclear even when the rest of the record looks healthy, because AWS documents that the field can simply be missing. Exit zero means no unresolved condition in the rows this capture held, under those checks - not that retention covered the period, not that the selectors collected what you needed, and not that the printed fields are proof against every hostile input.

Three coverage traps specific to this investigation:

- **`AccessKeyId` as a lookup attribute is not your session key.** The lookup output's `AccessKeyId` is [the access key ID that was used to sign the request](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html). On the issuance event, the session key lives *inside* the response, and the request itself is unsigned federation traffic. Use that attribute to find what the session went on to do; do not expect it to surface the issuance.
- **S3 object activity is not in management events at all.** Object operations such as `GetObject`, `DeleteObject` and `PutObject` on general purpose buckets are [data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html), and [by default, trails and event data stores do not log data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html). Whether your April write was recorded depends on the selectors in force in April: AWS's own example walks through an event that [occurred on an object that doesn't match the prefix specified in your trail or event data store](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html) and is therefore not logged, and read-only object APIs are dropped by a write-only selector. Check the historical selector configuration, prefix, read/write choice, region and retention before you interpret silence. Turning collection on now recovers nothing from then.
- **Look in the right region for STS.** AWS notes that [CloudTrail logs for requests made to the AWS STS global endpoint will be sent to the US East (N. Virginia) Region](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html), while [logs for requests served by AWS STS Regional endpoints will continue to be logged to their respective Region](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html). This article's example stipulates a regional endpoint, hence `us-west-2`. Do not assume that; where present, `additionalEventData.RequestDetails.endpointType` and `awsServingRegion` give you the endpoint type and the serving region, and the serving region is not the logging region.

Last, the hardest one. A missing issuance event is not a documented rejection. CloudTrail logs non-authenticated requests to `AssumeRoleWithWebIdentity`, but AWS states that [some non-authenticated AWS STS requests might not be logged because they do not meet the minimum expectation of being sufficiently valid to be trusted as a legitimate request](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html). No event is a coverage statement, not proof that a request was denied or that nothing was attempted.

<br>

**Write the scope statement in layers**

The deliverable is not "the workflow was fine" or "an attacker had prod." It is a set of conclusions, each labeled with the evidence that carries it:

- **Observed.** A successful `AssumeRoleWithWebIdentity` for `example-deploy-role` at `2026-04-14T09:12:47Z` in account `111122223333`, subject `repo:example-org/example-repo:environment:prod`, audience `sts.amazonaws.com`, credentials expiring at `10:12:47Z`.

- **Credential-correlated.** One `PutObject` on `amzn-s3-demo-bucket/deploy/example.txt` at `09:13:22Z`, joined by access key, session ARN and assumed role ID, with a `sessionContext.attributes.creationDate` consistent with the issuance, and no service error anywhere in the complete record.

- **GitHub association, with confidence.** Run `700001`, attempt `2`, job `9900012345`, supported by the recorded subject, an explicitly configured run-and-attempt session name, and step timings that bracket the issuance. It is a strong circumstantial association, not a cryptographic binding, and a generic session name would have left it ambiguous.

- **Explained by historical configuration.** The trust policy in force on that date allowed the repository-wide subject wildcard with the matching audience. The current policy is narrower, which is a later change, not the reason the session was issued.

- **Bounded capability.** `s3:PutObject` on `arn:aws:s3:::amzn-s3-demo-bucket/deploy/example.txt`, under the policy and request-context assumptions listed above, held across the request interval that `09:13:22` closes - listed, not implied. Nothing is claimed about the rest of the `deploy/` prefix, because nothing was checked about it.

- **Unresolved.** Whatever you did not establish. Executed action revisions. Environment protection rules as configured in April. Data-event coverage outside the recorded selector. Whether a human initiated the re-run or a scheduled process did.

That last section is the one that earns trust. It is also the easiest one to cut when the ticket is overdue, which is exactly the wrong trade.

One forward-looking change is worth the five minutes it takes. Session names are caller-controlled, and the AWS credentials action documents that [the default session name is "GitHubActions"](https://raw.githubusercontent.com/aws-actions/configure-aws-credentials/e3dd6a429d7300a6a4c196c26e071d42e0343502/README.md) and that [you can modify it by specifying the desired name in `role-session-name`](https://raw.githubusercontent.com/aws-actions/configure-aws-credentials/e3dd6a429d7300a6a4c196c26e071d42e0343502/README.md). A value built from `github.run_id` and `github.run_attempt` puts a lookup hint into the session name itself, which surfaces on retained records whose identity fields were populated in the first place, and not on records whose identity fields arrived empty or were trimmed on the way into your archive. That is my recommendation, not the README's, and its limits belong in the same breath: the value is still supplied by the caller and proves nothing on its own, it collides across jobs, matrix legs, repeated assumptions inside one job and different repositories that land on the same run number, and it cannot retroactively populate a single existing event.

If you are tempted to lean on session tags instead, note the action's own exception - it [uses session tagging by default during role assumption, unless you are assuming a role with a WebIdentity](https://raw.githubusercontent.com/aws-actions/configure-aws-credentials/e3dd6a429d7300a6a4c196c26e071d42e0343502/README.md), because for web identity the tags must come from inside the token. Do not expect GitHub run or actor tags on an OIDC session. And that behavior, like the default name and the retry count, is what the README at the pinned commit describes - check it against the revision your workflows actually run.

The reason to internalize all of this is not completeness for its own sake. It is that every one of these joins looks solid right up until the field is empty, the name is generic, the policy has been rewritten, or the selector never covered the prefix. Knowing in advance which link is about to break is what lets you write the honest version of the answer on the day the ticket is due.
