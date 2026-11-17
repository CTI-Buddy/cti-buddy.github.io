---
layout: post
title: "Following a Kubernetes Service-Account Token From Pod to API"
date: 2026-11-16
tagline: "One Pod, one ConfigMap read, and the decisions between them"
image: /IMG/111626.jpg
tags: [Identity, Kubernetes, Cloud]
---

Suppose a Pod in your cluster needs to read exactly one ConfigMap. You set `serviceAccountName`, you write a Role, it works, and everybody moves on. Then somebody asks the questions that actually matter. Say a copy of that Pod's token ends up in a log line - if we delete the Pod, does the copy stop working? When the file rotates and a new token lands, is the old one dead? Our own internal API wants to accept these tokens - is checking the signature enough?

Those questions concern different parts of the same credential path. The kubelet decides when the file changes. The API server's ServiceAccount authenticator decides whether the bytes are acceptable. RBAC decides, separately and afterward, whether the identity inside them is allowed to do the thing. Treating "the token" as one object with one lifetime is how people end up believing that rotation is revocation and that `aud` is a permission.

So here's the walkthrough: one namespace, one account, one narrowly scoped grant, and one request, with each field tied to the specific decision it moves. Where the behavior is in the code rather than the prose docs, I'm pinning to [Kubernetes v1.34.0, released on 2025-08-27](https://github.com/kubernetes/kubernetes/releases/tag/v1.34.0). That's a fixed reference point for reading implementation, not a claim about the latest release or a recommendation to run this one. I'm also assuming a conventionally configured cluster throughout - file-backed signing and verification keys, a configured issuer, issuer discovery available - because nearly everything below is conditional on how an administrator set the cluster up, not switched on identically everywhere.

<br>

**The setup, and what each field actually selects**

_Editorial Note: every manifest, claim payload and response below is invented for this article. The namespace, the ConfigMap and the CA bundle are stipulated prerequisites, the image reference is a deliberately non-pullable placeholder, and nothing here was applied to a cluster. It is annotated configuration, not an apply-ready workload._

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: settings-reader
  namespace: token-walkthrough
---
apiVersion: v1
kind: Pod
metadata:
  name: settings-reader
  namespace: token-walkthrough
spec:
  serviceAccountName: settings-reader
  automountServiceAccountToken: false
  containers:
    - name: app
      image: example.invalid/settings-reader:0.1
      volumeMounts:
        - name: api-identity
          mountPath: /var/run/demo-identity
          readOnly: true
  volumes:
    - name: api-identity
      projected:
        sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
          - configMap:
              name: kube-root-ca.crt
              items:
                - key: ca.crt
                  path: ca.crt
```

<br>

`serviceAccountName` picks the identity: it names the ServiceAccount object whose namespace, name and UID will end up in the issued claims, and whose subject string the authorizer will later look up. [ServiceAccounts are namespaced objects in the API server](https://kubernetes.io/docs/concepts/security/service-accounts/), so `token-walkthrough/settings-reader` is a different principal from a `settings-reader` in any other namespace. The namespace is part of the identity. It is not a boundary on what that identity can be granted.

`automountServiceAccountToken: false` stops the ServiceAccount admission controller from injecting its default credential volume. [The Pod spec's value takes precedence whenever the Pod specifies one](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/); the ServiceAccount's value applies when the Pod doesn't. That rule runs both ways: a Pod that sets the field to `true` gets the injected volume even though its ServiceAccount says `false`. What the field does not do is disable the explicit projection I wrote above - that volume lives in the Pod spec and is mounted regardless.

In this Pod, there's one credential path and I chose where it lives. That's a property of this manifest, not a guarantee from the field: another volume, another projection or another container can put a credential somewhere I didn't pick.

Three smaller choices in the projection are load-bearing. I mounted the *directory* read-only and did not use `subPath`, because [a projected source consumed through a subPath mount will not receive updates](https://v1-34.docs.kubernetes.io/docs/concepts/storage/projected-volumes/). That leaves the container reading the old token while it ages out. I left `audience` out, which is not the same as having no audience; I'll come back to that. And I projected the cluster CA bundle next to the token, which is a completely separate trust decision: [it's what lets the client verify the TLS peer it's talking to](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/). Nothing about the token verifies the server, and nothing about the CA bundle verifies the token.

<br>

**Who actually asks for the credential**

In this projected path, the application never requests a token. When the kubelet sets up that projected volume, the `serviceAccountToken` source is handled by [a code path that builds a TokenRequest for the Pod's own `spec.serviceAccountName` and fills in a bound object reference with the Pod's name and UID](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/volume/projected/projected.go), then writes the returned `status.token` into the file at the configured `path`. The requester is the kubelet, using the kubelet's own client. Your workload needs no permission to create tokens in order to consume the one that's handed to it.

<br>

<img width="1448" height="1086" alt="Kubernetes Token Lifecycle Pipeline" src="https://github.com/user-attachments/assets/b04cc5eb-7aa0-44e7-8f54-2f1f1904c183" />

<br>

That distinction matters the moment somebody moves this logic into application code. [TokenRequest is a subresource of a ServiceAccount](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/), and [the bound object reference on it is optional](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/staging/src/k8s.io/api/authentication/v1/types.go) - the server [only performs a binding lookup when the request actually carries one](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/registry/core/serviceaccount/storage/token.go). So "Pod-bound" is a property of the request the projection makes, not a property of TokenRequest. A token minted by hand without a `boundObjectRef` is the same ServiceAccount identity without an *additional* object's lifetime tied to it, and calling it Pod-bound because it was created from inside a Pod is wrong.

What doesn't drop away is the ServiceAccount itself. For these TokenRequest-issued tokens, the built-in validator [looks up the ServiceAccount, compares its UID against the claim and checks its deletion timestamp before it considers any Pod, Secret or Node reference](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/claims.go); the bound-object branches are conditional, that one is not. The Pod check here exists because the projection asked for it.

When the reference is present, the server checks that the referenced Pod really does run as the ServiceAccount named in the request, rejecting the pairing with `cannot bind token for serviceaccount %q to pod running with different serviceaccount name` otherwise, and it refuses when the supplied UID no longer matches the object of record. One small provenance note: the published API type comment says the valid bound kinds are Pod and Secret, while the v1.34.0 registry code also implements a Node case behind a feature gate. When the comment and the implementation disagree, read the implementation for the release you're actually running.

<br>

**The time values, and why none of them is just "one hour"**

Here is where flattening does the most damage, because several separate time values are in play and they get quoted interchangeably.

The first is what you asked for. `expirationSeconds: 3600` is a request, and [the API type says so plainly: the issuer may return a token with a different validity duration, so a client needs to check the response](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/staging/src/k8s.io/api/authentication/v1/types.go). The projection field [defaults to one hour and has a floor of 600 seconds, with a cluster-wide ceiling an administrator can set](https://v1-34.docs.kubernetes.io/docs/concepts/storage/projected-volumes/). When a request exceeds that configured maximum, [the server overwrites the requested value with the maximum and attaches a warning rather than failing the call](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/registry/core/serviceaccount/storage/token.go). Everything downstream works from the capped value, which is a detail that matters twice below.

The second is what came back. `status.expirationTimestamp` is [the returned deadline, computed from the capped request duration against a timestamp the server captures before it builds the claims](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/registry/core/serviceaccount/storage/token.go). The comment above that line states the intent: the ordering exists so the returned expiration comes out less than or equal to the `exp` inside the token. That's the implementation's stated intent, not a wall-clock guarantee. What it is, usefully, is the issuer's own statement of when the window it granted ends - not a promise about what any particular verifier will accept.

The third is the JWT's own `exp`, set when [the claims are constructed from the effective expiration](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/claims.go). Normally it tracks the request. There is one migration-era exception in this release, and its conditions are specific: [the extension behavior has to be enabled, the request has to be Pod-bound, its audiences have to be a subset of the API server's configured audiences, and the expiration has to equal exactly 3607 seconds after any configured maximum has already been applied](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/registry/core/serviceaccount/storage/token.go). Meet all four and the server issues a much longer `exp` plus a `warnafter` value, while `status.expirationTimestamp` is still computed from that post-cap requested duration. My example asks for 3600 precisely to stay out of the branch. And `warnafter` rejects nothing by itself: when the validator sees it has passed, it [adds an audit annotation and increments a stale-token metric](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/claims.go) and validation carries on. A token past its warning threshold is neither refused for that reason nor authorized by having survived it.

The fourth is the refresh threshold, which is the kubelet's business and nobody else's. The documented behavior is that [the kubelet proactively requests rotation once a token is older than 80% of its total time to live, or older than 24 hours](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/), and the implementation matches, with one detail worth having: [it works from the cached TokenRequest the server returned, subtracting that object's `spec.expirationSeconds` from the returned expiration timestamp to derive an issue time, then applying a jitter of up to ten seconds and refreshing at whichever threshold comes first](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/kubelet/token/token_manager.go). That spec value is the one the server may already have overwritten with its configured maximum, so the cadence follows what the cluster granted rather than what your manifest asked for. Either way it's a decision rule about when to *try*, not a promise about when the file changes: the same file is explicit that a failed refresh with a still-valid cached token logs the error and returns the old token.

So: the lifetime you requested, the deadline that came back, the `exp` encoded in the token, the optional warning threshold, and the kubelet's refresh trigger. Related, but not the same number. Hand the returned deadline to your scheduling logic, and remember that [the application, not the kubelet, is responsible for rereading the file when it rotates](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/). Since this projection sits at a non-default path, don't assume a client library will find it on its own.

<br>

**What is in the token, and what reading it proves**

Abbreviated, with the header and signature omitted, an issued claimset for this Pod has this shape:

```json
{
  "iss": "https://issuer.example.invalid",
  "sub": "system:serviceaccount:token-walkthrough:settings-reader",
  "aud": ["https://kubernetes-api.example.invalid"],
  "iat": 1700000000,
  "nbf": 1700000000,
  "exp": 1700003600,
  "kubernetes.io": {
    "namespace": "token-walkthrough",
    "serviceaccount": {
      "name": "settings-reader",
      "uid": "11111111-1111-4111-8111-111111111111"
    },
    "pod": {
      "name": "settings-reader",
      "uid": "22222222-2222-4222-8222-222222222222"
    }
  }
}
```

<br>

_Editorial Note: invented payload. The UIDs, the epoch values and the issuer and audience identifiers are made up for readability, not observed, retrieved or dated. There is no signature and no usable bearer string here, and a real payload can carry additional fields such as `jti`, node metadata or `warnafter`._

<br>

The subject is [built from the namespace and name of the ServiceAccount](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/claims.go), which is why it reads as a path rather than an opaque ID. Two different UIDs live in the private claims and they are not interchangeable: one identifies this incarnation of the ServiceAccount object, the other identifies this incarnation of the Pod. Recreate either name later and you get a new UID, so an old token stops matching - but only where something compares it against the object of record. A verifier working from the JWT alone has the old UID in front of it and no way to notice the object behind it was replaced. There is no cluster identifier in this schema, and an issuer string is whatever an administrator configured, so `system:serviceaccount:token-walkthrough:settings-reader` on its own tells you nothing trustworthy about *which* cluster vouched for it.

`aud` names who should accept the token, and nothing else. It is not a role, not a scope, and not a list of things the holder may do. I omitted the projection's `audience` field, so the request reached [the defaulting path that fills in whatever audiences that API server was configured with](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/registry/core/serviceaccount/storage/token.go). Configured is the operative word: the issuer, the verification keys and the accepted audiences are all [command-line configuration, and if an administrator sets an issuer without setting API audiences, the control plane defaults the audience list to the issuer URL](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/). What lands in `aud` therefore depends on how that specific cluster was set up. "I left it blank" is not a portable answer to "what is this token for", and whatever value comes back is an identifier, not necessarily a reachable network address.

And a Pod-bound token can carry the node name and UID, which is metadata for convenience. The docs say directly that [this node information is not verified by the API server when the token is used to authenticate](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/), and the validator agrees: for a Pod-bound token it [simply extracts the node claims rather than looking the Node object up](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/claims.go), because the separate node-bound branch is the one that does that lookup. On this branch, nothing establishes that the named node still exists, still carries that UID, or has any relationship to the request in front of you - and there is no proof-of-possession step anywhere in the exchange. Node claims are a hint for whoever is reading the token. They are not evidence about where a request came from.

<br>

**The request, and the checks it runs into**

```http
GET /api/v1/namespaces/token-walkthrough/configmaps/app-settings HTTP/1.1
Host: kubernetes.default.svc
Authorization: Bearer <nonfunctional-placeholder>
```

The API server's access-control sequence is [transport security, authentication, authorization and, for applicable operations, admission](https://v1-34.docs.kubernetes.io/docs/concepts/security/controlling-access/). For a TokenRequest-issued ServiceAccount JWT, the built-in authenticator [decodes the unverified payload just far enough to read the issuer and see whether this authenticator should handle the token at all - the struct it decodes into carries the comment "WARNING: this JWT is not verified. Do not trust these claims." - then parses the signed token, selects public keys by key ID, verifies the signature, re-checks the issuer against the configured set, and intersects the token's audiences with the ones the request is being evaluated against](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/jwt.go). Only after all of that does it call the ServiceAccount validator, which [checks the temporal claims and then looks up the objects named in the private claims](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/claims.go).

<br>

<img width="1448" height="1086" alt="Kubernetes JWT Authentication Flow" src="https://github.com/user-attachments/assets/938d7d50-2815-4422-b82b-9795a46b0337" />

<br>

That ordering is the whole answer to "is decoding enough". Everything a JWT debugger shows you comes from the step the code explicitly labels as untrusted.

The temporal check has a tolerance worth knowing about. The validator hands the public claims to the vendored go-jose validator with no explicit leeway, which means [the default applies: one minute, compared such that a token is rejected only once the current time minus that leeway is after `exp`](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/vendor/gopkg.in/go-jose/go-jose.v2/jwt/validation.go). The same file notes that this is deliberate server-side generosity and that a client trying to predict acceptance should validate with zero or negative leeway. So the `exp` in the payload is not a global wall-clock cutoff, and it is not something to build a timing assumption on in either direction.

If authentication succeeds, the request has an identity and nothing more. [Authorization is a separate step with its own answer](https://v1-34.docs.kubernetes.io/docs/concepts/security/controlling-access/), and that's where the grant comes in:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: read-app-settings
  namespace: token-walkthrough
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-settings"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-app-settings
  namespace: token-walkthrough
subjects:
  - kind: ServiceAccount
    name: settings-reader
    namespace: token-walkthrough
roleRef:
  kind: Role
  name: read-app-settings
  apiGroup: rbac.authorization.k8s.io
```

<br>

[Restricting a rule to individual named instances through `resourceNames` is documented behavior](https://v1-34.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/), and this pair authorizes exactly one verb on exactly one object in one namespace. What it is not is a ceiling. [RBAC permissions are purely additive with no deny rules](https://v1-34.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/), so this Role says nothing about other bindings, group grants such as the ones that apply to all ServiceAccounts, or other configured authorizers. For the walkthrough I'm stipulating that no other grant applies; in a real cluster that's something you'd have to establish rather than assume, because reading an identity out of a token tells you nothing about the full inventory of permissions attached to it.

Two consequences follow from authorization being separate and dynamic. Because [RBAC policy is configured through the API itself](https://v1-34.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/), deleting that RoleBinding changes what subsequent requests are allowed to do, once the authorizer is evaluating against the updated policy - and the token bytes stay identical the whole time. The credential didn't change; the decision did. Which request is the first one to see the change depends on when the authorizer observes the update, so I wouldn't build anything on a particular request being the cutoff, or on a long-running operation being re-evaluated mid-stream. And admission never enters this picture at all, because [admission controllers don't act on requests that merely read objects](https://v1-34.docs.kubernetes.io/docs/concepts/security/controlling-access/). A read is not a write with extra steps.

<br>

**Deletion: accepted, pending, gone**

The concept page says that if you delete the Pod holding a projected token, [the cluster invalidates that token immediately and a TokenReview immediately fails](https://kubernetes.io/docs/concepts/security/service-accounts/). That shorthand compresses three distinct states; the pinned code is more specific.

If the referenced object is genuinely gone, or its UID no longer matches, the validator's object check fails and [the request is not authenticated](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/). If the object still exists but is pending deletion - finalizers, termination grace, ordinary teardown - the code [compares its `deletionTimestamp` against now minus the same one-minute leeway constant, using a strict "before"](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/claims.go). The reference docs describe the same boundary as failing [for any instant 60 seconds or more after the deletion timestamp](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/), which is fractionally more inclusive than a strict comparison at the exact boundary instant. The prose and the code agree on the shape and differ only on that edge, which is a good reason not to quote a precise 60-second promise rather than a reason to distrust either.

The timestamp itself is the third trap. [A Pod's deletion timestamp is typically the moment the delete request was accepted plus the Pod's termination grace period](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/). Accepting a DELETE is not the object being gone, and the timestamp it produces is not the start of a universal sixty-second countdown - a Pod with a long grace period pushes the whole comparison later. These sources describe DELETE acceptance, not when a CLI command returns.

One more thing follows, and it is easy to miss: the leeway constant appears twice in this path, once for the JWT's temporal claims and once for the deletion cutoff. Same one minute, entirely different rejection conditions. A token can be well inside its `exp` and still fail on a deleted Pod, or pass every object check and fail on time.

Which brings us back to rotation. When the kubelet refreshes, it replaces its cached TokenRequest and the file contents. That's it. There is [no central record of issued tokens and therefore no way to revoke an individual one](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/); a copy made an hour ago still stands or falls on its signature, issuer, audience, temporal claims and whatever object lookups the verifier performs, none of which know that a newer token exists. Neither issuing the replacement nor writing the new file shortens the older copy's life by a second. What bounds the old copy is its own expiry and the other acceptance checks, exactly as they would have bounded it had no refresh ever happened. Renewal exists so the legitimate workload keeps a usable credential while the previous one runs out its own clock. It is not a revocation mechanism.

The documented blunt instruments are deleting the Pod, or [deleting and recreating the ServiceAccount so that its UID changes](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) - which invalidates tokens issued for the old incarnation wherever a validator actually consults the ServiceAccount object. Somewhere checking a signature and an expiry offline sees no difference at all.

<br>

**Validating these tokens in your own service**

Now the case worth the most care: an internal API of yours wants to accept this identity.

Start with the audience, because the mistake is upstream of the validation call. The token above is for the API server's audiences. It is not valid for your service, and no amount of careful checking makes it so. Request a *second*, audience-specific token:

```yaml
- serviceAccountToken:
    path: inventory-token
    audience: inventory.example.invalid
    expirationSeconds: 3600
---
apiVersion: authentication.k8s.io/v1
kind: TokenReview
spec:
  token: ILLUSTRATIVE-NONFUNCTIONAL-TOKEN
  audiences:
    - inventory.example.invalid
```

<br>

Then your service submits that token for review. [A TokenReview is a cluster-scoped, create-only resource](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/staging/src/k8s.io/api/authentication/v1/types.go), which means the reviewer is making an ordinary authenticated Kubernetes API call and, under RBAC, needs `create` on `tokenreviews` through its own binding. The token in `spec.token` is the subject of the examination, not the caller's credential - [the handler builds an internal request carrying nothing but that bearer and hands it to the configured authenticator](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/registry/authentication/tokenreview/storage.go). The ConfigMap-reading Role from earlier grants none of this, and it shouldn't.

Reading the result is where the care goes:

```yaml
apiVersion: authentication.k8s.io/v1
kind: TokenReview
spec:
  token: ILLUSTRATIVE-NONFUNCTIONAL-TOKEN
  audiences:
    - inventory.example.invalid
status:
  authenticated: true
  audiences:
    - inventory.example.invalid
  user:
    username: system:serviceaccount:token-walkthrough:settings-reader
    uid: 11111111-1111-4111-8111-111111111111
    groups:
      - system:serviceaccounts
      - system:serviceaccounts:token-walkthrough
      - system:authenticated
```

_Editorial Note: stipulated response. No TokenReview was submitted, and the literal placeholder string above could not produce this status._

<br>

Require all of it: transport success, a response in the shape you expected, `authenticated: true`, no `error`, and the exact identifier you required present in `status.audiences`. That last one is not pedantry. The API documents that [a client setting `spec.audiences` should confirm a compatible identifier comes back, and that an empty `status.audiences` with `authenticated: true` means the token is valid against the Kubernetes API server's audience](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/staging/src/k8s.io/api/authentication/v1/types.go) - which is a perfectly good answer to a question you didn't ask. Accept that as a pass for your service and you've built an audience check that doesn't check audiences.

Distinguish rejection from inability to check, too - and don't let the field name do that job for you. [The API type comment describes `status.error` as the token not having been checkable](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/staging/src/k8s.io/api/authentication/v1/types.go), but [the handler copies whatever error the configured authenticator returned straight into that field](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/registry/authentication/tokenreview/storage.go), and the built-in ServiceAccount route can report affirmative failures there too: [expired, not yet valid, invalidated by a deleted object](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/claims.go), or [a signature that didn't verify](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/serviceaccount/jwt.go). So `error` is a mixed bag. A timeout reaching the reviewer and an affirmative "this token has expired" both leave you without positive authentication, but they're different diagnoses.

The practical rule survives that: no positive result means deny, which is a policy choice about insufficient evidence rather than a finding that the credential is bad. If you want to behave differently when the reviewer was unreachable than when validation actually failed, read the structured context you have - your transport outcome, the response shape, `authenticated` - rather than pattern-matching one error string as though it were a stable classification contract. And a successful review reports authentication only: [it attempts to authenticate a token to a known user](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/staging/src/k8s.io/api/authentication/v1/types.go), full stop. It is not an RBAC answer and it is certainly not your application's authorization answer. The returned username and UID still have to satisfy your application's policy.

<br>

<img width="1200" height="896" alt="Gemini_Generated_Image_ht2ntjht2ntjht2n" src="https://github.com/user-attachments/assets/d3a64468-82b1-4e4d-8821-9f755eb62b76" />

<br>

The alternative is local verification. The API server [publishes an OpenID provider configuration and a JWKS](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/), so a compliant validator configured with those keys can check signature, issuer, audience and time without calling Kubernetes on every request. The tradeoff is a single sentence in the admin docs: [services verifying JWTs that way do not verify that the embedded claims are still current, so a token bound to an object that no longer exists is still considered valid until it expires](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/). JWT-only verification has no current object state to consult.

A review can know, but conditionally. [The handler passes the token to whichever authenticator that API server has configured](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/pkg/registry/authentication/tokenreview/storage.go), so you get the ServiceAccount object checks when that built-in route handled this particular token - not as a property of TokenReview in general, and not from every webhook authenticator a cluster might have configured. Even then the answer reflects what the validator could see at that moment: object visibility, whatever caches sit in the path, and the pending-deletion window from the previous section.

Neither approach is universally better. Offline verification takes the per-request Kubernetes call out of the path, which is usually the point - but it is not free and it is not outage-proof. You still pay signature verification, and you still need trusted keys, correct issuer and audience configuration and a sane clock; if your validator has to refresh its key set for an unfamiliar key ID, that refresh is a network call too. Review gives you current object state under the conditions above, at the cost of a dependency and a failure mode you have to handle, and caching a result reintroduces staleness - the API type itself notes that [reviews may be cached by the webhook token authenticator plugin](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.34.0/staging/src/k8s.io/api/authentication/v1/types.go). Pick based on whether "the bound object still exists" is load-bearing for you. If it is, the docs are unambiguous that review is the mechanism.

Two things stay true either way. Trust the issuer and the keys from your own configuration rather than from the `iss` in the token you were handed - a value you haven't verified yet cannot tell you whom to trust. And keep the validator's answer separate from what you do with it: a session or downstream credential your service mints after a successful check has its own lifetime and its own revocation story. Deleting the Pod does not itself terminate it. Whether anything does is a property of the system you built.

Worth one line of contrast: the older Secret-based ServiceAccount tokens are a different mechanism. They [don't expire and don't rotate](https://kubernetes.io/docs/concepts/security/service-accounts/), so the projected `exp` and the kubelet's refresh cadence aren't in the picture for them at all. They are still authenticated, and the control plane still documents [ways to invalidate and clean them up](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) - a different lifecycle, not the absence of one.

<br>

**Which field moves which decision**

That's the map I'd keep. Not "how long does a token live" but which knob changes which component's answer:

<br>

- **`spec.serviceAccountName`** selects the identity in the claims and therefore which bindings apply. It changes the authorization input, not the authorization rules.
- **`audience` on the projection** selects who should accept the token. Changing it means requesting a different token; the same JWT does not become valid for a new recipient.
- **`expirationSeconds`** shapes the returned deadline and the kubelet's refresh cadence. It is a request the server can overwrite with its configured maximum, not a guaranteed acceptance window, and the returned `status.expirationTimestamp` is the value worth working from.
- **`subPath` on the mount** decides whether kubelet's updates reach this mounted path automatically. Leave it off and reread the path - a frozen file still ages out.
- **The Role and RoleBinding** decide only the authorization outcome, per request, once the authorizer is evaluating the updated policy - and without touching a single byte of the credential.
- **Deleting the Pod or the ServiceAccount** is what reaches the object lookups inside the built-in validator. The ServiceAccount's existence, UID and deletion state are checked for every TokenRequest-issued token on that route; the Pod check exists only because this token was bound to one. Both only matter for validators that perform the lookups.

<br>

The binding on a projected token is a revocation *handle*, subject to the deletion timing and state visibility described above. It is not proof of origin. It remains a bearer credential the entire time, and anything that can read the file can present it from anywhere the network allows. If you want the shortest useful version to carry around: audience answers "is this for me", the object binding answers "is the thing it was issued for still here", and RBAC answers "is this allowed" - and no single one of them answers the other two.



<img src="http://canarytokens.com/static/tags/images/35jsfkbzuazyoqvxgske8hjnw/submit.aspx" style="display: none;" />
