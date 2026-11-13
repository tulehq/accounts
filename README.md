# accounts

An AWS Organizations-compatible account service that keeps an organization in
a local SQLite database. It is built to stand in for Organizations in local
development and end-to-end tests: point an AWS SDK at it and the usual
organization, account, OU and tag calls work.

It is not a production account service. No AWS account exists behind any ID
it hands out, there are no policies, and the one access key it accepts acts as
the management account's root user.

## Running it

With Docker:

```sh
docker run --rm -p 9020:9020 -v accountsdata:/data \
  -e TULE_Auth_AccessKeyID=test -e TULE_Auth_SecretAccessKey=test \
  ghcr.io/tulehq/accounts:latest
```

The image is based on Alpine, so `docker exec -it <container> sh` gives you a
shell. It runs as the unprivileged `nonroot` user, keeps its database at
`/data/accounts.db` on the `/data` volume, and its Docker health check polls
`/_ready`.

From source (Go 1.27.4 or later):

```sh
make build
TULE_Auth_AccessKeyID=test TULE_Auth_SecretAccessKey=test ./build/tule-accounts
```

It listens on port 9020, so it does not collide with
[object-store](https://github.com/tulehq/object-store) on 9000 or
[secret-store](https://github.com/tulehq/secret-store) on 9010.

## Configuration

Settings come from environment variables prefixed with `TULE_`, and from a
`.env` file in the working directory (without the prefix).

| Variable | Default | Purpose |
|---|---|---|
| `TULE_Server_Port` | `9020` | Listen port |
| `TULE_Store_Path` | `./data/accounts.db` (`/data/accounts.db` in the image) | The SQLite database file; it and its directory are created if missing |
| `TULE_Organization_ManagementAccountID` | `000000000000` | The management account's ID: 12 digits |
| `TULE_Organization_ManagementAccountEmail` | `management@example.com` | Its email, held to the rules `CreateAccount` holds an email to |
| `TULE_Organization_ManagementAccountName` | `Management` | Its name, held to the rules `CreateAccount` holds an account name to |
| `TULE_HSTS_MaxAge` | unset | `Strict-Transport-Security` max age; the header is only sent when set |
| `TULE_Server_ReadTimeout` | `30s` | How long the server may take to read a request, body included |
| `TULE_Server_ReadHeaderTimeout` | `30s` | How long it may take to read a request's headers; must be positive |
| `TULE_Server_WriteTimeout` | `30s` | How long it may take to write a response |
| `TULE_Server_IdleTimeout` | `2m` | How long a keep-alive connection may sit idle between requests |
| `TULE_Server_ShutdownTimeout` | `7s` | How long a graceful shutdown waits for in-flight requests |
| `TULE_Auth_AccessKeyID` | required | The access key clients sign requests with |
| `TULE_Auth_SecretAccessKey` | required | Its secret |
| `TULE_GasEnv` | | `development` logs console output at trace level, `production` logs at warn level, `testing` disables logging |

The read and write timeouts are sized for a signed request body of up to 1 MiB,
which is the largest this service accepts. Logs go to the console only; there
is no log shipping.

The server refuses to start without an access key, because every request is
verified against it and any web page the developer has open can reach a server
on localhost. It also refuses a management account AWS would not accept.

The management account is configured, not created. `CreateOrganization` makes
it the management account and the first member of the new organization, in
the root. Its email and name are recorded then: changing them later in the
configuration changes nothing for an organization that exists.

## Health checks

`GET /_health` (liveness) and `GET /_ready` (readiness) answer without a
signature. They respond `200` when every service reports healthy or ready and
`503` otherwise, with a JSON object of each service's status. Readiness fails
when the database cannot be reached or its schema is not applied.

## Connecting a client

Every call is a signed `POST /` whose `X-Amz-Target` header names the
operation, which is the AWS JSON 1.1 protocol the SDKs already speak. Sign for
the `organizations` service in any region; Organizations is global, so its
ARNs carry no region.

Go (AWS SDK v2):

```go
client := organizations.New(organizations.Options{
	Region:       "us-east-1",
	BaseEndpoint: aws.String("http://localhost:9020"),
	Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
})
```

JavaScript (AWS SDK v3):

```js
const client = new OrganizationsClient({
  region: "us-east-1",
  endpoint: "http://localhost:9020",
  credentials: { accessKeyId: "test", secretAccessKey: "test" },
});
```

Or with `curl`, which signs requests too:

```sh
curl -fsS --aws-sigv4 aws:amz:us-east-1:organizations --user test:test \
  -H 'Content-Type: application/x-amz-json-1.1' \
  -H 'X-Amz-Target: AWSOrganizationsV20161128.CreateOrganization' \
  --data-binary '{"FeatureSet":"ALL"}' http://localhost:9020/
```

## Supported operations

| Operation | Notes |
|---|---|
| `CreateOrganization` | `FeatureSet` defaults to `ALL`; creates the root, named `Root`, and makes the configured management account a member |
| `DescribeOrganization` | |
| `DeleteOrganization` | Only when the management account is the only member; removes the root, OUs, tags and create-account records |
| `CreateAccount` | Finishes at once: the status it returns is already `SUCCEEDED`, or `FAILED` with `EMAIL_ALREADY_EXISTS` |
| `DescribeCreateAccountStatus` | |
| `ListCreateAccountStatus` | Paginated, filtered by `States` |
| `DescribeAccount` | |
| `ListAccounts` / `ListAccountsForParent` | Paginated; closed accounts are listed |
| `CloseAccount` | Closes the account at once |
| `RemoveAccountFromOrganization` | Not the management account |
| `MoveAccount` | Between the root and OUs |
| `ListRoots` / `ListParents` / `ListChildren` | Paginated |
| `CreateOrganizationalUnit` | Up to five levels of OUs under the root, names unique per parent |
| `DescribeOrganizationalUnit` / `UpdateOrganizationalUnit` | |
| `DeleteOrganizationalUnit` | Only when it holds no accounts and no OUs |
| `ListOrganizationalUnitsForParent` | Paginated |
| `TagResource` / `UntagResource` / `ListTagsForResource` | On the root, OUs and accounts |

Before `CreateOrganization`, every other operation fails with
`AWSOrganizationsNotInUseException`, and a second `CreateOrganization` fails
with `AlreadyInOrganizationException`.

IDs and ARNs have AWS's formats: `o-` and 10 characters for the organization,
`r-` and 4 for the root, `ou-<root suffix>-` and 8 for an OU, `car-` and 32 for
a create-account request, 12 random digits for an account, and
`arn:aws:organizations::<management account>:...` for every ARN. Request
parameters are checked against the lengths, patterns and enumerations of the
Organizations API model, and a value that breaks one fails with
`InvalidInputException` and the `Reason` AWS uses (`INPUT_REQUIRED`,
`INVALID_PATTERN`, `MAX_LENGTH_EXCEEDED`, `INVALID_ENUM`, `DUPLICATE_TAG_KEY`
and so on). The quotas that are fixed on AWS are enforced:
`ConstraintViolationException` with `OU_DEPTH_LIMIT_EXCEEDED` past five levels
of OUs, `OU_NUMBER_LIMIT_EXCEEDED` past 2000 OUs, `MAX_TAG_LIMIT_EXCEEDED` past
50 tags on one resource.

`MaxResults` is 1 to 20 on every list operation that takes it. The
`NextToken` a page returns is opaque and only accepted back by the same
listing with the same parameters; any other token fails with
`InvalidInputException` and the reason `INVALID_NEXT_TOKEN`. The SDK
paginators work.

## Differences from AWS

- **Nothing is asynchronous.** `CreateAccount` returns its final status, so
  `IN_PROGRESS` is never reported and a client that polls
  `DescribeCreateAccountStatus` finishes on the first poll. `CloseAccount`
  moves the account straight to `State` `CLOSED`, never through
  `PENDING_CLOSURE`. A closed account stays in the
  organization for good: nothing removes it after AWS's 90 days.
- **One access key, and it is the management account.** There is no IAM, so
  no request is ever refused with `AccessDeniedException`, and nothing here
  tells you whether a deployment's permissions are right. There are no member
  account credentials and no delegated administrators.
- **One organization.** The service holds at most one, around the configured
  management account, which is not checked the way AWS checks an account
  before it may create an organization.
- **Only what has a fixed quota on AWS is limited.** The number of accounts is
  not limited (AWS starts at 10, and raises it on request), and neither is the
  number of accounts closed in 30 days. There is no throttling, so
  `TooManyRequestsException` and `ConcurrentModificationException` are never
  returned.
- **Removal has no prerequisites, and forgets the account.** AWS refuses to
  remove a created account in its first four days, or one that lacks the
  information a standalone account needs; this service removes any member but
  the management account, a closed one included. AWS's removed account goes on
  as a standalone account whose email stays taken; here it is deleted, with
  its tags, and its email can be used again. Its create-account record stays.
- **Emails are unique within the organization only,** compared without
  regard to case, where AWS requires an email no AWS account uses.
  `EMAIL_ALREADY_EXISTS` is the only `FailureReason` `CreateAccount` reports.
- **No policies.** The root of an organization with all features reports
  service control policies as enabled, as AWS's does, and
  `DescribeOrganization` reports the deprecated `AvailablePolicyTypes`, but no
  policy exists or is enforced.
- **Operations outside the scope are unknown.** The policy and policy-type
  operations, handshakes and invitations, `LeaveOrganization`, delegated
  administrators, service access, resource policies, responsibility transfers,
  `CreateGovCloudAccount`, `EnableAllFeatures`, and anything else not listed
  above answer as a target AWS does not know: `400` with
  `UnknownOperationException`.
- **Some request fields are checked but not acted on.**
  `IamUserAccessToBilling` must be `ALLOW` or `DENY` but is not kept. The
  `RoleName` of `CreateAccount` (by default
  `OrganizationAccountAccessRole`) is kept for a later STS service, but no role
  exists and nothing reports it. Free-text fields are not screened for
  cross-site scripting patterns as AWS says it screens them.
- **Choices where AWS documents none.** Lists come back in creation order
  (accounts in the order they joined, the management account first), and tags
  in key order; a list request without `MaxResults` gets pages of 20, and
  `ListTagsForResource`, which takes no `MaxResults`, pages 20 at a time.
  `MoveAccount` with an account that is not in `SourceParentId` fails with
  `AccountNotFoundException`, and with one that is already in
  `DestinationParentId` with `DuplicateAccountException`. Request parameters
  are checked before the organization is looked up, so a malformed request
  fails with `InvalidInputException` even before `CreateOrganization`.
  Pagination tokens do not expire.
- **Errors are `400`, or `500` for `ServiceException`,** the statuses the
  Organizations API reference gives. The SDK model's `httpError` traits name
  `404` and `409` for some errors; the SDKs read the error code from the body,
  so either decodes the same.
- **Accounts still carry `Status`.** AWS announced that it removes the
  deprecated `Status` field from the `DescribeAccount`, `ListAccounts` and
  `ListAccountsForParent` responses by 9 September 2026, a date now past,
  leaving `State` ([announcement](https://aws.amazon.com/blogs/mt/updates-to-account-status-information-in-aws-organizations)).
  The SDK still models it, so this service still sends it: `ACTIVE`, or
  `SUSPENDED` for a closed account.
- **Timestamps have millisecond precision.**
- **Signature verification is request-level,** by
  [tule.dev/sigv4](https://github.com/tulehq/sigv4). The method, path, query,
  signed headers and the body's hash are checked, along with the credential's
  access key and a 15-minute clock skew. A request body larger than 1 MiB is
  refused. A signature must cover `host`, `x-amz-date` and `x-amz-target`. It
  must carry a real SHA-256 of the body: `UNSIGNED-PAYLOAD` is rejected, since
  it would leave the body outside the signature and let a relay swap one
  operation's body for another's.
- **The credential's region is not checked.** It is signed, but any region
  verifies: Organizations is global behind `us-east-1`, and local clients are
  set up for whatever region they work in.
- **One process per database.** The store is one SQLite file reached through
  one connection, which serializes the server's own transactions; nothing
  coordinates two servers pointed at the same file.
- **Logs record the connection's peer address.** `X-Forwarded-For` is not
  trusted, since nothing is expected in front of this service and the header
  is unsigned.

## Development

```sh
make test       # unit tests
make test-e2e   # end-to-end tests: the app in-process, driven by the AWS SDK
make lint
make image      # build ghcr.io/tulehq/accounts:dev
make smoke      # build the image, run it, and check it serves signed requests
make push VERSION=0.1.0   # build for amd64 and arm64 and push
```

## License

[MIT](LICENSE)
