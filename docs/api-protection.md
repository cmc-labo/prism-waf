# API protection

PrismWAF understands the three common kinds of APIs and protects each
with what it knows about it:

| API | Protection | Enabled by |
|-----|------------|------------|
| [REST](#rest-openapi) | Requests must match the API's OpenAPI document: known operations only, valid parameters and bodies, credentials present (a positive security model) | `-openapi` |
| [GraphQL](#graphql) | Queries are parsed: limits on depth, fields, aliases and batches; introspection blocked; optional schema validation; every argument inspected on its own | `-graphql-path` |
| [gRPC](#grpc) | Calls are inspected message by message while they stream, over HTTP/2 with or without TLS, and as gRPC-Web; server reflection blocked; optional validation against the protobuf schema | Always on for gRPC calls; `-grpc-descriptor` for the schema |

```sh
prismwaf -backend http://127.0.0.1:3000 \
  -openapi /etc/prismwaf/openapi.yaml \
  -graphql-path /graphql -graphql-schema /etc/prismwaf/schema.graphql \
  -grpc-descriptor /etc/prismwaf/services.binpb
```

The built-in signatures and the [CRS](crs.md) still apply to every API
request: API protection adds checks, it does not replace them. Rejected
requests get `403 Forbidden` and an audit event with `reason` `api`, in a
form that the API's clients understand (a [GraphQL error](#responses), a
[gRPC status](#responses)).

- [Options](#options)
- [REST (OpenAPI)](#rest-openapi)
- [GraphQL](#graphql)
- [gRPC](#grpc)
- [Responses](#responses)
- [Audit events](#audit-events)
- [Order of processing](#order-of-processing)
- [Rolling out](#rolling-out)
- [Logs](#logs)
- [Performance](#performance)
- [Limitations](#limitations)

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-openapi` | (none) | OpenAPI 3.0 or 3.1 document (YAML or JSON). Requests under the paths of its servers that do not match it get `403` |
| `-graphql-path` | (none) | GraphQL endpoint, e.g. `/graphql`, or a prefix such as `/api/*`; repeatable |
| `-graphql-schema` | (none) | GraphQL schema (SDL); queries that are not valid for it get `403`. Repeatable, for a schema in several files |
| `-graphql-max-depth` | `15` | Maximum nesting of fields |
| `-graphql-max-aliases` | `20` | Maximum aliased fields per request |
| `-graphql-max-fields` | `1000` | Maximum fields per request, counting each use of a fragment |
| `-graphql-max-batch` | `10` | Maximum operations in a batched request |
| `-graphql-introspection` | `false` | Allow introspection queries (`__schema`, `__type`) |
| `-grpc-descriptor` | (none) | Protobuf descriptor set of the gRPC services; calls of other methods and messages that do not match get `PermissionDenied`. Repeatable |
| `-grpc-reflection` | `false` | Allow the gRPC server reflection service |

The `-graphql-*` options require `-graphql-path`. All files are read at
startup; restart PrismWAF to load new versions.

## REST (OpenAPI)

With `-openapi`, PrismWAF checks each request against the API's OpenAPI
document, which most frameworks generate (FastAPI, Spring, NestJS, ASP.NET
and others) or which the API was designed from:

| Check | Example of a rejected request | `violation` |
|-------|-------------------------------|-------------|
| The path has an operation | `GET /api/v1/admin/users`, scanners probing for endpoints | `unknown_path` |
| The method has an operation | `DELETE /api/v1/products/42` when only `GET` is described | `method_not_allowed` |
| Path, query, header and cookie parameters match their schemas | `GET /api/v1/products/abc` for an integer `id`; `?limit=100000` over `maximum: 100`; a value not in the `enum` | `parameter` |
| The body matches its schema and content type | A missing required property; a property that `additionalProperties: false` excludes (mass assignment, e.g. `"isAdmin": true`); a wrong type, a too long string, too many items | `body` |
| Credentials are present | No `Authorization: Bearer …` for an operation whose `security` requires it | `security` |

```sh
prismwaf -backend http://127.0.0.1:3000 -openapi openapi.yaml
```

**Which requests are checked.** Only requests under the base paths of the
document's `servers`: with `servers: [{url: https://shop.example.com/api/v1}]`,
requests to `/api/v1/…` are checked, and the web site at `/` and
`/about` is not. Server variables take their default values; the host
names are ignored. A document without `servers` covers all paths, which
suits a server that only serves the API.

Variants of a path that a backend may accept but that cannot match the
document, such as `/api/v1//admin`, `/static/../api/v1/admin` or
`/API/V1/admin`, are rejected as `unknown_path` rather than passed
unchecked.

**Credentials.** PrismWAF checks that a request has the credentials that
the operation's `security` requires: the header, query parameter or
cookie of an `apiKey`, an `Authorization` header with the scheme of
`http` security (`Bearer`, `Basic`, …), a bearer token for `oauth2` and
`openIdConnect`, a client certificate for `mutualTLS`. It cannot check that
the credentials are valid, which is the backend's job, but requests
without any never reach it.

**What real documents need.** PrismWAF was tested with the OpenAPI
documents of GitHub (3.0 and 3.1, 1281 operations) and Stripe (612
operations), and the OpenAPI examples:

- Examples and default values in the document are not checked, as they do
  not take part in validation and are often wrong.
- Paths that differ only in the names of their parameters, such as
  `GET /items/{id}` and `DELETE /items/{itemId}`, are accepted, although
  OpenAPI forbids them; the path with the request's method is used.
- A literal segment comes before a parameter: `/users/me` before
  `/users/{id}`.
- `HEAD` requests are checked against the `GET` operation if there is no
  `HEAD` operation. `OPTIONS` requests to a described path pass if there is
  no `OPTIONS` operation, since browsers send them before cross-origin
  requests (CORS preflight). A trailing slash is ignored.
- Parts of a document that the validator cannot check are not checked,
  instead of rejecting every request: parameters in the `deepObject` style
  with array values, form bodies with nested objects (both in Stripe's
  API), and bodies of types other than JSON, forms, multipart and text,
  such as XML. The other parameters are still checked.
- `$ref`s to other local files are resolved, relative to the document;
  `$ref`s to URLs are rejected.

Documents with structural errors, such as a path parameter that is not
declared, are rejected at startup with the error. Swagger 2.0 documents
are not supported; convert them to OpenAPI 3 first, e.g. with
[swagger2openapi](https://github.com/Mermade/oas-kit).

## GraphQL

With `-graphql-path`, PrismWAF parses the queries of requests to that
endpoint and rejects those that are expensive to execute or that explore
the API:

| Check | Attack | `violation` |
|-------|--------|-------------|
| `-graphql-max-depth` | Deeply nested queries that make the server resolve huge trees: `{ user { friends { friends { friends { … } } } } }` | `depth` |
| `-graphql-max-fields` | Queries with very many fields, also through fragments that are used many times ("fragment bombs", counted without expanding them) | `fields` |
| `-graphql-max-aliases` | Alias batching: one request that runs a field many times, e.g. `a: login(password: "1") b: login(password: "2") …` to guess passwords past rate limits | `aliases` |
| `-graphql-max-batch` | Batched requests (a JSON array) with many operations, for the same purpose | `batch` |
| Introspection | `__schema` and `__type` queries, which list the whole API to an attacker; allow them with `-graphql-introspection`, e.g. for development. `__typename` is always allowed | `introspection` |
| `-graphql-schema` | Queries that are not valid for the schema: unknown fields, missing or unknown arguments, wrong types | `schema` |
| Syntax | Queries that do not parse, fragments that spread themselves, requests that are not GraphQL requests | `invalid` |

Limits count per request: the fields and aliases of all operations of all
queries in a batch are added up. The parser also rejects queries nested
more than 1000 levels deep.

**Every argument on its own.** The string, enum and list arguments of
fields and directives, and the default values of variables, are inspected
by the signatures one by one, like the values of a JSON body. A payload at
the end of a value, such as `admin'--`, is then found although the query
continues after it. `match.field` names the argument, e.g. `user(name)`
or `products(filter.category)`. Variables are inspected as part of the
JSON body, e.g. `$.variables.email`.

**Request forms.** A `GET` with `query` in the URL; a `POST` with a JSON
body (a request or a batch), `application/graphql`, a form, or a
multipart request with file uploads (the `operations` field). A `POST`
with both is checked in full, as servers differ in which they use.
Requests without a query pass: a `GET` for a GraphQL IDE page, and
persisted queries (`extensions.persistedQuery`), whose text the server
already has.

**Schema.** `-graphql-schema` takes the schema in the GraphQL schema
definition language, as servers print it (e.g. `printSchema` in
graphql-js, `gqlgen` sources, `rover graph introspect`). Tested with
GitHub's public schema (1879 types).

```sh
prismwaf -backend http://127.0.0.1:4000 \
  -graphql-path /graphql -graphql-schema schema.graphql \
  -graphql-max-depth 10 -graphql-max-aliases 5
```

## gRPC

PrismWAF recognizes gRPC calls by their content type
(`application/grpc`, `application/grpc+proto`, `application/grpc+json`)
and gRPC-Web calls (`application/grpc-web`, `application/grpc-web-text`,
from browsers), and forwards them with what gRPC needs:

- **HTTP/2 on both sides.** PrismWAF accepts HTTP/2 with TLS and without
  (h2c, as gRPC clients use on internal networks), and sends gRPC calls to
  `http://` backends over h2c and to `https://` backends over HTTP/2.
  Other requests keep using HTTP/1.1 to `http://` backends, so one
  backend can serve both. gRPC-Web also works over HTTP/1.1.
- **Streaming.** The request stream is split into messages and inspected
  message by message while it is forwarded, and the responses stream back
  as they come. A message reaches the backend only once it has been
  inspected. Client-streaming and bidirectional calls work, including
  those where the client waits for an answer before it sends more.

Each message is inspected by the signatures, string by string:

- Without a schema, every length-delimited field may be a string, bytes
  or a nested message. Each is inspected as a string, and fields that
  decode as a nested message are inspected field by field too.
  `match.field` is the message index and the field numbers, e.g. `[0].2.1`
  for field 1 of the message in field 2 of the first message.
- With `-grpc-descriptor`, the messages are decoded with their types:
  `match.field` names the fields, e.g. `[0].filter.name` or `[2].tags[1]`,
  and messages that do not match the method's input type are rejected
  (`invalid_message`), e.g. a string where the type has a number, or
  invalid UTF-8 in a string field. Fields that the type does not have,
  e.g. from a newer client, are allowed and inspected as without a schema.
- Messages compressed with `gzip` or `deflate` are decompressed for
  inspection. Compressed messages in other encodings are rejected
  (`unsupported_encoding`), as they cannot be inspected.
- Messages in JSON (`application/grpc+json`) are inspected like JSON
  bodies.
- Metadata (headers) is inspected like HTTP headers, also by the CRS.

`-max-body` applies to each message, before and after decompression; a
stream can be longer. Larger messages are rejected with
`ResourceExhausted` and `reason` `body_too_large`.

**Methods.** The server reflection service
(`grpc.reflection.v1.ServerReflection`, `v1alpha`), which lists every
service and message of a server to tools such as `grpcurl`, is blocked
unless `-grpc-reflection` allows it. With `-grpc-descriptor`, calls of
methods that the descriptor set does not have are rejected
(`unknown_method`); the standard health service (`grpc.health.v1.Health`)
is always allowed for load balancers.

**Descriptor sets** are written by `protoc` or `buf` from the `.proto`
files of the services, with their imports:

```sh
protoc --include_imports --descriptor_set_out=services.binpb -I proto proto/shop/v1/*.proto
# or: buf build -o services.binpb
prismwaf -backend http://127.0.0.1:50051 -grpc-descriptor services.binpb
```

```sh
# A gRPC server behind PrismWAF, without TLS on both sides:
prismwaf -listen :8080 -backend http://127.0.0.1:50051
grpcurl -plaintext -proto shop/v1/search.proto -d '{"query":"shoes"}' 127.0.0.1:8080 shop.v1.Search/Find
```

`grpcurl` needs the `.proto` files (`-proto`), as reflection is blocked
unless `-grpc-reflection` allows it.

## Responses

A rejected request gets a response that its client can show:

| Request | Response |
|---------|----------|
| REST and other requests | `403 Forbidden` with the event ID as text, as for other blocked requests |
| GraphQL endpoint | The HTTP status (`403`, or `429`, `413` for rate limits and large bodies) with a GraphQL error: `{"errors":[{"message":"Forbidden; event ID: 4e1f0a9c2b7d3856","extensions":{"code":"FORBIDDEN","eventId":"4e1f0a9c2b7d3856"}}]}` |
| gRPC, gRPC-Web | HTTP `200` with `grpc-status` and `grpc-message` (`Forbidden; event ID: …`): `PermissionDenied` (7) for rejected calls, `ResourceExhausted` (8) for rate limits and too large messages, `InvalidArgument` (3) for a CRS rule that asks for `400` |

The other protections answer in the same forms: a gRPC call over a rate
limit gets `ResourceExhausted`, a GraphQL request from a blocked country a
GraphQL error. A gRPC client cannot solve a [bot challenge](bot-protection.md),
so it gets `PermissionDenied` instead of the challenge page.

A gRPC call that is rejected because of a message after the backend has
started to answer, as in a bidirectional stream, ends with the status in
the trailers; the backend never receives the rejected message.

## Audit events

```json
{
  "time": "2026-11-18T03:12:45.120Z",
  "id": "4e1f0a9c2b7d3856",
  "client_ip": "203.0.113.7",
  "remote_addr": "203.0.113.7:51544",
  "action": "block",
  "reason": "api",
  "api": {
    "protocol": "graphql",
    "violation": "depth",
    "operation": "query Friends",
    "limit": 15,
    "value": 23,
    "message": "depth 23, more than 15"
  },
  "request": { "method": "POST", "uri": "/graphql", "proto": "HTTP/1.1", "host": "api.example.com", "content_length": 412, "headers": { "Content-Type": "application/json" } }
}
```

| Field | Description |
|-------|-------------|
| `api.protocol` | `openapi`, `graphql` or `grpc` |
| `api.violation` | The check that failed: see the tables of [REST](#rest-openapi) and [GraphQL](#graphql); for gRPC `reflection`, `unknown_method`, `invalid_message` or `unsupported_encoding` |
| `api.operation` | The operation, if known: `GET /products/{id}` (the path template of the document), `query Friends`, `/shop.v1.Orders/Get` |
| `api.limit`, `api.value` | For GraphQL limits: the limit and the request's value |
| `api.message` | Details, e.g. `parameter "limit" in query has an error: number must be at most 100` |

Attacks found by the signatures in GraphQL arguments and gRPC messages are
logged with `reason` `signature`, as other attacks, with `match.location`
`graphql` or `grpc`:

```json
"match": { "location": "grpc", "field": "[0].filter.name", "data": "' or 1=1--", "value": "' OR 1=1--", "value_length": 10 }
```

```sh
# Rejected API requests by protocol and violation
jq -r 'select(.reason == "api") | "\(.api.protocol) \(.api.violation) \(.api.operation)"' audit.log | sort | uniq -c | sort -rn
# Endpoints that scanners look for
jq -r 'select(.api.violation == "unknown_path") | .request.uri' audit.log | sort | uniq -c | sort -rn | head
```

## Order of processing

1. [Geo filtering](geo-filtering.md), [rate limits](rate-limiting.md) and
   [bot protection](bot-protection.md), as for every request.
2. For gRPC calls: the method (reflection, schema), the path and
   metadata (signatures, then the CRS), then the messages as they stream.
3. For other requests: the signatures (path, query, headers, body), then
   GraphQL checks and argument inspection, then the OpenAPI document, then
   the CRS.

An attack is therefore reported as an attack (`reason` `signature`), and
a request that only breaks the API's rules as an API violation.

## Rolling out

The checks can reject legitimate requests if the document, schema or
limits do not match what clients really send. Start in detection mode:

1. Run with `-mode detect` and the API options.
2. After some days, look at what would have been rejected:
   ```sh
   jq -r 'select(.reason == "api") | "\(.api.violation)\t\(.api.operation)\t\(.api.message)"' audit.log | sort | uniq -c | sort -rn | head -50
   ```
3. Fix the document or schema where the API really accepts the requests,
   raise limits that real queries reach, then switch to `-mode block`.

Detection mode applies to all of PrismWAF; attacks are not blocked either
while it is on.

## Logs

| Level | Message | Meaning |
|-------|---------|---------|
| INFO | `OpenAPI validation enabled` | At startup: the `document`, its `version`, the number of `operations` and the base `paths` that are validated |
| INFO | `GraphQL protection enabled` | At startup: the `paths`, the `schema` files and the limits |
| INFO | `gRPC schema validation enabled` | At startup: the `descriptors` and the `services` they have |

## Performance

Measured on Linux (aarch64, 2 vCPUs) with Go 1.25:

| Check | Time per request |
|-------|-----------------:|
| OpenAPI 3.0, small document | ~5 µs |
| OpenAPI 3.0, GitHub's document (1281 operations), `GET` with parameters | ~6 µs |
| OpenAPI 3.1, small JSON body | ~50 µs |
| OpenAPI 3.1, GitHub's issue body | ~0.8 ms |
| GraphQL query, without schema | ~6 µs |
| GraphQL query, with GitHub's schema | 6-15 µs |

Bodies of OpenAPI 3.1 documents are checked with a JSON Schema 2020-12
validator, which compiles the schema for each request. Loading GitHub's
document takes about 1 second and 60 MB of memory, Stripe's about 2
seconds and 33 MB.

## Limitations

- **OpenAPI:** credentials are checked for presence, not validity.
  Responses are not validated. Query parameters that the document does not
  describe are allowed, as are properties of objects without
  `additionalProperties: false`. The document is loaded at startup only.
- **GraphQL:** the limits do not weigh fields by cost (e.g. a list of 100
  items against a single object): set them for the most expensive queries
  that clients really send. Persisted queries are not checked. Variables
  are not validated against the schema, only inspected.
- **gRPC:** without a descriptor set, the field types are guessed: a
  string that happens to decode as a message is inspected both ways, and
  binary fields are inspected as text. With a descriptor set, messages
  whose fields are unknown are allowed. A message is withheld until it
  has been inspected; the bytes of the next messages that came with it
  may be withheld too, until they are inspected. Compressed messages in
  encodings other than `gzip` and `deflate` are rejected. Responses are
  not inspected. Rate limits count calls, not the messages of a stream.
  gRPC over HTTP/3 is not supported.
- API protection does not replace authentication and authorization in
  the API, e.g. checks that a user may read an object (BOLA/IDOR).
