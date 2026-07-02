# Zeek Schema Notes

## Purpose

This document records the Phase 0 Zeek schema research needed before the first source-specific Zeek generator is
implemented. It is scoped to the `linux-mini-lab` environment and the canonical web browsing scenarios. Phase 1 should
still implement source-neutral events and generic normalized JSON Lines first; these notes are a handoff for the later
Zeek generator.

## Authoritative References

Primary schema target:

- Zeek 8.2.0 current documentation.
- `Conn::Info`: https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html
- `DNS::Info`: https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html
- `HTTP::Info`: https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html
- `SSL::Info`: https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html
- `Files::Info`: https://docs.zeek.org/en/current/scripts/base/frameworks/files/main.zeek.html
- Zeek log formats and JSON logging:
  https://docs.zeek.org/en/current/tutorial/logs.html#zeek-log-formats

Secondary compatibility target:

- Zeek 8.0.6 LTS documentation.
- LTS `conn.log`: https://docs.zeek.org/en/lts/scripts/base/protocols/conn/main.zeek.html
- LTS `dns.log`: https://docs.zeek.org/en/lts/scripts/base/protocols/dns/main.zeek.html
- LTS `http.log`: https://docs.zeek.org/en/lts/scripts/base/protocols/http/main.zeek.html
- LTS `ssl.log`: https://docs.zeek.org/en/lts/scripts/base/protocols/ssl/main.zeek.html

The official docs are Sphinx output generated from Zeek script declarations. For implementation, the generated schema
should be treated as authoritative because local Zeek deployments can add or remove columns through loaded scripts,
packages, and logging policy.

## Stream Scope

MVP Zeek stream targets:

| Stream | Phase 0 status | Source-neutral event source | Canonical scenario use |
| --- | --- | --- | --- |
| `conn.log` | Required for first Zeek generator | `network_connection`; prerequisite flow for protocol records | DNS and HTTP flows observed by `zeek-sensor-01`. |
| `dns.log` | Required for first Zeek generator | `dns_lookup` | DNS lookup for `web-server-01.internal`. |
| `http.log` | Required for first Zeek generator | `web_request` | Homepage, admin page, and archive requests. |
| `ssl.log` | Deferred | `tls_connection` | Not used by current scenarios because `svc-web-http` is plain HTTP. |
| `files.log` | Deferred | Download-classified `web_request` | Useful later for downloads, but not in `profile-zeek-only` yet. |

The first Zeek generator should not emit `ssl.log` for the canonical scenarios. It should also avoid adding
`files.log` until the environment logging profile and output contract explicitly include it.

For the protocol streams targeted here, `conn.log` is not optional supporting telemetry. Zeek protocol records such as
`dns.log`, `http.log`, `ssl.log`, and connection-scoped `files.log` must have an underlying `conn.log` record with the
same Zeek `uid`.

## Format Decision

The first Zeek generator should emit native-style Zeek TSV logs by default.

Rationale:

- Zeek's default log format is TSV with header rows such as `#separator`, `#fields`, and `#types`.
- Native-style output best satisfies the project's high-fidelity Zeek goal.
- The output contract already reserves future source-specific format names such as `zeek-tsv`.
- JSON output is useful for pipelines, but generic normalized JSONL already covers the Phase 1 structured-output need.

Deferred option:

- Add a Zeek JSONL writer later if tests or downstream examples need field-keyed Zeek records. It should be a Zeek
  output format option, not a replacement for generic normalized JSONL.

## Common Zeek Record Rules

All Zeek records produced by `zeek-sensor-01` should live under:

```text
output/
  logs/
    zeek-sensor-01/
      zeek/
        conn.log
        dns.log
        http.log
```

The Zeek generator should emit records only when the modeled traffic is visible to `zeek-sensor-01`. The
`linux-mini-lab` template currently gives the sensor visibility into workstation-to-server and server-to-workstation
traffic, which covers the canonical DNS and HTTP activity.

Protocol log records should never be emitted as standalone records. When a source-neutral event produces `dns.log`,
`http.log`, `ssl.log`, or connection-scoped `files.log`, the Zeek generator must also produce or reference the
corresponding `conn.log` record for the same observed flow.

Recommended native TSV conventions:

| Convention | MVP value |
| --- | --- |
| `#separator` | `\x09` |
| `#set_separator` | `,` |
| `#empty_field` | `(empty)` |
| `#unset_field` | `-` |
| `#path` | Stream name without `.log`, such as `conn`. |
| `#open` / `#close` | Deterministic UTC wall-clock strings derived from the run. |
| `ts` | Seconds since epoch with six fractional digits. |

## `conn.log` Minimum Field Set

`conn.log` is the network-flow anchor. `http.log`, `dns.log`, `ssl.log`, and connection-scoped `files.log` records
must reuse the same Zeek `uid` as the underlying connection record.

Minimum field target:

| Zeek field | Source or derivation |
| --- | --- |
| `ts` | `network_connection.timestamp`, rendered as epoch seconds. |
| `uid` | Generator-owned stable Zeek connection ID. |
| `id.orig_h` | Source host IP from expanded `network_connection.source_ip`. |
| `id.orig_p` | Generator-owned client source port. |
| `id.resp_h` | Destination IP from expanded `network_connection.destination_ip`. |
| `id.resp_p` | Destination port from expanded `network_connection.destination_port`. |
| `proto` | Transport protocol, such as `tcp` or `udp`. |
| `service` | Confirmed application protocol, such as `http` or `dns`, when known. |
| `duration` | Generator-owned plausible interval. |
| `orig_bytes` | Generator-owned payload byte count from originator. |
| `resp_bytes` | Generator-owned payload byte count from responder. |
| `conn_state` | Generator-owned Zeek state, usually `SF` for successful complete TCP sessions. |
| `local_orig` | Derived from `Site::local_nets` equivalent; `T` for lab-originated canonical traffic. |
| `local_resp` | Derived from `Site::local_nets` equivalent; `T` for internal lab responders. |
| `missed_bytes` | `0` for clean synthetic MVP traffic. |
| `history` | Generator-owned plausible packet history, such as a clean TCP handshake and close sequence. |
| `orig_pkts` / `resp_pkts` | Generator-owned packet counts. |
| `orig_ip_bytes` / `resp_ip_bytes` | Generator-owned IP byte counts consistent with payload counts. |
| `tunnel_parents` | `-` unless a later tunnel event type exists. |
| `ip_proto` | Numeric IP protocol, such as `6` for TCP and `17` for UDP. |

Implementation notes:

- A single source-neutral `network_connection` should produce at most one `conn.log` record for a sensor.
- A `dns_lookup` that produces `dns.log` must also produce the underlying UDP `conn.log` record for that DNS flow.
- `uid`, ports, bytes, packet counts, `duration`, `conn_state`, and `history` are Zeek-generator fields.
- The source-neutral model should not require any Zeek `conn.log` field beyond the existing network event facts.

## `dns.log` Minimum Field Set

`dns.log` records should be derived from `dns_lookup` events. Canonical scenarios use A lookups through `svc-dns` on
`lab-dns-01`. Each generated `dns.log` record requires a sibling UDP `conn.log` record for the resolver flow.

Minimum field target:

| Zeek field | Source or derivation |
| --- | --- |
| `ts` | `dns_lookup.timestamp`, rendered as epoch seconds. |
| `uid` | Zeek connection ID for the DNS flow. |
| `id.orig_h` | Source host IP. |
| `id.orig_p` | Generator-owned client source port. |
| `id.resp_h` | Resolver IP, `10.10.20.53` for `lab-dns-01`. |
| `id.resp_p` | Resolver port, `53`. |
| `proto` | `udp` for the MVP DNS service. |
| `trans_id` | Generator-owned 16-bit DNS transaction ID. |
| `rtt` | Generator-owned plausible response interval. |
| `query` | `dns_lookup.query_name`. |
| `qclass` / `qclass_name` | `1` / `C_IN` for ordinary internet-class queries. |
| `qtype` / `qtype_name` | DNS type number and name, such as `1` / `A`. |
| `rcode` / `rcode_name` | `0` / `NOERROR` for successful canonical lookups. |
| `AA`, `TC`, `RD`, `RA`, `Z` | Generator-owned DNS flags with deterministic defaults. |
| `answers` | `dns_lookup.resolved_addresses` for successful responses. |
| `TTLs` | Generator-owned answer TTL intervals. |
| `rejected` | `F` for successful canonical lookups. |

Implementation notes:

- Failed lookups should populate `rcode` and `rcode_name` consistently and leave successful answers unset.
- The DNS `uid` must match the `uid` in the underlying UDP `conn.log` record.
- `trans_id`, `rtt`, DNS flags, source port, and TTLs are Zeek-generator fields.
- Optional fields such as `auth`, `addl`, and `original_query` depend on policy scripts and should be omitted from
  the MVP target unless the generator explicitly models those scripts.

## `http.log` Minimum Field Set

`http.log` records should be derived from `web_request` events after helper expansion has identified the corresponding
connection. Each generated `http.log` record requires an underlying TCP `conn.log` record for the web flow.

Minimum field target:

| Zeek field | Source or derivation |
| --- | --- |
| `ts` | `web_request.timestamp`, rendered as epoch seconds. |
| `uid` | Zeek connection ID shared with the HTTP `conn.log` record. |
| `id.orig_h` | Client IP from the parent connection. |
| `id.orig_p` | Client source port from the parent connection. |
| `id.resp_h` | Web server IP from the parent connection. |
| `id.resp_p` | Web service port, `80` for `svc-web-http`. |
| `trans_depth` | Generator-owned request depth in the TCP connection. |
| `method` | `web_request.method`. |
| `host` | Service DNS name, such as `web-server-01.internal`. |
| `uri` | `path` plus optional query string. |
| `referrer` | Optional request header hint, otherwise unset. |
| `version` | Generator-owned default such as `1.1`. |
| `user_agent` | Generator-owned browser string unless scenario headers override it. |
| `request_body_len` | `0` for canonical `GET` requests. |
| `response_body_len` | Generator-owned body byte count consistent with route and download classification. |
| `status_code` | Expanded `web_request.status_code`. |
| `status_msg` | Derived from `status_code`, such as `OK` for `200`. |
| `tags` | Empty set unless a later scenario needs HTTP tags. |
| `resp_fuids` | Optional file IDs for downloads if HTTP entity logging is modeled. |
| `resp_filenames` | Optional response file names, such as `archive.tar.gz`. |
| `resp_mime_types` | Optional response MIME types. |

Implementation notes:

- The second misuse web request should reuse the same connection `uid` as the first misuse web request and increment
  `trans_depth`.
- The HTTP `uid` must match the `uid` in the underlying TCP `conn.log` record.
- `response_body_len`, `version`, `user_agent`, `trans_depth`, file IDs, MIME types, and response filenames are
  generator-owned unless source-neutral hints are provided.
- Download classification remains source-neutral metadata on the `web_request`; it does not require a separate
  source-neutral `file_download` event.
- HTTP entity fields such as `resp_fuids`, `resp_filenames`, and `resp_mime_types` are present only when Zeek's HTTP
  entity script is part of the modeled Zeek profile. They should be treated as optional.

## Deferred `files.log` Notes

`files.log` can represent downloaded response bodies more directly than `http.log`, but it should remain deferred
until a scenario or profile explicitly requests it. Connection-scoped file records should share the HTTP connection
`uid` and should not be emitted without the corresponding `conn.log` record.

Useful later fields:

| Zeek field | Source or derivation |
| --- | --- |
| `ts` | First time the file was seen. |
| `fuid` | Generator-owned file unique ID. |
| `uid` | Connection `uid` shared with `conn.log` and `http.log`. |
| `id` | Connection four-tuple. |
| `source` | `HTTP` for HTTP response bodies. |
| `depth` | HTTP transaction depth. |
| `mime_type` | Generator-owned or scenario-provided response MIME type. |
| `filename` | Inferred from path or HTTP headers, such as `archive.tar.gz`. |
| `is_orig` | `F` for server-to-client downloads. |
| `seen_bytes` / `total_bytes` | Generator-owned file size values. |
| `missing_bytes` / `overflow_bytes` | `0` for clean synthetic MVP traffic. |

Hash and extraction fields such as `md5`, `sha1`, `sha256`, `extracted`, and `extracted_size` depend on extra Zeek
scripts and should not be part of the first field target.

## Deferred `ssl.log` Notes

Zeek still uses the `SSL::Info` script namespace and `ssl.log` stream for TLS activity. This project can call the
source-neutral event `tls_connection`, but the Zeek generator should emit `ssl.log` when modeling HTTPS or other TLS
connections.

Useful later fields:

| Zeek field | Source or derivation |
| --- | --- |
| `ts` | TLS detection time, usually parent connection timestamp or TLS event timestamp. |
| `uid` | Connection `uid` shared with `conn.log`. |
| `id` | Connection four-tuple. |
| `version` | `tls_connection.tls_version` or generator default. |
| `cipher` | Generator-owned or scenario-provided cipher suite. |
| `curve` | Generator-owned or scenario-provided elliptic curve. |
| `server_name` | `tls_connection.server_name` or service DNS name. |
| `resumed` | Generator-owned boolean. |
| `last_alert` | Unset for clean handshakes. |
| `next_protocol` | Generator-owned ALPN value, such as `http/1.1` or `h2`. |
| `established` | `T` for successful TLS handshakes. |
| `ssl_history` | Generator-owned handshake history string. |

No canonical MVP scenario uses TLS, so these fields should not affect Phase 1 event models.

When TLS is added, each `ssl.log` record must share the `uid` of the underlying TCP `conn.log` record.

## Generator-Owned Values

These values must be generated by the Zeek generator or derived from environment visibility. They should not become
required source-neutral event fields:

- Zeek `uid` and file `fuid`.
- Client ephemeral source ports.
- DNS transaction IDs, RTTs, flags, and TTLs.
- Connection duration, packet counts, byte counts, `conn_state`, and `history`.
- HTTP transaction depth, version, user agent, response body length, response MIME type, and Zeek file linkage fields.
- TLS cipher details, ALPN, session-resumption flags, and `ssl_history`.
- Native Zeek timestamp formatting and TSV header rendering.
- Optional policy-loaded columns such as VLAN, DNS authority/additional answers, HTTP header-name vectors, file hashes,
  extracted-file metadata, JA3/JA3S package fields, or site-specific enrichments.

Source-neutral events should continue to own:

- Scenario IDs, event IDs, correlation IDs, and parent event IDs.
- Source and destination host references.
- Source and destination addresses and destination ports after expansion.
- Service references.
- DNS query names, query types, and resolved addresses.
- HTTP method, path, URL, status code, and download classification.

## Compatibility Notes

The Zeek 8.2.0 and 8.0.6 docs use the same core record families needed by the MVP: `Conn::Info`, `DNS::Info`,
`HTTP::Info`, and `SSL::Info`. No blocking field difference was identified for the minimum fields listed above.

Important compatibility guardrails:

- Keep the first Zeek field set limited to core fields present in both 8.2.x and 8.0.x LTS docs.
- Treat policy-loaded fields as optional because Zeek deployments can add or omit columns based on loaded scripts.
- Generate `#fields` and `#types` headers from the selected output profile, not from a hard-coded global list.
- Record the target Zeek profile and version family in the manifest when source-specific Zeek output is eventually
  implemented.
- Add fixture tests for both a minimal core profile and any enriched profile that enables HTTP entity or file fields.

## Canonical Scenario Mapping

### `scenario-benign-internal-web`

Expected Zeek records in a future full-family run:

| Source-neutral event | Zeek stream | Key generated facts |
| --- | --- | --- |
| `evt-benign-web-001` | `conn.log`, `dns.log` | UDP resolver flow plus query `web-server-01.internal`, answer `10.10.20.21`, `NOERROR`. |
| `evt-benign-web-002` | `conn.log` | TCP `10.10.10.11:<ephemeral>` to `10.10.20.21:80`, service `http`. |
| `evt-benign-web-003` | `http.log` | `GET /`, host `web-server-01.internal`, status `200`. |

### `scenario-local-account-misuse-web`

Expected Zeek records in a future full-family run:

| Source-neutral event | Zeek stream | Key generated facts |
| --- | --- | --- |
| `evt-misuse-web-002` | `conn.log`, `dns.log` | UDP resolver flow plus query `web-server-01.internal`, answer `10.10.20.21`, `NOERROR`. |
| `evt-misuse-web-003` | `conn.log` | TCP `10.10.10.11:<ephemeral>` to `10.10.20.21:80`, service `http`. |
| `evt-misuse-web-004` | `http.log` | `GET /admin`, transaction depth `1`, status `200`. |
| `evt-misuse-web-005` | `http.log` | `GET /admin/archive.tar.gz`, transaction depth `2`, status `200`, download metadata. |

The login event does not produce Zeek output because it is local host activity and not network traffic.

## Phase 1 Handoff

Phase 1 should not implement Zeek output unless the implementation scope changes. It should preserve enough
source-neutral information for the later Zeek generator to derive these records:

- Expanded `dns_lookup`, `network_connection`, and `web_request` events.
- Derived destination host, destination IP, destination port, and service protocol.
- Resolver flow facts for DNS lookups, including resolver IP, resolver port, and UDP protocol.
- Stable event ordering and parentage.
- Download classification on the archive request.
- Environment visibility rules for `zeek-sensor-01`.

The later Zeek implementation can start by adding deterministic helper functions for Zeek `uid`, client source ports,
epoch timestamp rendering, byte counts, packet counts, connection state, HTTP transaction depth, and TSV header output.
