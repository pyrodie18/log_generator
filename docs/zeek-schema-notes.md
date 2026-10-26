# Zeek Schema Notes

## Purpose

This document records the Zeek schema research used by the first source-specific Zeek generator. It is scoped to the
`linux-mini-lab` environment and the canonical web browsing scenarios. Phase 3 implements the MVP `conn.log`,
`dns.log`, and `http.log` output described here.

The implemented schemas and rendering live in `src/log_generator/output/zeek.py`; deterministic shared defaults live
in `src/log_generator/core/enrichment.py`. Authored and enriched details use the source-neutral `NetworkContext`,
`DnsContext`, and `HttpContext` models. The output manifest enriches events before writers run, and the tables below
describe current field mappings unless a stream is explicitly deferred.

## Authoritative References

Primary schema target:

- Zeek 8.2.0 current documentation.
- `Conn::Info`: https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html
- `DNS::Info`: https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html
- `HTTP::Info`: https://docs.zeek.org/en/current/scripts/base/protocols/http/main.zeek.html
- `SSL::Info`: https://docs.zeek.org/en/current/scripts/base/protocols/ssl/main.zeek.html
- SSL certificate/file linkage: https://docs.zeek.org/en/v8.2.0/scripts/base/protocols/ssl/files.zeek.html
- `Files::Info`: https://docs.zeek.org/en/current/scripts/base/frameworks/files/main.zeek.html
- `X509::Info`: https://docs.zeek.org/en/v8.2.0/scripts/base/files/x509/main.zeek.html
- Zeek `files.log`: https://docs.zeek.org/en/v8.2.0/reference/logs/files.html
- Zeek `ssl.log`: https://docs.zeek.org/en/v8.2.0/reference/logs/ssl.html
- Zeek `x509.log`: https://docs.zeek.org/en/current/reference/logs/x509.html
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

| Stream | Phase 3 status | Source-neutral event source | Canonical scenario use |
| --- | --- | --- | --- |
| `conn.log` | Implemented | `network_connection`; prerequisite flow for protocol records | DNS and HTTP flows observed by `zeek-sensor-01`. |
| `dns.log` | Implemented | `dns_lookup` | DNS lookup for `web-server-01.internal`. |
| `http.log` | Implemented | `web_request` | Homepage, admin page, and archive requests. |
| `ssl.log` | Deferred | `tls_connection` | Not used by current scenarios because `svc-web-http` is plain HTTP. |
| `files.log` | Deferred | Download-classified `web_request` | Useful later for downloads, but not in `profile-zeek-only` yet. |
| `x509.log` | Deferred | Certificate chain on `tls_connection` | Requires modeled and sensor-visible certificate details. |

Phase 3 does not emit `ssl.log`, `files.log`, or `x509.log`. Phase 4 plans to add them and extend the Zeek sensor
profile and output contract.

For the connection-scoped protocol streams, `conn.log` is not optional supporting telemetry. `dns.log`, `http.log`,
`ssl.log`, and connection-scoped `files.log` must have an underlying `conn.log` record with the same Zeek `uid`.
`x509.log` is certificate-scoped: its certificate ID/FUID is referenced by the corresponding SSL certificate-chain
fields, and it does not carry the connection UID.

## Format Decision

The Phase 3 Zeek generator emits native-style Zeek TSV logs.

Rationale:

- Zeek's default log format is TSV with header rows such as `#separator`, `#fields`, and `#types`.
- Native-style output best satisfies the project's high-fidelity Zeek goal.
- The output contract uses source-specific format names such as `zeek-tsv`.
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
| `id.orig_p` | Enriched `network.source_port`, authored or deterministically derived before output writers run. |
| `id.resp_h` | Destination IP from expanded `network_connection.destination_ip`. |
| `id.resp_p` | Destination port from expanded `network_connection.destination_port`. |
| `proto` | Transport protocol, such as `tcp` or `udp`. |
| `service` | Confirmed application protocol, such as `http` or `dns`, when known. |
| `duration` | Plausible interval derived by the Zeek writer; authored duration is not supported. |
| `orig_bytes` | Enriched `network.orig_bytes`, authored or deterministically estimated before output writers run. |
| `resp_bytes` | Enriched `network.resp_bytes`, authored or deterministically estimated before output writers run. |
| `conn_state` | Generator-owned Zeek state, usually `SF` for successful complete TCP sessions. |
| `local_orig` | Derived from `Site::local_nets` equivalent; `T` for lab-originated canonical traffic. |
| `local_resp` | Derived from `Site::local_nets` equivalent; `T` for internal lab responders. |
| `missed_bytes` | `0` for clean synthetic MVP traffic. |
| `history` | Generator-owned plausible packet history, such as a clean TCP handshake and close sequence. |
| `orig_pkts` / `resp_pkts` | Enriched network packet counts, authored or deterministically estimated before output writers run. |
| `orig_ip_bytes` / `resp_ip_bytes` | Derived from payload byte counts plus packet counts and estimated IP header sizes. |
| `tunnel_parents` | `-` unless a later tunnel event type exists. |
| `ip_proto` | Numeric IP protocol, such as `6` for TCP and `17` for UDP. |

Implementation notes:

- A single source-neutral `network_connection` should produce at most one `conn.log` record for a sensor.
- A `dns_lookup` that produces `dns.log` must also produce the underlying UDP `conn.log` record for that DNS flow.
- Zeek `uid`, `conn_state`, and `history` are Zeek-generator fields.
- Client source ports and byte or packet counts use enriched shared context. The Zeek writer consumes these values and
  derives Zeek-specific IDs and record fields.
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
| `id.orig_p` | Enriched DNS event `network.source_port`, authored or deterministically derived before output writers run. |
| `id.resp_h` | Resolver IP, `10.10.20.53` for `lab-dns-01`. |
| `id.resp_p` | Resolver port, `53`. |
| `proto` | `udp` for the MVP DNS service. |
| `trans_id` | Enriched `dns.trans_id`, authored or deterministically derived as a 16-bit transaction ID. |
| `rtt` | Enriched `dns.rtt`, authored or defaulted to `0.025` seconds. |
| `query` | `dns_lookup.query_name`. |
| `qclass` / `qclass_name` | `1` / `C_IN` for ordinary internet-class queries. |
| `qtype` / `qtype_name` | DNS type number and name, such as `1` / `A`. |
| `rcode` / `rcode_name` | `0` / `NOERROR` for successful canonical lookups. |
| `AA`, `TC`, `RD`, `RA`, `Z` | Enriched `dns.flags` for the first four flags; `Z` is always `0`. |
| `answers` | `dns_lookup.resolved_addresses` for successful responses. |
| `TTLs` | Enriched `dns.ttls`, authored or defaulted to `300` seconds per answer. |
| `rejected` | `F` for successful canonical lookups. |

Implementation notes:

- Failed lookups should populate `rcode` and `rcode_name` consistently and leave successful answers unset.
- The DNS `uid` must match the `uid` in the underlying UDP `conn.log` record.
- DNS transaction IDs, RTTs, flags, source ports, and TTLs use enriched shared context. Future DNS writers can consume
  the same values.
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
| `version` | Enriched `http.version`, authored or defaulted to `1.1`. |
| `user_agent` | Enriched `http.user_agent`, authored first, then the `User-Agent` request header, then the shared default. |
| `request_body_len` | `0` for canonical `GET` requests. |
| `response_body_len` | Enriched `http.response_body_len`, authored first, then a metadata override or shared estimate. |
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
- `trans_depth` and Zeek file IDs are Zeek-owned. Authored HTTP context is preferred for response size, version,
  user agent, and MIME type. File names come from metadata or the request path. Shared enrichment supplies omitted
  HTTP defaults for this and future writers.
- Download classification remains source-neutral metadata on the `web_request`; it does not require a separate
  source-neutral `file_download` event.
- HTTP entity fields such as `resp_fuids`, `resp_filenames`, and `resp_mime_types` are present only when Zeek's HTTP
  entity script is part of the modeled Zeek profile. They should be treated as optional.

## Planned Phase 4 `files.log` Notes

`files.log` represents file observations from network transfers; its presence does not claim that file content was
extracted. Phase 4 plans to emit it for successful, download-classified HTTP responses. Connection-scoped file records
share the HTTP connection `uid` and require the corresponding `conn.log` record.

Useful later fields:

| Zeek field | Source or derivation |
| --- | --- |
| `ts` | First time the file was seen. |
| `fuid` | Generator-owned file unique ID. |
| `uid` | Connection `uid` shared with `conn.log` and `http.log`. |
| `id` | Connection four-tuple. |
| `source` | `HTTP` for HTTP response bodies. |
| `depth` | HTTP transaction depth. |
| `mime_type` | Enriched `http.response_content_type`, or unset if not modeled. |
| `filename` | Inferred from path or HTTP headers, such as `archive.tar.gz`. |
| `is_orig` | `F` for server-to-client downloads. |
| `seen_bytes` / `total_bytes` | Generator-owned file size values. |
| `missing_bytes` / `overflow_bytes` | `0` for clean synthetic MVP traffic. |

Hash and extraction fields such as `md5`, `sha1`, `sha256`, `extracted`, and `extracted_size` depend on extra Zeek
scripts and should not be part of the first field target.

## Planned Phase 4 `ssl.log` Notes

Zeek uses the `SSL::Info` script namespace and `ssl.log` stream for TLS handshake activity. Phase 4 implements a
source-neutral `tls_connection` event and emits `ssl.log` only when modeled TLS traffic is visible to the sensor.

Useful later fields:

| Zeek field | Source or derivation |
| --- | --- |
| `ts` | TLS detection time, usually parent connection timestamp or TLS event timestamp. |
| `uid` | Connection `uid` shared with `conn.log`. |
| `id` | Connection four-tuple. |
| `version` | Authored or enriched TLS version; unset when not observed. |
| `cipher` | Authored or enriched negotiated cipher suite; unset when not observed. |
| `curve` | Authored or enriched negotiated elliptic curve; unset when not observed. |
| `server_name` | Observed or authored SNI; unset when not available or visible. |
| `resumed` | Authored or enriched resumption state. |
| `last_alert` | Unset for clean handshakes. |
| `next_protocol` | Observed or authored ALPN value, such as `http/1.1` or `h2`; unset when not negotiated. |
| `established` | Authored handshake outcome. |
| `ssl_history` | Generator-owned handshake history string. |

Load the Zeek SSL/files integration needed to expose certificate-chain identifiers in `ssl.log`. Keep package-added
fields and validation outputs such as JA3, OCSP, and certificate-verification results outside the first profile.

Each `ssl.log` record must share the `uid` of the underlying TCP `conn.log` record. Omit optional handshake facts that
are absent; do not infer SNI from the target service. A TLS 1.3 record may have no observable certificate chain.

## Planned Phase 4 `x509.log` Notes

Phase 4 adds `x509.log` for certificates explicitly modeled on a `tls_connection` and visible to the passive sensor.
For the first canonical certificate scenario, use TLS 1.2. Do not infer X.509 records from SNI, server names, or a
TLS 1.3 version value. The `ssl.log` record carries the server/client certificate-chain identifiers; `x509.log`
records carry certificate IDs and parsed metadata, not the flow UID. See `docs/phase-4-planning.md` for the proposed
certificate context, deterministic IDs, and acceptance criteria.

## Generator-Owned Values

These values are Zeek-specific and must be generated by the Zeek writer or derived from environment visibility. They
should not become required source-neutral event fields:

- Zeek connection `uid` and file or certificate FUIDs.
- Zeek `conn_state` and Zeek `history`.
- HTTP transaction depth and `ssl_history`.
- Native Zeek timestamp formatting and TSV header rendering.
- Optional policy-loaded columns such as VLAN, DNS authority/additional answers, HTTP header-name vectors, file hashes,
  extracted-file metadata, JA3/JA3S package fields, or site-specific enrichments.

Shared source-neutral context owns values that multiple generators need to agree on, such as client source ports,
shared packet or byte estimates, DNS transaction context, HTTP versions, user agents, and response body lengths.
Authored values win, and the deterministic enrichment pass supplies omitted values before writers run. Zeek continues
to own its UIDs, connection state, history, transaction depth, and native TSV rendering.

Source-neutral events should continue to own:

- Scenario IDs, event IDs, correlation IDs, and parent event IDs.
- Source and destination host references.
- Source and destination addresses and destination ports after expansion.
- Service references.
- DNS query names, query types, and resolved addresses.
- HTTP method, path, URL, status code, and download classification.
- Authored or enriched TLS negotiation facts and modeled certificate metadata needed by multiple output families.

## Compatibility Notes

The Zeek 8.2.0 and 8.0.6 docs use the same core record families needed by the MVP: `Conn::Info`, `DNS::Info`,
`HTTP::Info`, and `SSL::Info`. No blocking field difference was identified for the minimum fields listed above.

Important compatibility guardrails:

- Keep the first Zeek field set limited to core fields present in both 8.2.x and 8.0.x LTS docs.
- Treat policy-loaded fields as optional because Zeek deployments can add or omit columns based on loaded scripts.
- Generate `#fields` and `#types` headers from the selected output profile, not from a hard-coded global list.
- The current manifest records `log_family: zeek` and `format: zeek-tsv`. Explicit Zeek profile and version metadata
  remain future additions.
- Add fixture tests for both a minimal core profile and any enriched profile that enables HTTP entity or file fields.

## Canonical Scenario Mapping

### `scenario-benign-internal-web`

Expected Zeek records in a Phase 3 Zeek-enabled run:

| Source-neutral event | Zeek stream | Key generated facts |
| --- | --- | --- |
| `evt-benign-web-001` | `conn.log`, `dns.log` | UDP resolver flow plus query `web-server-01.internal`, answer `10.10.20.21`, `NOERROR`. |
| `evt-benign-web-002` | `conn.log` | TCP `10.10.10.11:<ephemeral>` to `10.10.20.21:80`, service `http`. |
| `evt-benign-web-003` | `http.log` | `GET /`, host `web-server-01.internal`, status `200`. |

### `scenario-local-account-misuse-web`

Expected Zeek records in a Phase 3 Zeek-enabled run:

| Source-neutral event | Zeek stream | Key generated facts |
| --- | --- | --- |
| `evt-misuse-web-002` | `conn.log`, `dns.log` | UDP resolver flow plus query `web-server-01.internal`, answer `10.10.20.21`, `NOERROR`. |
| `evt-misuse-web-003` | `conn.log` | TCP `10.10.10.11:<ephemeral>` to `10.10.20.21:80`, service `http`. |
| `evt-misuse-web-004` | `http.log` | `GET /admin`, transaction depth `1`, status `200`. |
| `evt-misuse-web-005` | `http.log` | `GET /admin/archive.tar.gz`, transaction depth `2`, status `200`, download metadata. |

The login event does not produce Zeek output because it is local host activity and not network traffic.

## Implementation Handoff

Phase 1 preserved the source-neutral information consumed by the implemented Phase 3 Zeek writer:

- Expanded `dns_lookup`, `network_connection`, and `web_request` events.
- Derived destination host, destination IP, destination port, and service protocol.
- Resolver flow facts for DNS lookups, including resolver IP, resolver port, and UDP protocol.
- Stable event ordering and parentage.
- Download classification on the archive request.
- Environment visibility rules for `zeek-sensor-01`.

Phase 3 implements shared deterministic defaults, Zeek `uid`, epoch timestamp rendering, connection state, HTTP
transaction depth, and TSV header output. Phase 4 plans to add `files.log`, `ssl.log`, and `x509.log`; see
`docs/phase-4-planning.md` for the implementation handoff.
