# Linux Mini Lab Environment Template

## Purpose

`linux-mini-lab` is the first built-in environment template for the synthetic log generator. It is intentionally small
and Linux-only so early implementation work can focus on source-neutral modeling, deterministic event generation, and
cross-source consistency before adding larger enterprise dependencies.

The template should support the first canonical scenarios:

- Benign internal web browsing from a Linux workstation to an internal Apache server.
- Local Linux account misuse followed by suspicious internal web access and file download activity.

## Design Goals

- Keep the modeled environment small enough to reason about manually.
- Use stable IDs, IP addresses, hostnames, and service names so tests can assert exact values.
- Make every valid scenario reference resolvable through the environment.
- Make impossible activity easy to reject during validation.
- Provide enough network, service, and policy detail for current Zeek output and future Apache, auditd, and firewall
  generators.
- Keep downstream ingestion concerns outside the template. Directory structure and metadata should be clear to humans.

## Template Identity

| Field | Value |
| --- | --- |
| Template ID | `linux-mini-lab` |
| Display Name | Linux Mini Lab |
| Version | `0.1` |
| Primary Domain | `internal` |
| Time Zone | UTC |
| Environment Type | Small internal lab |

All internally generated timestamps should use timezone-aware UTC datetimes. Source-specific generators may render
timestamps in a source-native format, but the environment itself should not carry local-time assumptions.

## Network Zones

| Zone ID | Display Name | CIDR | Hosts | Purpose |
| --- | --- | --- | --- | --- |
| `workstation-vlan` | Workstation VLAN | `10.10.10.0/24` | `linux-ws-01`, `linux-ws-02` | Linux user workstations. |
| `server-vlan` | Server VLAN | `10.10.20.0/24` | `web-server-01`, `lab-dns-01` | Internal application and infrastructure services. |
| `monitoring-vlan` | Monitoring VLAN | `10.10.30.0/24` | `zeek-sensor-01` | Sensor management and monitoring interfaces. |
| `internet` | Internet | external | none | External resources outside the lab boundary. |

The MVP scenarios should only require `workstation-vlan`, `server-vlan`, and `monitoring-vlan`, but the template also
defines an external `internet` zone so later scenarios can model boundary firewall traversal without changing the
topology model.

## Hosts

| Host ID | Hostname | FQDN | Role | Zone | Primary IP | OS | Logging Profiles |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `linux-ws-01` | `linux-ws-01` | `linux-ws-01.internal` | workstation | `workstation-vlan` | `10.10.10.11` | Ubuntu Linux | `profile-auditd-only` |
| `linux-ws-02` | `linux-ws-02` | `linux-ws-02.internal` | workstation | `workstation-vlan` | `10.10.10.12` | Ubuntu Linux | `profile-auditd-only` |
| `web-server-01` | `web-server-01` | `web-server-01.internal` | web server | `server-vlan` | `10.10.20.21` | Ubuntu Linux | `profile-apache-auditd` |
| `lab-dns-01` | `lab-dns-01` | `lab-dns-01.internal` | DNS resolver | `server-vlan` | `10.10.20.53` | Ubuntu Linux | none |
| `zeek-sensor-01` | `zeek-sensor-01` | `zeek-sensor-01.internal` | passive sensor | `monitoring-vlan` | `10.10.30.31` | Zeek sensor | `profile-zeek-only` |

### Host Notes

- `linux-ws-01` is Alice and Bob's primary workstation.
- `linux-ws-02` is Carol's primary workstation and gives the lab a second benign workstation for future noise.
- `web-server-01` hosts the internal Apache service used by the first scenarios.
- `lab-dns-01` is a normal host with no MVP logging profile attached. A future DNS logging profile can enable DNS
  server-side records without changing the entity model.
- `zeek-sensor-01` has a management IP in `monitoring-vlan` and passive visibility into traffic between the
  workstation and server VLANs.
- `boundary-fw-01` is modeled under network devices rather than hosts because its interfaces and policy rules drive
  path selection and firewall telemetry.

Hosts without logging profiles are still part of the environment. They can own services, appear in DNS, participate in
network activity, and become visible to sensors, but they do not produce their own host-side log files.

## Users

| User ID | Username | Display Name | Account Type | Login Hosts | Normal Login Hosts | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `user-alice` | `alice` | Alice Adams | local user | `linux-ws-01` | `linux-ws-01` | Primary actor for canonical scenarios. |
| `user-bob` | `bob` | Bob Brown | local user | `linux-ws-01` | `linux-ws-01` | Benign actor for later background activity. |
| `user-carol` | `carol` | Carol Clark | local user | `linux-ws-02` | `linux-ws-02` | Benign actor for later background activity. |
| `user-www-data` | `www-data` | Apache Runtime User | service account | `web-server-01` | none | Service account for Apache-owned processes. |

### User Rules

- All accounts are local Linux accounts.
- LDAP, Active Directory, Kerberos, NTLM, SAML, and cloud identity are out of scope for this template.
- User-to-host account placement should be owned by the user definition. Host-local account lists can be derived from
  `users[].login_hosts` instead of duplicated under each host.
- `login_hosts` means the local account exists on those hosts and can be used in authored login scenarios.
- `normal_login_hosts` is a pattern-of-life hint for random benign login generation.
- Service accounts can exist on hosts while having no normal interactive login behavior.
- User IDs are stable environment identifiers. Usernames are the values expected to appear in generated logs.

## Groups

| Group ID | Name | Members | Purpose |
| --- | --- | --- | --- |
| `group-workstation-users` | `workstation-users` | `user-alice`, `user-bob`, `user-carol` | Normal interactive workstation users. |
| `group-web-runtime` | `web-runtime` | `user-www-data` | Runtime identity for the Apache service. |

Groups are intentionally minimal. The MVP should not use groups for authorization decisions unless a scenario requires
that behavior later.

## Services

| Service ID | Name | Target Host | Port | Protocol | URL or Name | Visibility |
| --- | --- | --- | --- | --- | --- | --- |
| `svc-web-http` | Internal Apache HTTP | `web-server-01` | 80 | TCP/HTTP | `http://web-server-01.internal/` | Zeek, Apache |
| `svc-web-ssh` | Web Server SSH | `web-server-01` | 22 | TCP/SSH | `ssh://web-server-01.internal` | Zeek, auditd |
| `svc-dns` | Internal DNS Resolver | `lab-dns-01` | 53 | UDP/DNS | `lab-dns-01.internal` | Zeek |

### HTTP Routes

| Method | Path | Purpose | Expected Status | Notes |
| --- | --- | --- | --- | --- |
| `GET` | `/` | Homepage | `200` | Used by benign web browsing. |
| `GET` | `/about` | Static informational page | `200` | Useful for future benign noise. |
| `GET` | `/admin` | Administrative page | `200` | Used by the local account misuse scenario. |
| `GET` | `/login` | Login page | `403` | Represents a denied login portal access attempt. |
| `GET` | `/admin/archive.tar.gz` | Suspicious archive download | `200` | Used by the local account misuse scenario. |
| `GET` | `/missing` | Missing page | `404` | Useful for future error-log and noise behavior. |

The template defines default path availability. Scenarios may still override response codes when they intentionally
model an error condition or access-control edge case. In the structured template, these routes should be nested under
`svc-web-http` so the service is defined once with its route behavior attached.

## DNS Records

| Name | Type | Value | Notes |
| --- | --- | --- | --- |
| `linux-ws-01.internal` | A | `10.10.10.11` | Workstation identity. |
| `linux-ws-02.internal` | A | `10.10.10.12` | Workstation identity. |
| `web-server-01.internal` | A | `10.10.20.21` | Used by web scenarios. |
| `zeek-sensor-01.internal` | A | `10.10.30.31` | Sensor management identity. |
| `lab-dns-01.internal` | A | `10.10.20.53` | Internal resolver identity. |

DNS lookups in MVP scenarios should query `lab-dns-01` and should be visible to `zeek-sensor-01`.

## Logging Profiles

Logging profiles are reusable telemetry bundles. A profile defines one or more log families and streams. A host
attaches one or more profiles, and the effective generated files are derived from the host ID plus the attached
profile's families and streams.

| Profile ID | Families and Streams | Attached Entities | Purpose |
| --- | --- | --- | --- |
| `profile-zeek-only` | `zeek`: `conn.log`, `dns.log`, `http.log`| `zeek-sensor-01` | Passive network telemetry. |
| `profile-auditd-only` | `auditd`: `audit.log` | `linux-ws-01`, `linux-ws-02` | Local authentication and process telemetry. |
| `profile-apache-auditd` | `apache`: `access.log`, `error.log`; `auditd`: `audit.log` | `web-server-01` | Web access, server errors, and host telemetry. |
| `profile-firewall-traffic` | `firewall`: `traffic.log` | `boundary-fw-01` | Firewall allow and deny telemetry. |

The attached entities column is an explanatory inverse view. In the structured template, the source of truth is each
host's or network device's `logging_profiles` list.

## Network Devices and Policy

Network devices describe routed connectivity between zones. Scenarios should not author firewall events directly.
Instead, an authored event such as `web_request` or `network_connection` should resolve to a source zone and
destination zone. If the selected path crosses a network device with matching policy and logging enabled, the matching
firewall records can be generated from that derived path.

### Network Device Inventory

| Device ID | Type | Interfaces | Logging Profiles | Purpose |
| --- | --- | --- | --- | --- |
| `boundary-fw-01` | firewall | `workstation-vlan` `10.10.10.1`; `server-vlan` `10.10.20.1`; `internet` `203.0.113.10` | `profile-firewall-traffic` | Routes and filters workstation, server, and external traffic. |

Interfaces intentionally use only `zone` and `ip` fields in the structured template. Interface IDs are omitted because
the MVP only needs to resolve zone membership and device traversal for log generation.

### Firewall Policy Rules

Policy rules are owned by the network device that enforces them. The first matching rule should determine the action,
path metadata, NAT behavior, and whether a firewall log record is generated.

| Device ID | Rule ID | Source Zones | Destination Zones | Protocols | Destination Ports | Action | Logging | NAT |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `boundary-fw-01` | `allow-workstations-dns` | `workstation-vlan` | `server-vlan` | UDP | `53` | allow | yes | none |
| `boundary-fw-01` | `allow-workstations-internal-web` | `workstation-vlan` | `server-vlan` | TCP | `80` | allow | yes | none |
| `boundary-fw-01` | `allow-workstations-external-web` | `workstation-vlan` | `internet` | TCP | `80`, `443` | allow | yes | source NAT to `203.0.113.10` |
| `boundary-fw-01` | `deny-workstations-other` | `workstation-vlan` | any | any | any | deny | yes | none |

These rules are not source-neutral events. They are environment constraints. A successful event must match an allow
rule when it crosses `boundary-fw-01`; denied traffic can be modeled by an authored event with `status: denied` that
matches a deny rule.

## Sensor Visibility

`zeek-sensor-01` passively observes the following traffic:

| Source Zone | Destination Zone | Visible | Notes |
| --- | --- | --- | --- |
| `workstation-vlan` | `server-vlan` | yes | Required for DNS and web scenarios. |
| `server-vlan` | `workstation-vlan` | yes | Required for response-side connection metadata. |
| `workstation-vlan` | `workstation-vlan` | yes | Useful for future lateral or peer traffic scenarios. |
| `server-vlan` | `server-vlan` | yes | No MVP scenario currently depends on this path. |
| `workstation-vlan` | `internet` | no | Boundary firewall telemetry covers external traffic in this template. |
| `monitoring-vlan` | any | no | Sensor management traffic is out of scope for MVP scenarios. |

Visibility means the sensor can generate Zeek network records for event types supported by the current writer. It does
not mean every event must produce a Zeek record.

## Expected Output Paths

The environment should naturally map to this output structure:

```text
output/
  manifest.json
  logs/
    zeek-sensor-01/
      zeek/
        conn.log
        dns.log
        http.log
    linux-ws-01/
      auditd/
        audit.log
    linux-ws-02/
      auditd/
        audit.log
    web-server-01/
      apache/
        access.log
        error.log
      auditd/
        audit.log
    boundary-fw-01/
      firewall/
        traffic.log
  metadata/
    ground-truth.jsonl
    scenario-manifest.json
```

The path identifies the generating source first, then the log family, then the stream. A human should be able to tell
what produced each file without opening `manifest.json`.

These paths are derived from host profile attachments. For example, `web-server-01` attaches
`profile-apache-auditd`, which expands into `logs/web-server-01/apache/access.log`,
`logs/web-server-01/apache/error.log`, and `logs/web-server-01/auditd/audit.log`.
Network device paths follow the same source-first pattern. For example, `boundary-fw-01` attaches
`profile-firewall-traffic`, which expands into `logs/boundary-fw-01/firewall/traffic.log`.

The first implementation should not create empty files for configured streams with zero records. The manifest can
record omitted streams if coverage visibility is useful.

## Environment Lookup Rules

Implementations should provide lookup helpers for:

- Host ID, hostname, FQDN, and IP address.
- User ID and username.
- Service ID, service name, FQDN, IP, port, and protocol.
- Network device ID, interface zone, and interface IP address.
- Firewall policy rule ID and network device ID.
- HTTP service route by service ID, method, and path.
- Logging profile ID and attached host or network device ID.
- DNS name to record value.
- Zone ID and CIDR when the zone has an enumerated CIDR.

Lookup failures should produce validation errors that name the missing reference and the field where it appeared.

## Validation Rules

### Host and Address Rules

- Every host reference must resolve to a known host ID, hostname, FQDN, or IP address.
- Host IDs must be globally unique even though host definitions are nested under zones.
- Every modeled internal IP address must belong to exactly one defined zone.
- A host's primary IP address must belong to the host's zone.
- Generated traffic between unknown internal IP addresses should be rejected.
- Events may reference external IP addresses only when the scenario explicitly marks the destination as external.
- Network device interface IP addresses must belong to the referenced internal zone unless the zone is external.
- Network devices must not define duplicate interfaces for the same zone unless later routing needs require it.

### User and Authentication Rules

- Local Linux login events must reference a known user and known host.
- A local login is valid only if the target host appears in the user's `login_hosts`.
- Host-local account membership is derived from `users[].login_hosts`.
- `normal_login_hosts` must be a subset of `login_hosts`.
- Random pattern-of-life login generation should use `normal_login_hosts` by default.
- Group membership must reference user IDs, not usernames, so relationships remain stable if display names or
  usernames change later.
- `alice` and `bob` may log into `linux-ws-01`.
- `carol` may log into `linux-ws-02`.
- `www-data` may run service processes on `web-server-01` but should not perform interactive login activity by
  default.
- Failed login events may reference valid users on invalid hosts only when the scenario explicitly models misuse,
  probing, or misconfiguration.

### Service Rules

- Web requests to `web-server-01.internal` should resolve through `svc-web-http` unless a scenario specifies another
  service.
- A service must target a known host.
- A service IP should be derived from the target host's `primary_ip` unless the service explicitly defines `bind_ip`.
- Every service name should have a DNS record that resolves to the target host's `primary_ip` unless the service
  explicitly defines `bind_ip`.
- DNS lookups should use `lab-dns-01` as the resolver unless a scenario explicitly chooses another resolver.
- DNS lookups for known `*.internal` names should resolve to the values in the DNS records table.
- DNS lookups for unknown internal names should return a negative result unless the scenario explicitly creates a
  temporary record.
- Apache request events must target `svc-web-http`.
- HTTP path defaults should be resolved from the target service's nested `routes` list.
- SSH activity against `web-server-01` should target `svc-web-ssh`.

### Network Policy Rules

- Every policy rule must belong to a known network device.
- Every policy rule source and destination zone must resolve to a known zone or the literal `any`.
- A routed event that crosses a network device must match exactly one first-applicable policy rule.
- A successful event that crosses a firewall must match an allow rule.
- A denied event may match a deny rule and should still generate firewall telemetry when rule logging is enabled.
- NAT fields are policy-owned and should not be authored on source-neutral events.

### Visibility Rules

- Events observed through `profile-zeek-only` must involve traffic that is visible to `zeek-sensor-01`.
- Apache records should only be generated for requests handled by `web-server-01`.
- Auditd records should only be generated by a host with an attached auditd-capable logging profile.
- Firewall records should only be generated for events whose computed path crosses a network device with an attached
  firewall-capable logging profile and a matching logged policy rule.
- The same event may produce records from multiple attached profiles only when each profile has a clear visibility path.

### Logging Profile Rules

- Every host-attached logging profile ID must resolve to a known logging profile.
- Every network-device-attached logging profile ID must resolve to a known logging profile.
- Every logging profile family must define at least one stream.
- Every stream name must be filesystem-safe.
- Hosts without logging profiles can own services and participate in events, but they should not generate host-side log
  files.

## Canonical Scenario Support

### Benign Internal Web Browsing

The environment supports this path:

1. `alice` uses `linux-ws-01`.
2. `linux-ws-01` queries `lab-dns-01` for `web-server-01.internal`.
3. `lab-dns-01` resolves the name to `10.10.20.21`.
4. `linux-ws-01` connects to `10.10.20.21:80`.
5. `boundary-fw-01` allows the workstation-to-server DNS and HTTP flows through matching policy rules.
6. `web-server-01` serves `GET /`.
7. `zeek-sensor-01` can observe the DNS lookup and HTTP connection.
8. `web-server-01` can generate an Apache access record.
9. `boundary-fw-01` can generate firewall traffic records when the scenario requests the `firewall` output family.

### Local Account Misuse and Suspicious Download

The environment supports this path:

1. A scenario marks `alice` account use on `linux-ws-01` as suspicious or attacker-controlled.
2. `linux-ws-01` generates local authentication telemetry for the login.
3. `linux-ws-01` queries `lab-dns-01` for `web-server-01.internal`.
4. `linux-ws-01` connects to `web-server-01` over HTTP.
5. `boundary-fw-01` allows the workstation-to-server DNS and HTTP flows through matching policy rules.
6. `web-server-01` serves `/admin`, denies `/login`, or serves `/admin/archive.tar.gz` depending on the scenario.
7. `zeek-sensor-01` can observe the DNS and HTTP activity.
8. `web-server-01` can generate Apache access records.
9. `boundary-fw-01` can generate firewall traffic records when the scenario requests the `firewall` output family.
10. The scenario can write answer-key metadata identifying the suspicious use and download.

## Proposed Structured Template

The first implementation can represent this document as Python objects, YAML, JSON, or fixtures. The following
structured shape is intended as a direct translation target. Hosts are nested under zones so a reader can inspect a
zone and immediately see its host coverage and attached logging profiles.

The structured YAML is the intended source of truth. The prose tables above are summaries for review and should be
derived from the structured representation once implementation begins.

```yaml
id: linux-mini-lab
version: "0.1"
display_name: Linux Mini Lab
domain: internal
timezone: UTC
zones:
  - id: workstation-vlan
    cidr: 10.10.10.0/24
    hosts:
      - id: linux-ws-01
        hostname: linux-ws-01
        fqdn: linux-ws-01.internal
        primary_ip: 10.10.10.11
        os: ubuntu-linux
        roles:
          - workstation
        logging_profiles:
          - profile-auditd-only
      - id: linux-ws-02
        hostname: linux-ws-02
        fqdn: linux-ws-02.internal
        primary_ip: 10.10.10.12
        os: ubuntu-linux
        roles:
          - workstation
        logging_profiles:
          - profile-auditd-only
  - id: server-vlan
    cidr: 10.10.20.0/24
    hosts:
      - id: web-server-01
        hostname: web-server-01
        fqdn: web-server-01.internal
        primary_ip: 10.10.20.21
        os: ubuntu-linux
        roles:
          - web-server
        logging_profiles:
          - profile-apache-auditd
      - id: lab-dns-01
        hostname: lab-dns-01
        fqdn: lab-dns-01.internal
        primary_ip: 10.10.20.53
        os: ubuntu-linux
        roles:
          - dns-resolver
        logging_profiles: []
  - id: monitoring-vlan
    cidr: 10.10.30.0/24
    hosts:
      - id: zeek-sensor-01
        hostname: zeek-sensor-01
        fqdn: zeek-sensor-01.internal
        primary_ip: 10.10.30.31
        os: zeek-sensor
        roles:
          - network-sensor
        logging_profiles:
          - profile-zeek-only
  - id: internet
    type: external
    hosts: []
network_devices:
  - id: boundary-fw-01
    type: firewall
    interfaces:
      - zone: workstation-vlan
        ip: 10.10.10.1
      - zone: server-vlan
        ip: 10.10.20.1
      - zone: internet
        ip: 203.0.113.10
    logging_profiles:
      - profile-firewall-traffic
    policies:
      rules:
        - id: allow-workstations-dns
          source_zones:
            - workstation-vlan
          destination_zones:
            - server-vlan
          protocols:
            - udp
          destination_ports:
            - 53
          action: allow
          logging: true
        - id: allow-workstations-internal-web
          source_zones:
            - workstation-vlan
          destination_zones:
            - server-vlan
          protocols:
            - tcp
          destination_ports:
            - 80
          action: allow
          logging: true
        - id: allow-workstations-external-web
          source_zones:
            - workstation-vlan
          destination_zones:
            - internet
          protocols:
            - tcp
          destination_ports:
            - 80
            - 443
          action: allow
          logging: true
          nat:
            type: source_nat
            translated_source_ip: 203.0.113.10
        - id: deny-workstations-other
          source_zones:
            - workstation-vlan
          destination_zones:
            - any
          protocols:
            - any
          destination_ports:
            - any
          action: deny
          logging: true
users:
  - id: user-alice
    username: alice
    display_name: Alice Adams
    account_type: local-user
    login_hosts:
      - linux-ws-01
    normal_login_hosts:
      - linux-ws-01
  - id: user-bob
    username: bob
    display_name: Bob Brown
    account_type: local-user
    login_hosts:
      - linux-ws-01
    normal_login_hosts:
      - linux-ws-01
  - id: user-carol
    username: carol
    display_name: Carol Clark
    account_type: local-user
    login_hosts:
      - linux-ws-02
    normal_login_hosts:
      - linux-ws-02
  - id: user-www-data
    username: www-data
    display_name: Apache Runtime User
    account_type: service-account
    login_hosts:
      - web-server-01
    normal_login_hosts: []
groups:
  - id: group-workstation-users
    name: workstation-users
    members:
      - user-alice
      - user-bob
      - user-carol
  - id: group-web-runtime
    name: web-runtime
    members:
      - user-www-data
services:
  - id: svc-web-http
    target_host: web-server-01
    port: 80
    protocol: http
    names:
      - web-server-01.internal
    routes:
      - method: GET
        path: /
        default_status: 200
        purpose: Homepage
      - method: GET
        path: /about
        default_status: 200
        purpose: Static informational page
      - method: GET
        path: /admin
        default_status: 200
        purpose: Administrative page
      - method: GET
        path: /login
        default_status: 403
        purpose: Denied login portal access attempt
      - method: GET
        path: /admin/archive.tar.gz
        default_status: 200
        purpose: Suspicious archive download
      - method: GET
        path: /missing
        default_status: 404
        purpose: Missing page
  - id: svc-web-ssh
    target_host: web-server-01
    port: 22
    protocol: ssh
    names:
      - web-server-01.internal
  - id: svc-dns
    target_host: lab-dns-01
    port: 53
    protocol: dns
    names:
      - lab-dns-01.internal
dns_records:
  - name: linux-ws-01.internal
    type: A
    value: 10.10.10.11
  - name: linux-ws-02.internal
    type: A
    value: 10.10.10.12
  - name: web-server-01.internal
    type: A
    value: 10.10.20.21
  - name: zeek-sensor-01.internal
    type: A
    value: 10.10.30.31
  - name: lab-dns-01.internal
    type: A
    value: 10.10.20.53
logging_profiles:
  - id: profile-zeek-only
    families:
      - name: zeek
        streams:
          - conn.log
          - dns.log
          - http.log
  - id: profile-auditd-only
    families:
      - name: auditd
        streams:
          - audit.log
  - id: profile-apache-auditd
    families:
      - name: apache
        streams:
          - access.log
          - error.log
      - name: auditd
        streams:
          - audit.log
  - id: profile-firewall-traffic
    families:
      - name: firewall
        streams:
          - traffic.log
```

## Phase 1 Translation Notes

- Prefer plain data models for this template before adding a template-loading DSL.
- Keep host, user, service, network device, policy rule, and logging profile IDs stable because tests will likely assert
  them.
- Treat hosts without logging profiles as normal environment hosts that do not generate host-side log files.
- Keep validation errors explicit and reference the environment field that failed.
- Do not introduce SIEM-specific settings into the environment template.
