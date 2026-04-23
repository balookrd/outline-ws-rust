# Working Grafana dashboard for control-plane uplinks

Dashboard file:

- `outline-ws-rust-uplinks-dashboard.json`

This version is intentionally **stable/importable** and uses only:

- built-in Grafana panels (`stat`, `table`, `text`)
- Infinity datasource (`yesoreyeram-infinity-datasource`)

No custom JS panel is required for the main view.

## What works out of the box

- Top summary cards:
  - Instances
  - Uplink Groups
  - Uplinks
  - Active Uplinks
  - Inactive Uplinks
- Topology table from `/control/topology`
- Active/inactive highlighting via computed `active_any`
- Authenticated reads from `/control/summary` and `/control/topology`

## Required datasource/plugin

### Infinity datasource

Install plugin:

- `yesoreyeram-infinity-datasource`

Dashboard queries call URLs:

- `${control_url}/control/summary`
- `${control_url}/control/topology`

with header:

```http
Authorization: Bearer ${control_token}
```

## Dashboard variables

- `control_url` (textbox) — control endpoint base, e.g. `http://127.0.0.1:9091`
- `control_token` (hidden textbox) — bearer token

## Activation (`POST /control/activate`)

Grafana built-in + Infinity reliably handle read APIs, but row-level POST actions with JSON body templating are plugin-dependent.

So dashboard includes an "Activate uplink" instruction panel with exact payload.

For one-click activation install one of:

- Volkov Labs Business Forms
- Volkov Labs Data Manipulation

Use request:

```http
POST /control/activate
Authorization: Bearer <token>
Content-Type: application/json

{
  "group": "core",
  "uplink": "uplink-02",
  "transport": "tcp"
}
```

Legacy compatibility:

- `POST /switch?group=...&uplink=...&transport=tcp|udp|both`

## Security notes

- `/control` must not be public.
- Keep listener internal (loopback / management VLAN / VPN).
- Store bearer token as secret (prefer datasource secure settings or secret manager).
- Keep `/metrics` and `/control` on separate listeners.
