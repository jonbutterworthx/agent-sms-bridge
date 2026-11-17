# Installation and initial setup

Use a dedicated ordinary OS account and protected storage. Do not run the service as root. Runtime dependencies are Python's standard library; setuptools builds the package. From a reviewed source directory:

```sh
python3 -m venv "$HOME/.local/share/agent-sms-bridge/venv"
"$HOME/.local/share/agent-sms-bridge/venv/bin/python" -m pip install .
install -d -m 700 "$HOME/.local/share/agent-sms-bridge/data"
```

Keep the source revision/wheel and dependency build inputs pinned for repeatable deployment. No network exposure or system-service installation is performed by package installation.

## Optional initial form

```sh
"$HOME/.local/share/agent-sms-bridge/venv/bin/agent-sms-bridge-setup" \
  --data-dir "$HOME/.local/share/agent-sms-bridge/data"
```

The temporary form listens only on `127.0.0.1:4192`, closes after a successful save or ten minutes, and prints a private setup-code file path. Read the code locally from that file; never put it in a URL, chat, issue or log. The form requires the code, a same-origin session and CSRF token. It rejects existing configuration. A saved setup initializes only the explicitly named owner number, leaves outbound sending disabled, and does not contact SMSGate.

For remote setup, use an authenticated SSH tunnel from your browser's computer:

```sh
ssh -N -L 4192:127.0.0.1:4192 YOUR_PRIVATE_HOST
```

Open `http://127.0.0.1:4192/` locally. Do not bind setup publicly or forward an unauthenticated public port. Browser form protection does not make the separate device API encrypted: use verified HTTPS or a separately encrypted private tunnel for credentials and content.

## JSON route

Copy `examples/setup.json` into protected local storage, replace synthetic values locally, and set mode 0600. Use explicit `+` country-code numbers. A private IP literal URL is required; embedded URL credentials, redirects, public addresses and arbitrary API paths are rejected.

```sh
chmod 600 /ABSOLUTE/PRIVATE/setup.json
"$HOME/.local/share/agent-sms-bridge/venv/bin/agent-sms-bridge-configure" \
  --input /ABSOLUTE/PRIVATE/setup.json \
  --data-dir "$HOME/.local/share/agent-sms-bridge/data"
```

This validates without writing. Add `--apply` to create the initial config and owner policy. Both routes use the same validation and an exclusive initialization claim. If setup crashes after creating `setup.claim`, inspect and preserve the private config/database before recovery. Do not remove a claim and overwrite partially initialized state blindly.

## Verify before enabling

1. Run `agent-sms-bridge-admin --config /ABSOLUTE/DATA/config.json probe`. This is authenticated read-only access and reports schema metadata, not bodies or credentials.
2. Record the exact installed Android app version. Version or `contentPreview` naming alone does not establish complete SMS text. Compare observed API content privately against a known long/multipart SMS, including beginning, middle and ending, and verify that app version's contract. Test only with a consenting recipient.
3. Preserve private comparison evidence. Only after success, set `inbox_full_body_verified` to true and `inbox_verification_evidence` to a nonempty protected evidence reference. Reverify after an app upgrade. Until then the service stores preview observations but excludes them from permitted history.
4. Start in the foreground using `agent-sms-bridge-server --config /ABSOLUTE/DATA/config.json`. Check health and polling freshness. Unverified initial backfill remains historical and cannot become new work automatically.
5. Provision a scoped client as described in API.md. Review owner permission and set `outbound_enabled` true only when intentionally permitting queued sends. Inspect existing queues before enabling. A controlled test send requires explicit recipient intent.

The installed wheel includes documentation, examples and optional units under
the venv's `share/agent-sms-bridge/` directory. No unit is installed or enabled
automatically.

`poll_seconds` accepts an integer from 10 to 3600 (default 60). A value of 10
reduces collection wait but increases device/API activity; monitor the phone.
The poller waits after completion and retains its cursor overlap. This does not
guarantee carrier latency or recover messages lost upstream.

Edit private configuration locally, retaining mode 0600, then restart only this service. There is one configured device endpoint; no automatic fallback to a less secure endpoint.

## Optional user systemd units

The example units assume the venv/data paths above. Review and adjust them before copying into `~/.config/systemd/user/`. They use no root account. `systemctl --user daemon-reload`, then `systemctl --user enable --now agent-sms-bridge.service` starts the service. Enabling `agent-sms-bridge-backup.timer` schedules local-only snapshots at 03:20 UTC with up to five minutes of jitter. Adjust the timezone deliberately; backups never upload or prune automatically.

User-service boot behavior depends on your account's login/linger policy. Enabling a unit is not proof of successful physical reboot recovery. No account-wide linger change is made by these examples.

## Upgrade, stop and uninstall

Before upgrading, stop the service, preserve the current private config and a consistent online SQLite snapshot, and record the old package revision. Install the reviewed pinned replacement into a separate venv, run tests and isolated restore checks, then switch the unit to that venv and start. Inspect polling, history and pending/unknown submissions. Never run two instances against the same database; a process lock enforces one owner. Do not restore an old database merely to roll back code because that discards later history and may replay sends.

To remove runtime activation: `systemctl --user disable --now agent-sms-bridge.service agent-sms-bridge-backup.timer`, remove only the reviewed units, and reload user units. Remove the package/venv if desired. Preserve private config, database/WAL files, evidence and backups until you deliberately decide their retention. Uninstall does not delete message history or revoke Android credentials for you.


## Opt-in compatibility for an existing legacy installation

New configurations default to `"normalization_profile": "strict"`: explicit
country codes are required and national identifiers remain opaque. Initial setup
always uses this default. No geographic region is guessed.

Only a reviewed migration from the earlier NANP deployment should explicitly set
`"normalization_profile": "legacy-nanp-v1"` in its private runtime configuration.
This preserves its exact national 10/11-digit expansion and its treatment of short
explicit identifiers. The profile applies per Store to contacts, policies,
principals, intake, outgoing requests, delivery receipts and status matching;
server and admin commands both load it. Unknown profiles fail before storage is
opened. Configuration owner/device numbers still require explicit country codes.

Selecting a profile does not rewrite stored history, permissions or raw inputs.
Keep it consistent across service/admin processes. Do not switch profiles on an
existing database without a reviewed compatibility rehearsal: changed matching can
alter permissions or status reconciliation even with identical storage schema.
Preserve the existing effective device identity explicitly in `device_id` during
migration, because it participates in deduplication. Keep the latest database for
rollback so post-upgrade messages and send attempts survive. This option does not
authorize a live cutover, sending, provider calls or policy changes.
