# Backup and recovery

Required recovery material includes the SQLite database, private configuration/credentials, exact-version full-content verification evidence, reviewed service definitions and a pinned source/package revision. Independent API client tokens need protected backup or deliberate revocation/reprovisioning. Data-root permissions must stay 0700 and sensitive files 0600. Application files are not encrypted at rest; use an encrypted backup destination and an appropriate host account/storage policy.

`"$HOME/.local/share/agent-sms-bridge/venv/bin/agent-sms-bridge-admin" --config /ABSOLUTE/DATA/config.json backup` uses SQLite's online backup API and checks integrity. It creates a private snapshot under the configured data directory's `backups` subdirectory. Do not copy a live DB without coordinating its WAL. No snapshot uploads, deletion or retention automation are included. Same-disk snapshots do not protect against disk loss.

Verify a selected snapshot into a fresh isolated directory beneath the private data root:

```sh
"$HOME/.local/share/agent-sms-bridge/venv/bin/agent-sms-bridge-admin" --config /ABSOLUTE/DATA/config.json verify-restore \
  --backup /ABSOLUTE/DATA/backups/SELECTED.db \
  --destination /ABSOLUTE/DATA/restore-check
```

This checks integrity and logical equality without starting a sender or replacing the live database. A backup receipt or successful archive upload alone is not a proven restore.

For actual recovery: stop the service and snapshot timer, preserve the complete current private directory including WAL/SHM and post-snapshot evidence, restore into a separate directory, then verify before deliberately switching configuration. Reconcile all queued/submitting/unknown outgoing operations against provider and post-snapshot activity before enabling sends. Never replay an old queue automatically. Interrupted submissions remain unknown, not retryable sends.

For endpoint rollback, preserve the current config and restore only a reviewed previous configuration, then restart this service and inspect polling/state. A rollback from an encrypted tunnel to plain LAN HTTP is a security change requiring an explicit operator decision; no automatic fallback is implemented.

Backup integration is intentionally external. Select exact required files and a consistent DB snapshot, excluding caches and disposable restore checks. Do not assume a broad home-directory backup is safe or complete. Establish retention and restore exercises explicitly.
