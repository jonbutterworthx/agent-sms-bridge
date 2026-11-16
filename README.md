# Agent SMS Bridge

Connect an application or agent to an Android phone running SMSGate Local Server.
Agent SMS Bridge keeps observed SMS in SQLite and exposes a private API with
explicit recipient permissions. It works without an AI provider, hosted messaging
service, or particular VPN or backup vendor.

**0.1.0rc1 is a local review candidate, not a published release.** Intended
repository: `jonbutterworthx/agent-sms-bridge`. Licensed under [MIT](LICENSE); see [provenance](NOTICE.md).

- Durable intake and history, with cursor recovery and duplicate suppression.
- Scoped API tokens, explicit international numbers, and per-number blocking.
- Idempotent submissions; uncertain phone submissions are never blindly resent.
- Conservative delivery status and a required check before treating incoming
  text as complete.
- Private configuration, local SQLite snapshots, and isolated restore checks.
- Optional temporary setup form or a JSON/CLI route using the same validation.

Requires Python 3.11+ on a Unix-like host and a reachable private SMSGate API.
Local package tests cover Python 3.13/Linux; the adapter contract was reviewed
against SMSGate 1.78.3. Other app versions need renewed verification. Use verified
HTTPS or an encrypted private tunnel to the phone; a private IP alone does not
encrypt credentials or messages.

Start with [installation and setup](docs/INSTALL.md), then [API examples](docs/API.md).
Review [security and provider limits](SECURITY.md) and [recovery](docs/RECOVERY.md)
before enabling sends. Polling is configurable from 10–3600 seconds, default 60;
each poll completes before its next interval starts.

There is no ongoing inbox dashboard, automatic reply engine, RCS/MMS support,
contact import or supported webhook interface. Only observed SMS is covered;
upstream loss and ambiguous delivery cannot always be resolved.

## Runtime dependencies

The runtime uses Python's standard library. Setup JavaScript and CSS are bundled
in the package and served locally. Network calls go to the configured SMSGate
endpoint for polling, submission and status checks. There is no telemetry, CDN,
AI provider or other runtime service by default. The setup page links to the
SMSGate documentation; opening that link is a separate browser action.

Package installation and build tooling may download files. Keep build inputs
pinned for deployment and review any new dependency or network destination.

## Local tests and packaging

Run the synthetic source tests:

```sh
python3 -B -m unittest discover -s tests -v
```

Tests use disposable data and loopback mock servers. They do not contact a phone
or send SMS. Coverage includes authentication and recipient permissions, duplicate
observations, idempotency, ambiguous sends, restart/restore behavior, setup
authorization and safe defaults. Polling checks cover the integer interval bounds
and sequential scheduling after slow successful or failed requests.

Build a source distribution and wheel in a separate environment:

```sh
python3 -m venv .venv-build
.venv-build/bin/python -m pip install build
.venv-build/bin/python -m build
```

Then test the installed wheel outside the source directory:

```sh
test_dir=$(mktemp -d)
python3 -m venv "$test_dir/venv"
"$test_dir/venv/bin/python" -m pip install --no-deps dist/agent_sms_bridge-0.1.0rc1-py3-none-any.whl
cp -R tests "$test_dir/tests"
(
  cd "$test_dir"
  env -u PYTHONPATH "$test_dir/venv/bin/python" -I -B -m unittest discover -s tests -v
  "$test_dir/venv/bin/python" -I -c 'import communications; print(communications.__file__)'
  "$test_dir/venv/bin/agent-sms-bridge-setup" --help
)
```

The printed module path must be inside the temporary environment's site-packages.
Keep generated data and environments out of source control. CLI setup validation
should write nothing without `--apply`; saving synthetic setup must leave outbound
sending and complete-content verification disabled and refuse an overwrite.

Local verification covers Python 3.13 on Linux aarch64. Python 3.11 and 3.12 are
supported by the package metadata but have not been tested locally. Hosted CI is
intentionally absent. Synthetic tests do not establish physical-phone behavior,
carrier delivery or complete incoming content on another SMSGate installation.
