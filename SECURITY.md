# Security and limits

Contact the maintainer through an existing private channel to arrange a security
report. If you do not have one, request a private contact route without including
vulnerability details. Do not post credentials, phone numbers, message bodies or
private logs in an issue. Include the affected version, a minimal synthetic
reproduction, impact and sanitized metadata in the private report.

This project is in a private-repository phase. GitHub's private vulnerability
reporting is available for public repositories, so it is not the reporting route
here. See [GitHub's reporting documentation](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories).

The local OS account and root can read private state. The service is not a sandbox for malicious code running as that account. Use protected directories, separate revocable client tokens and explicit number scopes. Credentials must stay outside source control. Browser origins are rejected by the API; the optional initial form is loopback-only with a private one-time code, CSRF and strict Origin/Host checks.

HTTP Basic credentials and SMS content are plaintext at the HTTP layer. A private IP alone does not encrypt transport. Use verified HTTPS or an encrypted private tunnel to the phone; never disable certificate verification. Protect the phone's existing LAN listener separately. An encrypted host-to-phone connection does not make carrier SMS end-to-end encrypted, prove sender identity, or remove any other listener.

The service has no automatic agent execution or response logic. Phone-number permission is not authority for account changes, financial actions or other sensitive operations. Unknown/blocked messages are retained silently; contact association grants no permission.

Provider limits:

- Only observed SMS is covered. No claim for RCS, MMS, deleted/unobserved messages, or messages sent outside this service.
- Verified behavior is specific to SMSGate 1.78.3. Its `contentPreview` was found to contain full SMS text for that version, but every installation must verify actual long/multipart collection before enabling complete-content history.
- The Android provider's 32-bit deduplication hash can suppress messages before this service observes them. Polling cannot distinguish two occurrences whose observable identity fields are all identical. Distinct timestamps and other observed identity fields are retained; no claim of perfect losslessness.
- Polling (10–3600 seconds, default 60) with overlap and durable cursors cannot recover data already pruned on the phone, out-of-window late inserts, or upstream collisions. Monitor the phone's background operation and retention.
- An ambiguous provider submission is never automatically resent. This may require manual resolution of an operation that did not actually send, in preference to risking a duplicate.
- Aggregate multipart Delivered is partial/unquantified evidence. Verify actual recipient receipt separately.
- Webhooks are unsupported in this release candidate. Dormant internal code and synthetic tests are not evidence of an exposed, configured or verified webhook service.

Automated tests and privacy scans are useful evidence, not a complete security audit. Physical-device behavior, carrier delivery, filesystem access and recovery policies need deployment-specific verification.
