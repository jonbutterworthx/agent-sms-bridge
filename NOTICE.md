# Provenance and dependencies

Agent SMS Bridge is an independently implemented Python client/service for the
SMSGate Local Server HTTP API. Its Python implementation and setup page were
prepared for this project from the maintainer's original service. API behavior
was checked against upstream SMSGate Android source for version 1.78.3.
No Android source code, application, assets or upstream documentation is bundled.
SMSGate is a separate project; no affiliation or endorsement is claimed.

Python standard-library modules are imported, not vendored. There are no runtime
third-party Python dependencies. Setuptools is external build tooling. Build tools are not relicensed or
redistributed as part of this source. No vendored third-party code requiring
an additional bundled notice was identified in the candidate review.

Copyright is attributed to jonbutterworthx. See LICENSE for the MIT terms.
