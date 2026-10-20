# htmx 2.0.10

Vendored on 2026-09-07 from the official bigskysoftware/htmx repository.
The JavaScript and license are unmodified upstream bytes. No CDN is contacted
at runtime, and no build step or Python dependency is needed.

- Upstream: https://github.com/bigskysoftware/htmx
- Exact tag: https://github.com/bigskysoftware/htmx/tree/v2.0.10
- Tag commit (verified through the GitHub refs API): `bdc7d7d3e25d0390c7ee11049806e8279b075598`
- JavaScript: https://raw.githubusercontent.com/bigskysoftware/htmx/bdc7d7d3e25d0390c7ee11049806e8279b075598/dist/htmx.min.js
- License: https://raw.githubusercontent.com/bigskysoftware/htmx/bdc7d7d3e25d0390c7ee11049806e8279b075598/LICENSE
- License identifier: BSD-0-Clause (Zero-Clause BSD); full text in `LICENSE`.

SHA-256 checksums:

```text
71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de  htmx.min.js
d3d2456f76414f2456104660ebd65aff1c04cd7966b942bdabd63f3cdb316a38  LICENSE
```

The JavaScript SHA-384 also matches the integrity value published in the
[upstream README](https://github.com/bigskysoftware/htmx/blob/v2.0.10/README.md):
`sha384-H5SrcfygHmAuTDZphMHqBJLc3FhssKjG7w/CeCpFReSfwBWDTKpkzPP8c+cLsK+V`.

Verify locally with PowerShell:

```powershell
Get-FileHash static/vendor/htmx/htmx.min.js,static/vendor/htmx/LICENSE -Algorithm SHA256
```

`templates/base.html` loads htmx before page scripts and supplies Django's CSRF
header on the body. History snapshots are disabled: Back/Forward cache misses
perform full page navigation, refreshing authentication, CSRF and filter state.
`historyRestoreAsHxRequest` is also false, consistent with full-page restoration.
`static/js/htmx-support.js` provides generic, dismissible error feedback without
rendering response text and turns login expiration into full login navigation.
