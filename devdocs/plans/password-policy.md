# Purpose

Apply the requested shorter manual-password policy consistently to account
creation, administrator resets, self-service changes and initial credential
creation. Preserve current credentials, login, session authentication, hashing,
roles, CSRF and rate limiting.

# Rules and compatibility

- At least eight Unicode code points and at most 1,024 UTF-8 bytes.
- ASCII lowercase letter, ASCII digit and printable ASCII punctuation required.
- Eight or nine characters additionally require an ASCII uppercase letter.
- Ten or more characters may include uppercase but do not require it.
- Printable ASCII punctuation is U+0021..U+002F, U+003A..U+0040,
  U+005B..U+0060 or U+007B..U+007E. Spaces and Unicode symbols do not satisfy
  this requirement; other valid Unicode characters may be additional content.
- Additional whitespace does not satisfy the punctuation class and is not
  otherwise prohibited. Invalid UTF-8 is rejected by the common validator.
  Existing CR/LF rejection remains only in the one-line initial-password file writer.

New values only are validated. Existing hashes never encode password composition,
so credentials loading and password verification must not apply the new rules.
The current-password UI field likewise performs no new-policy check. A legacy
password may authenticate and be replaced by a new compliant password normally.
No migration or forced password/session rotation occurs during package upgrade.

# Design

A small Go policy module owns the new-password check and fixed Korean guidance.
GenerateCredentials and WriteInitialPassword call the same validator. Generated
initial passwords retain the existing 24 random bytes (192 bits), with a fixed
composition suffix rather than reducing random entropy or assuming base64
always contains a digit and punctuation.

The account dialogs use equivalent JS code-point and UTF-8-byte checks and
native new-password input constraints, with visible Korean help. Current/login
inputs keep their previous compatibility behavior. HTTP creation and both reset
paths return the same safe policy guidance without echoing a supplied value.

# Validation and delivery

Test lengths 7/8/9/10, each composition requirement, Unicode/astral length,
spaces versus punctuation, UTF-8 byte limit and exact 1,024-byte values,
initial generator output and legacy verification/current-password replacement.
Exercise account creation/admin reset/self-change, session invalidation after
an actual change, role/CSRF/rate limits and UI/API policy agreement.

Run the existing full verify suite and a static Central RPM15 build. Deployment
must preserve the complete protected state and account credential/session
material. The parent agent performs reviewed source publication and live rollout;
this work does not reset a production account or print credentials.
