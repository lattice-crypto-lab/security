# Test fixtures

Fixtures are small, stable inputs shared by contract and integration tests.
They are not runtime cache entries and are never loaded by the deployed
services.

- `examples/` contains representative public requests and import/export files.
  Tests use them to verify JSON round trips and exercise the same payloads a
  user can submit.
- `schema/valid/` contains the smallest accepted public document.
- `schema/invalid/` pins important rejection boundaries and their error paths,
  such as cross-variant fields, exponent notation, invalid fixed weights, and
  missing ring-reduction declarations.

Keep a fixture only when multiple tests or a public example benefit from a
named, reviewable input. One-off values belong directly in the test that uses
them.
