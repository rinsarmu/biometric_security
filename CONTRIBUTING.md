# Contributing to biometric_security

Thanks for your interest! This is a security-critical package, so contributions
are held to a high bar for correctness, testing, and honesty about limitations.

## Ground rules

- **Never weaken the security defaults** without an explicit, reviewed rationale.
- **Never** log secrets or keys, persist keys in plaintext, implement custom
  cryptography, or return plaintext on a failure path.
- Prefer the platform's secure hardware (Keystore / Keychain + Secure Enclave);
  the hardware key must never cross the platform channel.
- Be honest in docs and comments — if something is not crash-safe, not tested on
  device, or a platform limitation, say so.

## Development setup

```bash
flutter pub get
flutter analyze          # must be clean
flutter test             # Dart unit tests
dart format .            # formatting is required
```

Native tests:

```bash
cd example/android && ./gradlew :biometric_security:testDebugUnitTest   # Kotlin
# iOS: run the "RunnerTests" scheme in Xcode, or via xcodebuild test
```

Build both example apps before submitting native changes:

```bash
cd example && flutter build apk --debug
cd example && flutter build ios --no-codesign
```

## Pull requests

1. Open an issue first for anything non-trivial.
2. Keep changes focused; one concern per PR.
3. Add or update tests — especially for cryptography, key lifecycle, and failure
   paths. New security-relevant behavior needs a test that proves it.
4. Update `CHANGELOG.md` and any affected docs
   (`ARCHITECTURE.md`, `STORAGE.md`, `SECURITY_AUDIT.md`, `README.md`).
5. Ensure `flutter analyze`, `flutter test`, and `dart format --set-exit-if-changed .`
   all pass.
6. Match the surrounding code style, naming, and comment density.

## Reporting security issues

Do **not** use public issues for vulnerabilities — follow
[`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
project's BSD 3-Clause [`LICENSE`](LICENSE).
