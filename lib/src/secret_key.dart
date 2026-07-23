/// A type-safe identifier for a stored secret.
library;

/// A logical identifier for a stored secret.
///
/// A zero-cost wrapper over a [String] so secret keys cannot be accidentally
/// swapped with arbitrary strings elsewhere in an app.
///
/// ```dart
/// const pin = SecretKey('payment_pin');
/// await security.write(key: pin, value: '1234', policy: SecurityPolicy.strong());
/// ```
extension type const SecretKey(String value) {
  /// The underlying storage key string.
  String get raw => value;
}
