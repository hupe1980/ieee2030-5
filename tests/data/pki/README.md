# Certificate fixtures

The offline profile tests use the public DER certificates below. The private keys were discarded. Tests set the verification time explicitly so results are reproducible.

| File | Purpose |
| --- | --- |
| `root.der`, `issuer.der`, `device.der` | Valid manufacturing chain for a generic device. The issuing CA permits no subordinate CAs. |
| `wrong-curve.der` | P-384 leaf where the profile requires P-256. |
| `wrong-usage.der` | Leaf with only key encipherment usage. |
| `wrong-policy.der` | Leaf with an administration policy. |
| `unauthorized-class.der` | Individually valid mobile-device leaf whose issuer can authorize only generic devices. |
