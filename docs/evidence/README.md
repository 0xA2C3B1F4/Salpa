# Evidence index

Evidence is scoped to its source revision, hardware profile, and test method.
An older record keeps the state observed at that time. It does not override a
later acceptance result or authorize another device operation.

| Capability | Evidence | Scope |
| --- | --- | --- |
| Public alpha host and build checks | [Source validation](public-source-alpha-20260905.json) | Clean export, public compile fixtures, refactor equivalence and fresh advisory scan; no hardware action |
| Secure Boot V2 enforcement | [Provisioning and readback](secure-boot-v2-esp32s2-0d295e8.json) | Authorized hardware stage; later normal operation is recorded separately |
| Protected S2 normal boot, persistence, signed USB update, rollback, and ROM recovery | [Protected acceptance](protected-ota-esp32s2-20260905.json) | Physical second test device; complete write readbacks and the same test credential |
| Attestation import and recovery | [Import acceptance](attestation-import-esp32s2-20260905.json) | New development identity explicitly authorized by its owner; existing firmware signing and flash keys preserved |
| Protected browser authentication | [OpenAI owner report](openai-protected-esp32s2-20260905.json) | Chrome enrollment and Safari login reported by the owner; PIN and physical button required |
| Local maintainer key custody | [macOS Keychain checks](key-management-macos-20260905.json) | Host authentication, ACLs, signing, encryption and backup tests; not a hardware secure element |
| GPIO16 presence | [Dedicated button test](non-strapping-up-esp32s2-3001ce9.json) | Disposable development device; GPIO0 rejected as normal presence |
| Development USB update fault handling | [USB acceptance](usb-signed-update-esp32s2-0121171.json) | Unencrypted development profile; do not extend its power-cut coverage to protected electrical fault resistance |
| Earlier signed A/B boot selection | [A/B acceptance](signed-ab-esp32s2-0f5bd51.json) | Reversible development profile without eFuse-enforced Secure Boot |
| Initial protected package preparation | [Preflight](protected-preflight-esp32s2-fe17f88.json) and [audited rebuild](protected-preflight-esp32s2-0d295e8.json) | Host packaging and read-only device checkpoints |
| Encrypted DROM mapping diagnosis | [Diagnosis and later checkpoint](encrypted-drom-diagnosis-20260905.json) | Historical failure analysis with links to the completed acceptance |

The repeatable host suites cover CTAPHID and update state machines, storage
faults, persistent FIDO state, backup checks, and export policy. CI additionally
checks the exported tree, S2/S3 linking, and macOS helper crypto fixtures. A CI
job definition is not evidence of a successful run; check the run on the exact
published commit.

Open work includes an OpenAI login after a fresh USB power cycle on the
protected device, a complete physical S3 acceptance, controlled electrical
brownout/fault testing, independent security review, and final ROM policy.
No record here establishes FIDO certification, secure-element protection,
hardware anti-downgrade, or resistance to replay of old credential storage.
