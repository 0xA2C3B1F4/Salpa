# Physical-attack applicability before ROM closure

This 2026-09-06 review covers published sources, package structure and retained
device records. It is not a physical attack test. No board probing, power-trace
capture, flash emulation, fault injection, package opening or device write was
performed for this assessment. Earlier functional and power-cut evidence keeps
its original scope.

## Target and flash access

The retained ROM identification reports `ESP32-S2FNR2`, silicon revision 1.0,
4 MB embedded flash and 2 MB embedded PSRAM. The installed esptool 5.4 uses
that shortened name. These capabilities match the manufacturer's
ESP32-S2FN4R2 variant; the marketing name alone is not the identification.

The [S2 datasheet v1.9][datasheet], sections 1.2, 2.3.5, 2.6 and figure 7-2,
documents in-package memory and QFN56 terminals. The flash interface is not
documented as an entirely internally terminated, inaccessible bus:

| Signal | Package terminal | Role |
| --- | ---: | --- |
| SPICS0 | 33 | Flash chip select |
| SPICLK | 34 | Memory clock |
| SPIQ / SPID | 35 / 36 | Flash data |
| SPIHD / SPIWP | 31 / 32 | Additional quad-SPI data |
| SPICS1 | 29 | PSRAM select, distinct from flash select |
| VDD_SPI | 30 | Memory/interface supply |

The [WEMOS S2 Mini page][wemos] specifies FN4R2, while its
[v1.0.0 reference schematic][schematic] labels U1 as S2FH4. On that drawing,
SPI signals 29 and 31–36 are marked unconnected externally, not routed to the
headers. VDD_SPI has local decoupling. Header labels SCK/MISO/MOSI refer to
other GPIOs, not these flash signals. The reference drawing cannot establish
the actual specimen's routing or solder-pad accessibility.

Conclusion: in-package flash removes an ordinary separate flash-chip target,
but does not justify assuming this package's memory bus is inaccessible.
Package-terminal access and practical control of a bus shared with internal
memory are different prerequisites. Neither observation nor replacement of
that bus has been demonstrated on this specimen. A subsequent non-invasive
visual inspection could not resolve the board or package markings. The exact
board revision, visible-pad routing and shielding therefore remain unverified;
retain the conservative package-access assumption. No probing or modification
was performed to resolve this uncertainty.

## What the cited sources establish

| Source | Demonstrated targets and prerequisite | S2 assessment |
| --- | --- | --- |
| [AR2022-003 V2.0][ar2022], issued 2022-11-18, pp. 1–5 | Reports Ledger's ESP32 revision 3.0 hardware-AES/flash work. Power analysis needs physical measurement; body-bias injection additionally needs die access. | The advisory explicitly lists S2 among potentially affected families. XTS-AES increases difficulty; it is not an immunity claim. The cited experiments do not demonstrate the same result on this S2 revision. |
| [AR2023-007 V1.0][ar2023], issue date 2024-01-05, pp. 1–3 | Reports C3/C6 attacks combining CPA, controlled encrypted boot data, voltage faults and ROM exploitation. Its CPA result concerns a block's key/tweak information, not automatic recovery of the entire XTS key set. | Names S2 among theoretical XTS-AES CPA targets. The complete chain depends on each family's ROM. C3/C6 code-execution results are not S2 evidence. The retrieved advisory reports no fix for the described issue. |
| [Kévin Courdesses, Breaking the Flash Encryption Feature of Espressif's Parts][courk] | Reports experiments on ESP32, C3 and C6, using a custom power-measurement setup, controlled boot ciphertext through FPGA fake flash, and repeated resets. For C3/C6 the reported CPA work recovers enough information for a particular 128-byte block. | No S2 experiment is reported in this article. Its related secure-boot bypass is a distinct step. Similar XTS architecture motivates investigation; it does not establish this board's leakage model, required samples or successful ROM exploit. |

None of these requested sources supplies a demonstrated complete attack on
this S2 board. That is an evidence limit, not a conclusion that S2 is safe.
The advisory's internally terminated SiP example must not be generalized to
every part advertised as having embedded flash. Do not transplant C6 masking
or glitch-detection claims to S2, or assume revision 1.0 fixes these attacks
without S2-specific evidence.

Do not derive a Salpa compromise time from any reported measurement count,
capture duration, analysis duration or equipment cost. No such time or cost
has been measured or estimated here. Do not multiply a per-block result by
the flash size to predict a complete compromise either: execution compromise
and state replay have different prerequisites.

## Effect of the current and proposed protections

Retained complete eFuse evidence records Secure Boot enabled, encrypted flash,
hard-disabled JTAG and disabled download cache/manual-encryption functions.
Full ROM download was available during this source review, and the hardware
security-version floor was zero. The subsequent separately authorized counter
transaction advanced it to five; independent capture confirmed all 95 eFuse
fields and permissions, with only `SECURE_VERSION` changed. Both current normal
images also use epoch five. The subsequent physical trial rejected a correctly
signed epoch-four image with higher VALID metadata and retained the epoch-five
fallback; see
the [current hardening evidence](../plans/esp32s2-hardening.md). Final closure
then set `DIS_DOWNLOAD_MODE`; physical native-USB ROM entry was blocked while
normal FIDO and signed updates remained usable. Physical UART denial was not
electrically tested. The complete pre-closure eFuse capture remains preserved;
an independent full ROM readback is no longer available after closure.

| Protection | What it contributes | What it does not establish |
| --- | --- | --- |
| Device-specific flash key and encrypted storage | Confidentiality against an ordinary raw read; limits reuse of one device's flash secret | Resistance to leakage or fault-assisted extraction from this device |
| Secure Boot and signed updates | Reject unauthorized executable images in normal execution | Correct verification under a successful physical fault attack |
| Hardware epoch floor 5; signed epoch-4 rejection demonstrated on this device | Enforces the minimum application epoch under the tested boot policy | FIDO-state freshness, side-channel resistance or a universal old-bootloader barrier |
| Hard-disabled JTAG and download closure; native-USB denial tested | Remove the tested debug and ROM command access paths | UART electrical qualification, or disabling normal SPI boot and its flash decryption |
| Fresh GPIO16 presence and PIN controls | Enforce normal protocol authorization | An attacker in physical possession cannot manipulate the button, bypass software with faults, or replay old state |
| Mac Keychain custody or a future approval application | Controls the host's own key-use and permitted tool path | Protects on-device AES activity or stops a writer that bypasses the host |

For the cited attack class, access to a suitable measurement point, repeatable
boot activity and control of relevant ciphertext are substantive prerequisites.
The package and reference schematic do not establish that these are absent.
Closing download mode does not stop normal encrypted SPI boot and therefore
must not be credited as closing every physical CPA or boot-fault route.
No application delay or dummy operation has been shown to protect the ROM's
earlier cryptographic activity. No new noise or tamper-wipe code is added.

Keep the [old-state replay threat][pin-state] separate. Replaying valid
ciphertext at its original location can reset PIN attempts without recovering
the flash key or bypassing firmware signature verification. Direct credential
key extraction is more serious still; a long random PIN does not protect keys
after extraction. Neither outcome has been demonstrated physically here.

## Risk decision and closure criteria

Treat a capable physical attacker as an unresolved, potentially high-impact
threat. Do not advertise resistance to these techniques on the strength of
encryption, package integration, a green software suite or closed download
mode. Continue the functional hardening work for its demonstrated benefits.

Before requesting final ROM closure:

1. Bind the current chip/revision and fresh complete eFuse readout to private
   evidence. Keep current, proposed and actually programmed policy distinct.
2. Compare the actual board markings and visible layout with the reference
   schematic. Record flash-terminal and supply accessibility as observed,
   inferred or unknown. Until verified, conservatively assume a skilled
   attacker may obtain package-level access. Do not substitute a different
   S2 Mini revision or an internally terminated SiP's properties.
3. Include separate rows for raw ROM replay, physical valid-state replay,
   side-channel extraction and boot fault injection in the immediate approval
   sheet. Record which path each proposed eFuse closes and which remains.
4. Complete the already required A/B, signature, epoch-floor, credential and
   power-cut checks. Then test denial on applicable ROM transports while
   confirming normal USB operation. These remain functional tests, not CPA
   or fault-injection qualification.
5. Obtain the device operator's explicit decision on residual physical risk and loss of
   recovery before the exact irreversible approval. If resistance to this
   attacker is required, defer that acceptance and assess hardware with a
   suitable protected execution/state boundary and independent physical
   evaluation. A secure element must enforce key use and retry policy; simply
   attaching a signing chip is insufficient.

A tamper-resistant enclosure or protected bus routing could increase access
cost, but no such construction is qualified here. Preserve original keys,
attestation, credentials and backups. Do not add automatic secret deletion as
an unreviewed response to tampering. Independent account recovery is a loss
mitigation, not proof against credential compromise.

The [final native-USB ROM-policy tests](../testing/esp32s2-final-hardening.md)
passed on 2026-09-06, with normal FIDO, signed updates and fallback preserved.
Physical UART denial was not electrically tested. Actual-board markings remain
unreadable, routing is unverified, and physical attack resistance remains open.

[datasheet]: https://www.espressif.com/sites/default/files/documentation/esp32-s2_datasheet_en.pdf
[wemos]: https://www.wemos.cc/en/latest/s2/s2_mini.html
[schematic]: https://www.wemos.cc/en/latest/_static/files/sch_s2_mini_v1.0.0.pdf
[ar2022]: https://www.espressif.com/sites/default/files/advisory_downloads/AR2022-003%20Security%20Advisory%20Concerning%20Breaking%20the%20Hardware%20AES%20Core%20and%20Firmware%20Encryption%20of%20ESP32%20Chip%20Revision%20v3.0%20-%20V2.0%20EN.pdf
[ar2023]: https://www.espressif.com/sites/default/files/advisory_downloads/AR2023-007%20Security%20Advisory%20Concerning%20Bypassing%20Secure%20Boot%20and%20Flash%20Encryption%20using%20CPA%20and%20FI%20attack%20on%20ESP32-C3%20and%20ESP32-C6%20EN.pdf
[courk]: https://courk.cc/breaking-flash-encryption-of-espressif-parts
[pin-state]: ../development/pin-token-security.md
