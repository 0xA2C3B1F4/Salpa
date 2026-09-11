# ESP32-S2 final hardening results

The tested ESP32-S2 completed the final USB ROM-closure acceptance on
2026-09-06. Normal USB FIDO, signed USB updates and failed-candidate fallback
worked afterward. This is functional evidence for one device, not a claim of
resistance to invasive attacks, fault injection or encrypted-state replay.

## Final policy

The retained signing root, flash-encryption key, attestation identity and
credential store were preserved. The final normal image is version `0.1.0`,
security epoch 5, built from source `47fb9cd`. Its signed size is 417,792 bytes.
The separate counter stage had already advanced the hardware floor to 5 and
proved rejection of an original-root-signed epoch-4 application on the device.

Immediately before closure, all 95 eFuse fields and permissions matched the
expected baseline. Both normal images and their separate VALID metadata were
checked through ROM, and a complete encrypted flash snapshot matched the
device. The one separately approved closure change was:

| Field | Before | After | Verification |
| --- | --- | --- | --- |
| `DIS_DOWNLOAD_MODE` | 0 | 1 | Normal firmware status and physical USB ROM-entry attempt |
| `DIS_USB` | 0 | 0 | Normal firmware status and working USB FIDO/update transport |
| `SECURE_VERSION` | raw `0x001f`, floor 5 | unchanged | Normal firmware status |
| `WR_DIS` | `0x01800305` | unchanged | Normal firmware status; shared bit 18 remains clear |

Eleven security-epoch bits remain. Leaving shared write-protection bit 18
clear permits a future separately approved floor increase. The closure bit
itself cannot be cleared. The normal application and read-only bootloader do
not automatically advance the counter.

The closure command's completion alone was not treated as proof. The normal
firmware status, physical USB ROM-entry attempt and functional checks below
establish the result. Detailed operation receipts and original snapshots remain
in private maintenance evidence.

## Checks after closure

- Normal USB enumeration, CTAPHID INIT, fragmented PING and GetInfo passed.
  The firmware's RKS1 status matched the intended closure policy and epoch 5.
- The existing saved credential produced a verified signature with fresh
  GPIO16 approval before the first post-closure update.
- A signed normal image was installed in ota_0 and booted after a full USB
  power cycle. The existing credential still produced valid signatures.
- A signed `0.1.1-ab-fail` epoch-5 candidate was installed in ota_1. Its first
  boot was observed. The next power cycle returned to normal `0.1.0`, and the
  existing credential's signature verified after fallback.
- A signed normal image replaced that test image in ota_1. A power cycle,
  normal FIDO checks and the existing credential's signature passed again.
- An epoch-4 update header was rejected with `rollback` before image transfer
  or erase. This checks the USB admission policy; the independent nonzero-floor
  boot-rejection trial occurred before closure.
- Holding BOOT through RESET did not expose the former USB ROM endpoint.
  A subsequent normal RESET restored USB FIDO, the expected RKS1 policy and
  a working signature with the existing credential.
- A final PIN-protocol-2 assertion verified the existing credential's signature
  and both UV and UP flags. PIN retries were unchanged. No PIN change or
  credential reset was performed.

After closure, full ROM image and metadata readback is no longer available.
The updater verified and activated each installed signed image; runtime and
credential checks then passed. Identical version strings alone do not prove
which slot ran. The guarded updater checked its actual running mapping before
each subsequent installation, including the fallback-to-normal sequence.

## macOS test receiver

After the first update, the stock python-fido2 2.2.1 macOS receiver failed three
assertions. A capture restricted to packet types and lengths showed keepalives
followed by continuation packet 0 without the initial CBOR reply packet.
No credential payloads, tokens or channel identifiers were retained.

Keeping the macOS receive run loop scheduled continuously produced two verified
assertions with the same firmware and credential. The remaining update,
fallback, credential and PIN checks passed with that isolated receiver.
This implicates host receive scheduling; a USB bus analyzer was not used to
locate the loss independently.

`tools/fido2_transport.py` retains this receiver for the host tools. CTAP parsing
and cryptographic verification remain in python-fido2. Host tests cover packet
ordering, reception between reads, bounded timeout, shutdown, startup failure,
reader failure, version gating and descriptor selection. The promoted helper
also passed five live INIT/PING/GetInfo/update-status checks. Those read checks
are separate from the preceding assertions using the isolated equivalent.

## Remaining limits

Physical UART ROM denial was not electrically tested. The all-mode disable
bit is reported set, but the directly tested route is native USB. RKS1 is a
limited status report from the signed firmware, not an independent post-closure
dump of all 95 eFuse fields.

ROM-based flash readback and recovery are lost. Signed application updates and
A/B fallback remain available while a working application and boot metadata
can start. They cannot repair every bootloader, partition-table or dual-image
failure. Existing private backups and original keys remain retained; their
existence does not prove that FIDO credentials can be restored to another chip.

The [physical attack assessment](../design/physical-attack-applicability.md)
still applies. Firmware anti-rollback does not establish FIDO-state freshness.
Physical access sufficient to replay an old valid encrypted state can restore
PIN attempts. No protected mutable retry counter or secure element was added.
An independent tested account login method remains necessary.

See the [hardening plan](../plans/esp32s2-hardening.md) for the approval order,
counter budget and recovery dependencies.
