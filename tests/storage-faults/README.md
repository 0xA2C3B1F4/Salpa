# Persistent-storage fault tests

This host-only crate runs RissoKey's production `mount_existing` and storage
version checks against `littlefs2` 0.8.1. Its in-memory NOR model uses the
device partition's 4 KiB block size, 32-block capacity, four-byte program size,
and erased value `0xff`.

The tests cover:

- unformatted and fully corrupt storage;
- one corrupt superblock and both corrupt superblocks;
- a wrong storage version marker;
- an I/O failure at every read used by normal startup;
- interruption at every flash operation used to create the version marker;
- interruption at every program and erase operation in a record update that
  triggers littlefs garbage collection.

Each interrupted program or erase is tested before any bytes change, after an
aligned half-operation, and after the whole operation changes flash but still
returns an error. Normal startup must leave the complete flash image unchanged
after every mount, read, version, or corruption failure. A record update may
recover either its old or new complete value, never a partial value.

Run the pinned harness without using the firmware's Xtensa Cargo configuration:

```sh
./tools/test-storage-faults
```

Build output follows `CARGO_TARGET_DIR` when set and otherwise goes under
`$TMPDIR`. These tests exercise the real littlefs C implementation through
`littlefs2`, but the NOR device is a software model. They do not replace a
controlled physical brownout test of ESP flash.
