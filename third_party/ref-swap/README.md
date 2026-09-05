<!--
Copyright (C) 2023 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

Ref-Swap
========

Safe wrapper around [`AtomicPtr`](https://doc.rust-lang.org/core/sync/atomic/struct.AtomicPtr.html).
Instead of swapping a pointer, it works with references and lifetimes, allowing a safe API.
Two versions are provided:
- [`RefSwap`](https://docs.rs/ref-swap/latest/ref_swap/struct.RefSwap.html) for swapping references
- [`OptionRefSwap`](https://docs.rs/ref-swap/latest/ref_swap/struct.OptionRefSwap.html) for swapping `Option<&T>`.
[`OptionRefSwap`](https://docs.rs/ref-swap/latest/ref_swap/struct.OptionRefSwap.html) encodes `None` as a null pointer and has no additionnal overhead.

With references
---------------

```rust
use ref_swap::RefSwap;
use core::sync::atomic::Ordering;

let a = 10;
let b = 20;
let reference = RefSwap::new(&a);

// In another thread
let loaded = reference.load(Ordering::Relaxed);
assert_eq!(loaded, &a);
assert!(core::ptr::eq(loaded, &a));

reference.store(&b, Ordering::Relaxed);

// In another thread
let loaded = reference.load(Ordering::Relaxed);
assert_eq!(loaded, &b);
assert!(core::ptr::eq(loaded, &b));
```

With optionnal references
-------------------------


```rust
use ref_swap::OptionRefSwap;
use core::sync::atomic::Ordering;

let a = 10;
let b = 20;
let reference = OptionRefSwap::new(None);

// In another thread
let loaded = reference.load(Ordering::Relaxed);
assert_eq!(loaded, None);

reference.store(Some(&b), Ordering::Relaxed);

// In another thread
let loaded = reference.load(Ordering::Relaxed);
assert_eq!(loaded, Some(&b));
assert!(core::ptr::eq(loaded.unwrap(), &b));

reference.store(Some(&a), Ordering::Relaxed);

// In another thread
let loaded = reference.load(Ordering::Relaxed);
assert_eq!(loaded, Some(&a));
assert!(core::ptr::eq(loaded.unwrap(), &a));
```

## License

This project is licensed under the [GNU Lesser General Public License (LGPL)
version 3][LGPL-3.0].  Configuration files and examples are licensed under the
[CC0 1.0 license][CC0-1.0].  For more information, see the license header in
each file.  You can find a copy of the license texts in the
[`LICENSES`](./LICENSES) directory.

[LGPL-3.0]: https://opensource.org/licenses/LGPL-3.0
[CC0-1.0]: https://creativecommons.org/publicdomain/zero/1.0/

This project complies with [version 3.0 of the REUSE specification][reuse].

[reuse]: https://reuse.software/practices/3.0/
