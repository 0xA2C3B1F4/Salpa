/* Keep fixed decrypted-read mappings outside the application's DROM segment. */
ASSERT(_rodata_end <= 0x3f390000,
       "application rodata overlaps release flash-encryption mappings");
