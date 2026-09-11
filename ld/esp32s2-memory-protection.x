/* The first 32 KiB of SRAM has coarse PMS permissions. Keep all mutable
   application data above it and use the fine-grained split for the rest.
   IRAM and DRAM are aliases of the same SRAM, offset by 0x70000. */
_salpa_pms_iram_end = ABSOLUTE(MAX(ADDR(.rwtext.wifi) + SIZEOF(.rwtext.wifi), 0x40028000));

.salpa.pms.dram_alias_reservation (NOLOAD) : ALIGN(4) {
  . = MAX(ABSOLUTE(.), _salpa_pms_iram_end - 0x70000);
} > RWDATA
