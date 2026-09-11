/* Based on esp-hal 1.1.2 linkall.x and esp32s2.x (MIT option).
   Keep the vendor section layouts, replacing only its SRAM alias reservation
   with the PMS-aware reservation before .data. */
INCLUDE "memory.x"
INCLUDE "alias.x"
INCLUDE "exception.x"
INCLUDE "fixups/rtc_fast_rwdata_dummy.x"
SECTIONS {
  INCLUDE "rwtext.x"
  INCLUDE "esp32s2-memory-protection.x"
  INCLUDE "rwdata.x"
}
INCLUDE "rodata.x"
INCLUDE "text.x"
INCLUDE "rtc_fast.x"
INCLUDE "rtc_slow.x"
INCLUDE "stack.x"
INCLUDE "dram2.x"
INCLUDE "metadata.x"
INCLUDE "eh_frame.x"
INCLUDE "hal-defaults.x"

ASSERT(_data_start == _salpa_pms_iram_end - 0x70000,
       "PMS code/data SRAM aliases do not meet at the same boundary");
ASSERT(_salpa_pms_iram_end >= 0x40028000 && _salpa_pms_iram_end < 0x40050000,
       "PMS split outside supported application SRAM");
ASSERT(SIZEOF(.rtc_fast.text) == 0 && SIZEOF(.rtc_slow.text) == 0,
       "PMS profile requires non-executable RTC memory");
