from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "build_signed_ab_bootloader", ROOT / "tools/build-signed-ab-bootloader.py"
)
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class ReadOnlyEfuseTests(unittest.TestCase):
    def test_actual_guards_never_change_the_counter(self) -> None:
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "a C compiler is required for the eFuse guard test")
        with tempfile.TemporaryDirectory(prefix="salpa-efuse-guard-") as temporary:
            work = Path(temporary)
            (work / "sdkconfig.h").write_text(
                "#define CONFIG_RISSOKEY_EFUSE_READ_ONLY 1\n"
                "#define CONFIG_IDF_TARGET_ESP32S2 1\n"
                "#define CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK 1\n"
                "#define CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD 16\n"
            )
            (work / "esp_err.h").write_text(
                "typedef int esp_err_t;\n"
                "#define ESP_OK 0\n"
                "#define ESP_ERR_NOT_SUPPORTED 0x106\n"
            )
            (work / "esp_efuse.h").write_text(
                "#include <stdint.h>\n"
                "uint32_t esp_efuse_read_secure_version(void);\n"
            )
            (work / "main.c").write_text(
                r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

static uint32_t counter;
uint32_t esp_efuse_read_secure_version(void) { return counter; }
int __wrap_esp_efuse_update_secure_version(uint32_t version);
int __wrap_esp_efuse_utility_burn_chip_opt(bool ignore, bool verify);

int main(void)
{
    for (uint32_t floor = 0; floor <= 16; ++floor) {
        counter = floor;
        for (uint32_t request = 0; request <= 17; ++request) {
            int result = __wrap_esp_efuse_update_secure_version(request);
            assert((result == 0) == (request == floor));
            assert(counter == floor);
        }
        assert(__wrap_esp_efuse_update_secure_version(UINT32_MAX) != 0);
        for (int ignore = 0; ignore <= 1; ++ignore) {
            for (int verify = 0; verify <= 1; ++verify) {
                assert(__wrap_esp_efuse_utility_burn_chip_opt(ignore, verify) != 0);
                assert(counter == floor);
            }
        }
    }
    return 0;
}
"""
            )
            source = ROOT / (
                "security/esp-idf-bootloader/bootloader_components/main/read_only_efuse.c"
            )
            executable = work / "guard-test"
            command = [
                compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(work), str(source), str(work / "main.c"),
                "-o", str(executable),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            subprocess.run([str(executable)], check=True)

            # A truncated counter or missing check must fail at compile time.
            config = work / "sdkconfig.h"
            original = config.read_text()
            for unsafe in (
                original.replace("EFUSE_FIELD 16", "EFUSE_FIELD 4"),
                original.replace("ANTI_ROLLBACK 1", "ANTI_ROLLBACK 0"),
            ):
                config.write_text(unsafe)
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)

    @patch.object(BUILD.shutil, "which", return_value="target-nm")
    @patch.object(BUILD.subprocess, "run")
    def test_link_check_rejects_real_writers_or_missing_guards(self, run, _which) -> None:
        symbols = {
            "__wrap_esp_efuse_update_secure_version",
            "__wrap_esp_efuse_utility_burn_chip_opt",
            "esp_efuse_check_secure_version",
            "esp_efuse_read_secure_version",
        }

        def validate(selected: set[str]) -> None:
            run.return_value = subprocess.CompletedProcess(
                [], 0, stdout="\n".join(f"40000000 T {name}" for name in selected)
            )
            BUILD.validate_linked_efuse_policy(Path("bootloader.elf"), dict(os.environ))

        validate(symbols)
        for writer in (
            "esp_efuse_update_secure_version",
            "esp_efuse_utility_burn_chip_opt",
            "efuse_hal_program",
        ):
            with self.assertRaises(BUILD.BuildError):
                validate(symbols | {writer})
        for missing in symbols:
            with self.assertRaises(BUILD.BuildError):
                validate(symbols - {missing})


if __name__ == "__main__":
    unittest.main()
