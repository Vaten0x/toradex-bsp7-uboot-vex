# Patches

`CVE-2026-29007-29008-backport-v2024.07.patch` is for U-Boot code that the **stock** `verdin-imx8mp_defconfig` does not build. Use it only if you enable the feature. It is a `git format-patch` file against `u-boot-toradex` `3f772959` + the BSP 7.8.0 recipe patches. Apply it with `git am` or as an ordinary Yocto `SRC_URI` patch.

License: GPL-2.0-only, the license of the U-Boot file it modifies (see `../LICENSE`).

| File | Use it when | What it does | Test status |
|---|---|---|---|
| `CVE-2026-29007-29008-backport-v2024.07.patch` | `CONFIG_CMD_WGET`, `CONFIG_PROT_TCP` or `CONFIG_TCP_FUNCTION_FASTBOOT` is enabled | Adapts upstream `a0e2935a4bde` ("net: tcp: drop segments with an invalid data offset") and `cf248526dbd1` ("net: tcp: check option lengths in tcp_parse_options()"), both first in v2027.01-rc3, to the pre-rework TCP stack in `net/tcp.c`. Neither upstream commit applies to v2024.07. The upstream window-scale clamp is left out because v2024.07 does not store the window scale; the commit message explains each hunk | `git apply --check` clean on the BSP 7.8.0 tree, reverse check fails before and passes after. **Not compiled and not runtime-tested** |

**NFS:** there is no NFS patch here. Four upstream fixes cover `net/nfs.c` (`d6694018eadd` for CVE-2026-29009, `85d82c523275`, `1c0aff3a5fbf` for CVE-2026-74221, `0bbf09859658` for CVE-2026-74220), and none applies to v2024.07, because the code later moved to `net/nfs-common.c`. A partial backport would leave the newer CVEs open, so if you enable `CONFIG_CMD_NFS`, port all four together. The simpler choice for production is to leave `CMD_NFS` and `CMD_WGET` off and boot over TFTP, which is the BSP 7 default.

The fixes that apply to the stock build are upstream or Toradex commits, not files in this directory. They are listed under "Minimal backport bundle" in `../README.md`.
