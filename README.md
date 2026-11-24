# U-Boot CVE triage (VEX): Toradex BSP 7, Verdin iMX8M Plus

This repository holds an [OpenVEX](https://github.com/openvex/spec) v0.2.0 document and a short write-up. Together they cover **22 CVEs** that apply to U-Boot 2024.07 by version, and how each one applies to the U-Boot that Toradex BSP 7 builds for the Verdin iMX8M Plus. Eleven of them are what NVD's CPE match returns; the other eleven were published in August–September 2026 without CPE data, so NVD-based scanners do not report them (see finding 2).

**Result for the stock build: 5 affected, 17 not affected.** All five affected CVEs are fixed by seven upstream commits that apply cleanly to the BSP 7.8.0 tree.

**Unofficial. Not affiliated with or endorsed by Toradex or the U-Boot project.** It is an independent third-party analysis. Each ruling holds only for the source, configuration and releases pinned below.

- `vex/toradex-bsp7-verdin-imx8mp-u-boot.openvex.json`: 88 statements (22 CVEs × 4 product variants)
- `findings.csv`: the same data, one row per CVE per variant
- `patches/`: an adapted backport for a code path that is off in the stock build (see `patches/README.md`)

Triage date: 2026-11-22, extended 2026-11-23. NVD, CVE-record and OSV data were fetched on those dates. Upstream U-Boot was checked at `ee1b3477e3af` (v2027.01-rc3, 2026-11-23).

## Pins

| | |
|---|---|
| Board / machine | Toradex Verdin iMX8M Plus, `MACHINE = "verdin-imx8mp"` |
| U-Boot config | `verdin-imx8mp_defconfig` (`UBOOT_CONFIG[sd]`) |
| Recipe | `meta-toradex-bsp-common`, branch `scarthgap-7.x.y`, `recipes-bsp/u-boot/u-boot-toradex_2024.07.bb` (`CVE_PRODUCT = "denx:u-boot"`) |
| Source | `git.toradex.com/u-boot-toradex.git` at `SRCREV = 3f772959501c99fbe5aa0b22a36efe3478d1ae1c`. That is plain upstream **v2024.07** ("Prepare v2024.07") plus the recipe's `TDX_PATCHES` |
| Analysed layer revision | `meta-toradex-bsp-common` `8f13083c771e`. It descends from the **BSP 7.8.0** pin `e99ec578177e`; the two commits in between touch only `linux-toradex-upstream`. In 7.8.0 the recipe carries 43 patches |
| Releases | Toradex tags releases in `toradex-manifest` (`bsp/pinned-tdx.xml`). 7.0.0 to 7.8.0 all use the same `SRCREV`. Recipe patch counts: 7.0.0: 7, 7.1.0: 11, 7.2.0: 14, 7.3.0: 16, 7.4.0: 29, 7.5.0: 31, 7.6.0 to 7.7.0: 32, 7.8.0: 43 |
| Secure-boot variant | `meta-toradex-security` `scarthgap-7.x.y` at `9347d9ad41e4`: `UBOOT_SIGN_ENABLE=1`, with the U-Boot fragments `fit-signature.cfg` and `u-boot-hab.cfg` |
| Toolchain | Ubuntu 24.04 `aarch64-linux-gnu-gcc` 13.3.0, `CONFIG_LTO=y` |

### Product identifiers

Each statement names its product with a purl:

```
pkg:generic/toradex/u-boot-toradex@2024.07?bsp=7.8.0&fit_signature=off&machine=verdin-imx8mp
pkg:generic/toradex/u-boot-toradex@2024.07?bsp=7.8.0&fit_signature=on&machine=verdin-imx8mp
```

There are four variants: {BSP 7.8.0, BSP 7.0.0–7.7.0} × {stock, FIT signature on}. The older range lists each release (7.0.0, 7.1.0, 7.2.0, 7.3.0, 7.4.0, 7.5.0, 7.6.0, 7.6.1, 7.6.2, 7.7.0) as its own product. Each product also carries `cpe:2.3:a:denx:u-boot:2024.07` as a subcomponent, because NVD-based scanners match on that CPE.

Why `pkg:generic` and these qualifiers:

- A ruling here depends on four things: the recipe, the BSP release, the machine, and whether FIT signature verification is compiled in. The registered `pkg:yocto` type identifies a recipe and a layer revision. It has no qualifier for machine or build configuration, so it cannot tell a stock build from a signed one. Scarthgap SBOMs also do not emit it. `pkg:generic` with explicit qualifiers says exactly what was analysed.
- `fit_signature` is set explicitly on both variants (`off` and `on`). Some purl matchers, vexctl among them, let a product purl match any query that has extra qualifiers. If the stock purl simply left the qualifier out, a signed build would also match the stock `not_affected` statement for CVE-2026-46728.
- To use the document, map your SBOM's U-Boot entry to the matching purl. A purl with no `fit_signature` qualifier matches nothing.

OpenVEX v0.2.0 has no field for "not_affected unless the customer enables X". The FIT signature case is a supported Toradex configuration, so it gets its own product variants. For every other CVE the stock ruling is the statement, and the condition that would change it is written into `impact_statement` (it also appears in the table below and in `findings.csv`).

## Results

The stock ruling is the same for every BSP 7 release from 7.0.0 to 7.8.0. "Evidence" says how each stock ruling was checked; see [Limitations](#limitations).

| CVE | CVSS (NVD / CNA) | Stock ruling | Ruling if the feature is enabled | Action | Evidence |
|---|---|---|---|---|---|
| CVE-2024-42040 | – / 8.1 (CISA-ADP) | not_affected: `bootp_handler()` is compiled out because `CMD_DHCP=y` | `CMD_DHCP` off with `CMD_BOOTP` on: affected (fix `81e5708cc2c8`) | none needed. Recommended hardening: `f447887238822` (no CVE) | binary |
| CVE-2024-57254 | 6.8 / 7.1 | not_affected: squashfs not built | `FS_SQUASHFS`: affected | none needed. If you enable squashfs, take the 4-commit set below | binary |
| CVE-2024-57255 | 6.8 / 7.1 | not_affected: squashfs not built | `FS_SQUASHFS`: affected | as above | binary |
| CVE-2024-57256 | 6.8 / 7.1 | **affected** (U-Boot proper; SPL not) | – | backport `35f75d2a46e5` **and** `107ed84602bb` | binary |
| CVE-2024-57257 | 2.4 / 2.0 | not_affected: squashfs not built | `FS_SQUASHFS`: affected | as for 57254 | binary |
| CVE-2024-57258 | 7.8 / 7.1 | **affected** (U-Boot proper; SPL not). Practical exploitability is rated low | – | backport `8642b2178d2c` + `0a10b49206a2`, recommended `9b9368b5c4dc` | binary |
| CVE-2024-57259 | 6.8 / 7.1 | not_affected: squashfs not built | `FS_SQUASHFS`: affected | as for 57254 | binary |
| CVE-2026-29007 | – / 5.3 | not_affected: `net/tcp.c` not built | `CMD_WGET`, `PROT_TCP` or `TCP_FUNCTION_FASTBOOT`: affected. Upstream fix only in v2027.01-rc3 (**NVD/OSV "fixed in 2026.04" is wrong**) | none needed. If enabled, apply the adapted backport in `patches/` | binary |
| CVE-2026-29008 | – / 7.5 | not_affected: `net/tcp.c` and `net/wget.c` not built | as for 29007 | as for 29007 | binary |
| CVE-2026-29009 | 9.8 / 8.2 | not_affected: `net/nfs.c` not built | `CMD_NFS`: affected | none needed. If enabled, see "NFS" under the backport bundle | binary |
| CVE-2026-46728 | 8.8 / 8.2 | not_affected: FIT signature verification not built | FIT signature (Toradex secure boot): **fixed in 7.8.0, affected in 7.0.0–7.7.0** | secure-boot users on 7.7.0 or older: upgrade to 7.8.0, or add the patches from Toradex commit `2ed62810` | binary + host-tool test |

**Published without CPE data** (not reported by NVD-based scanners; CVSS from the CNA or CISA-ADP, none from NVD):

| CVE | CVSS (source) | Stock ruling | Ruling if the feature is enabled | Action | Evidence |
|---|---|---|---|---|---|
| CVE-2026-15390 | 9.0 (CERT-PL, v4.0) | **affected**: IP reassembly state not cleared (`IP_DEFRAG=y`). Runs only while U-Boot is on the network (network commands, or the `dhcp` boot target after SD and eMMC fail). SPL not | – | backport `b1aec609bb5e` | binary |
| CVE-2026-71971 | 8.2 (VulnCheck) | **affected**: 4-byte out-of-bounds write in IP reassembly; low impact in this exact link. Same reachability. SPL not | – | backport `04ca915d5bf3` | binary |
| CVE-2025-70293 | 9.8 (CISA-ADP) | **affected**: `ext4fs_get_bgdtable()` overflow on ext4 *write* (`ext4write`, `save`, `ln`, EFI apps, EFI variable store on an ext4 "ESP"). Realistic impact here is a crash. SPL not | – | backport `fc16c847a1c9` + `107ed84602bb`; recommended `29cb98d515` | binary |
| CVE-2025-70290 | 9.8 (CISA-ADP) | not_affected: ZFS not built | `CMD_ZFS`: affected | none needed. If enabled: `c8f0294285f6` | binary |
| CVE-2026-71972 | 5.9 (VulnCheck) | not_affected: video not built | `VIDEO` + `VIDEO_BMP_RLE8`: affected | none needed. If enabled: `5201e83342d6` (drop its `int ret;` hunk) | binary |
| CVE-2026-71973 | 5.2 (VulnCheck) | not_affected: squashfs not built | `FS_SQUASHFS`: affected | none needed. If enabled: `59fd62d71c6a` then `561ae28cb56a` | binary |
| CVE-2026-71974 | 4.8 (VulnCheck) | not_affected: Android bootmeth does not exist in 2024.07 (added in v2025.04) | – | none | source + binary |
| CVE-2026-74220 | 8.2 (VulnCheck) | not_affected: `net/nfs.c` not built | `CMD_NFS`: affected | none needed. If enabled, see "NFS" below | binary |
| CVE-2026-74221 | 8.2 (VulnCheck) | not_affected: `net/nfs.c` not built | `CMD_NFS`: affected | as for 74220 | binary |
| CVE-2026-74222 | 8.2 (VulnCheck) | not_affected: no lwIP stack in 2024.07 (added in v2025.07) | – | none | source + binary |
| CVE-2026-74225 | 7.1 (VulnCheck) | not_affected: DHCPv6 not built (`IPV6` off) | `IPV6` + `CMD_DHCP6`: affected | none needed. If enabled: `20209a62bc85` | binary |

Full commit IDs, file and line evidence, and the gating Kconfig symbols are in each statement's `impact_statement`, `status_notes` and `action_statement`.

## Findings worth knowing

1. **For CVE-2024-57256, the fix NVD lists is not enough on 64-bit.** NVD references only `35f75d2a46e5`. On aarch64 that fix's `__builtin_add_overflow(u32, 1, &size_t)` does not catch the wrap, because `0x100000000` fits in a 64-bit `size_t`. A `0xffffffff` symlink size therefore becomes `zalloc(0x100000000)`. That request is larger than the 4 MiB heap, so `memalign()` returns NULL, and the tree's `zalloc()` then runs `memset(NULL, 0, 4 GiB)`. The companion commit `107ed84602bb` ("ext4: Fix zalloc()"), from the same series, closes this. You need both.
2. **A CPE-based scan misses half the CVEs, including three that are built in.** NVD's CPE match for `denx:u-boot` 2024.07 returns 11 CVEs. Eleven more U-Boot CVEs were published between 2026-08-26 and 2026-09-29 and are still "Awaiting Analysis" or "Deferred" at NVD, with no CPE data, so Yocto `cve-check` and other NVD-based scanners do not report them. Three of them hit code the stock build compiles: CVE-2026-15390 and CVE-2026-71971 (IP fragment reassembly) and CVE-2025-70293 (ext4 write). OSV does better but is not exact. It lists eight of the eleven against v2024.07, including two false positives (CVE-2026-71974 and CVE-2026-74222 are in code that did not exist yet in 2024.07), and it has no record of CVE-2026-15390, CVE-2025-70293 or CVE-2025-70290.
3. **NVD and OSV mark CVE-2026-29007/29008 as fixed seven releases too early.** NVD's CPE range says "before 2026.04", and OSV's "fixed" event points at `88dc2788777b` "Prepare v2026.04", which is only a version bump. The real fix landed on 2026-11-23: `a0e2935a4bde` ("net: tcp: drop segments with an invalid data offset") and `cf248526dbd1` ("net: tcp: check option lengths in tcp_parse_options()"), first in **v2027.01-rc3**. So v2026.04 through v2027.01-rc2 are still vulnerable, and version-range scanners will report them clean. The bug being unfixed upstream had already been noted on the U-Boot list (July 2026); the scanner-data error is what this repo adds. Neither fix applies to v2024.07. The out-of-bounds read site the CVE names, `tcp_parse_options()`, already exists there, and with wget enabled the negative length reaches `wget_connected()`, which copies without an LMB bound. `patches/` has an adapted backport of both commits.
4. **CVE-2026-46728 is fixed only from BSP 7.8.0.** Toradex backported the fix in `meta-toradex-bsp-common` commit `2ed62810` (2026-08-21). The first release whose pinned layer contains it is 7.8.0 (2026-11-06); `7.8.0-devel-202609` is the first devel snapshot with it. No release from 7.0.0 to 7.7.0 contains it, including 7.6.1, 7.6.2 and 7.7.0. The stock defconfig does not build FIT signature verification, so the CVE only matters with secure boot. In that case 7.0.0–7.7.0 are affected. The fix also fails closed: a FIT signed with a `sign-images` list narrower than the images its configuration references will stop verifying. Note that **Yocto `cve-check` still reports 46728 as unpatched on 7.8.0**, because Toradex's patch has no `CVE: CVE-2026-46728` tag and the recipe sets no `CVE_STATUS`. On 7.8.0 you can add `CVE_STATUS[CVE-2026-46728] = "backported-patch: fixed by 2ed62810 in BSP 7.8.0"` in your own layer.
5. **A DHCP hardening fix has no CVE.** CVE-2024-42040 does not apply to the stock build, because the BOOTP handler is compiled out. The DHCP path that *is* built, `dhcp_message_type()`, has the same class of out-of-bounds read. Upstream fixed it in `f447887238822` (v2026.07). That commit is not in BSP 7, and we found no CVE for it. A CVE scanner will never flag it.
6. **Five FIT-verifier fixes without CVEs are missing from every BSP 7 release.** Binarly reported six bugs in U-Boot's FIT signature verification in June 2026 (BRLY-2026-037 to -042), with no CVEs assigned. Their upstream fixes are all first in v2026.10-rc1:
   - `f3d2ff3f5c3f` "fdt: Check return value of fdt_get_name() calls" (BRLY-2026-037/038, rated possible code execution) — applies cleanly
   - `7304d569e615` "fdt_region: Check return value of fdt_get_property_by_offset() calls" — applies cleanly
   - `e73328612534` "image-fit-sig: Validate hashed-strings region size" — needs adapting
   - `69f6272b24a2` "image-fit: Validate external data offset and size" — needs adapting
   - `9e0d2fb42965` "image-fit: Limit recursion depth in fdt_check_no_at()" — needs adapting

   They matter only with FIT signature verification on, but a secure-boot product on BSP 7.8.0 that is "clean" for CVE-2026-46728 still carries all five. None was build-tested here.

Smaller observation: Toradex's backport of the 46728 fix adapts `test/py/tests/test_vboot.py` by hand. It uses names that do not exist in 2024.07 (`utils`, `ubman`), so that test would raise `NameError`. The test is not shipped, so there is no security impact.

## Method

1. Built the exact tree: `SRCREV` plus every recipe patch, then `make verdin-imx8mp_defconfig`.
2. For each CVE, located the vulnerable function. Then checked three things:
   - Is the fix present? The upstream fix must pass `git apply --check` and fail `git apply -R --check`.
   - Is the code compiled? Checked Makefile `obj-$(CONFIG_…)` gates, `#if` blocks and the resulting `.config`, for U-Boot proper and SPL separately.
   - Is it reachable? Traced the default boot flow (`distro_bootcmd`, boot targets).
3. Cross-built U-Boot proper and SPL from the exact tree; the build's `.config` is identical to the analysed one. For every CVE, checked which objects appear in `u-boot.map` / `u-boot-spl.map` and which functions appear in each image's symbol table (`readelf -s`). Under `CONFIG_LTO=y` a static function with one caller can be inlined, so the link map is the main evidence. A missing symbol counts only when a comparable static function in the same object does keep its symbol: for example `dhcp_handler` is present while `bootp_handler` is absent.
4. For CVE-2026-46728:
   - Compared Toradex's patches hunk by hunk with upstream.
   - Built three configurations: stock, secure boot patched, and secure boot on pristine v2024.07.
   - Ran differential tests with `mkimage` / `fit_check_sign` built from the patched and the pristine tree.
   - Traced `2ed62810` against the layer revision pinned by every `toradex-manifest` tag.
5. For releases before 7.8.0, a scripted scan of each release's pinned recipe patches looked for any that touch `net/`, `fs/`, `common/dlmalloc.c` or `boot/image-fit-sig.c`, or change the relevant `CONFIG_` symbols. Only 7.8.0's `0002` (the 46728 fix) does.
6. Backports were applied with `git am` to a throwaway worktree.

## Limitations

- **No runtime tests.** No ruling was tested on hardware, and no exploit or PoC was run. That includes the full published CVE-2026-46728 bypass. The 46728 rulings rest on code identity with upstream and on host-tool differential tests.
- **Binary checks are static.** Every stock ruling was confirmed against the built 7.8.0 images (link maps and symbol tables): no squashfs, ZFS, video, TCP, wget, NFS, DHCPv6, lwIP or FIT-signature objects; `bootp_handler` absent while `dhcp_handler` is present; ext4 (read and write), the IP stack with its reassembly buffer, and the full dlmalloc linked into U-Boot proper but not SPL. These checks show what is built in, not that a path is reachable at runtime. With `CONFIG_LTO=y`, static functions can be inlined (`ext4fs_read_symlink()` has no symbol of its own), so the link map is the main evidence.
- **The backports are apply-tested only.** The seven-commit bundle, the recommended additions and the TCP patch in `patches/` were applied in sequence to the 7.8.0 tree. None of them was compiled or run. The three Binarly fixes that need adapting and the four NFS fixes were not adapted.
- **Releases 7.0.0–7.7.0 were not rebuilt.** Their rulings are inferred from the 7.8.0 build, the identical `SRCREV`, and the patch scan above.
- **Mainly one configuration.** Only `verdin-imx8mp_defconfig` was analysed, plus the Toradex secure-boot fragments for 46728. If you change any `CONFIG_` symbol named in a statement, your result may differ.
- **CVE-2024-57258 call sites were not audited.** We did not check whether any reachable caller can request an allocation near 2^63. If you need a `not_affected` ruling for it, that audit is the missing piece; the backport is cheaper.
- **Network and ext4-write impact.** For CVE-2026-15390, CVE-2026-71971 and CVE-2025-70293 the reachability analysis (when the network comes up, which paths write ext4, including the EFI variable store) was traced in source and not exercised on hardware.
- **Point in time.** The CVE set is NVD's CPE match for 2024.07 plus the U-Boot CVEs in the CVE List and OSV without CPE data, as of 2026-11-23. New CVEs are not covered.

## Reproduce

```sh
# Sources (full clones; the release-boundary check needs history)
git clone https://git.toradex.com/toradex-manifest.git
git clone -b scarthgap-7.x.y https://git.toradex.com/meta-toradex-bsp-common.git
git clone https://git.toradex.com/u-boot-toradex.git
L=$PWD/meta-toradex-bsp-common/recipes-bsp/u-boot

# 1. Tree for BSP 7.8.0: SRCREV + TDX_PATCHES in recipe order
git -C meta-toradex-bsp-common checkout e99ec578177e51492f38a6a31abcb190ca195f2d
cd u-boot-toradex && git checkout 3f772959501c99fbe5aa0b22a36efe3478d1ae1c
for p in $(sed -n '/^TDX_PATCHES/,/"$/p' $L/u-boot-toradex_2024.07.bb | grep -o 'file://[^ ]*' | sed 's#file://##'); do
  git apply --index "$L/u-boot-toradex/$p" || break
done
git commit -qm "Apply BSP 7.8.0 TDX_PATCHES"

# 2. Stock build and checks
make O=out/stock verdin-imx8mp_defconfig
make O=out/stock CROSS_COMPILE=aarch64-linux-gnu- -j"$(nproc)" u-boot spl/u-boot-spl
# Expect: CMD_BOOTP, CMD_DHCP, FS_EXT4, SPL_SYS_MALLOC_SIMPLE (and friends) =y; no SQUASHFS/TCP/WGET/NFS/FIT_SIGNATURE lines
grep -E 'CONFIG_(FS_SQUASHFS|SPL_FS_SQUASHFS|CMD_DHCP|CMD_BOOTP|PROT_TCP|CMD_WGET|CMD_NFS|SPL_NET|FIT_SIGNATURE|SPL_FIT_SIGNATURE|FS_EXT4|SPL_FS_EXT4|SPL_SYS_MALLOC_SIMPLE)\b' out/stock/.config
# Expect NO output from the next two commands (code not built)
grep -E 'fs/squashfs/|fs/zfs/|drivers/video/|net/(tcp|wget|nfs|fastboot_tcp|dhcpv6)\.o|net/lwip/|boot/image-fit-sig\.o' out/stock/u-boot.map out/stock/spl/u-boot-spl.map
readelf -sW out/stock/u-boot out/stock/spl/u-boot-spl | awk '{print $8}' \
  | grep -xE 'bootp_handler|sqfs_[a-z_]+|rxhand_tcp_f|wget_handler|nfs_readlink_reply|fit_config_check_sig'
# Expect output from these (code that IS built):
readelf -sW out/stock/u-boot | awk '{print $8}' | grep -xE 'dhcp_handler|malloc|sbrk'   # U-Boot proper
grep -cE 'fs/ext4/ext4_(common|write)\.o|net/net\.o' out/stock/u-boot.map              # 3 = ext4 read+write and IP stack in proper
readelf -sW out/stock/u-boot | awk '{print $8}' | grep '^pkt_buff'                     # IP reassembly buffer (CONFIG_IP_DEFRAG)
readelf -sW out/stock/spl/u-boot-spl | awk '{print $8}' | grep -xE 'malloc|sbrk'       # none = SPL has no dlmalloc

# 3. Secure-boot variant: append the meta-toradex-security fragments
#    (fit-signature.cfg and u-boot-hab.cfg) to a copy of the stock .config, then
make O=out/secure olddefconfig && make O=out/secure CROSS_COMPILE=aarch64-linux-gnu- -j"$(nproc)" u-boot
strings out/secure/u-boot | grep -c 'Failed to build hash node list'   # 1 = 46728 fix compiled in

# 4. Is an upstream fix present? (absent = forward check passes, reverse fails)
git apply --check fix.patch && ! git apply -R --check fix.patch && echo "fix absent"

# 5. 46728 release boundary
cd ..
for t in 7.0.0 7.1.0 7.2.0 7.3.0 7.4.0 7.5.0 7.6.0 7.6.1 7.6.2 7.7.0 7.8.0; do
  pin=$(git -C toradex-manifest show "$t:bsp/pinned-tdx.xml" | grep meta-toradex-bsp-common | grep -o 'revision="[0-9a-f]*"' | cut -d'"' -f2)
  git -C meta-toradex-bsp-common merge-base --is-ancestor 2ed62810c9538d6265a8f03222cb23b07faaf060 "$pin" \
    && echo "$t fix present" || echo "$t fix absent"
done
```

To query the VEX document with [vexctl](https://github.com/openvex/vexctl) (v0.4.4 tested):

```sh
vexctl merge --vuln CVE-2026-46728 \
  --product 'pkg:generic/toradex/u-boot-toradex@2024.07?bsp=7.6.1&fit_signature=on&machine=verdin-imx8mp' \
  vex/toradex-bsp7-verdin-imx8mp-u-boot.openvex.json
```

## Minimal backport bundle

Upstream commits refer to `https://source.denx.de/u-boot/u-boot` (now redirecting to `git.u-boot-project.org`; mirror: `github.com/u-boot/u-boot`). Export each with `git format-patch -1 <sha>` and add it to your recipe's `SRC_URI`.

**Every BSP 7 build (stock config).** Seven commits fix all five affected CVEs. They were applied together, in this order, with `git apply` on the 7.8.0 tree, and every recommended addition below applies cleanly on top. They were not compiled.

| Order | Commit | For |
|---|---|---|
| 1 | `35f75d2a46e5859138c83a75cd2f4141c5479ab9` ext4: Fix integer overflow in ext4fs_read_symlink() | CVE-2024-57256 |
| 2 | `107ed84602bb5b77c333e3a4f373db5e62b50c61` ext4: Fix zalloc() | CVE-2024-57256 (64-bit), CVE-2025-70293 |
| 3 | `8642b2178d2c4002c99a0b69a845a48f2ae2706f` dlmalloc: Fix integer overflow in request2size() | CVE-2024-57258 |
| 4 | `0a10b49206a29b4aa2f80233a3e53ca0466bb0b3` dlmalloc: Fix integer overflow in sbrk() | CVE-2024-57258 |
| 5 | `fc16c847a1c9c6e0ee1f605849cc500a04c21602` fs: prevent integer overflow in ext4fs_get_bgdtable | CVE-2025-70293 |
| 6 | `b1aec609bb5e0d08c25c888c91935287ab4ee5fa` net: clear IP defragmentation state after returning a complete packet | CVE-2026-15390 |
| 7 | `04ca915d5bf39dda5d1bce62d04d2b59d293c5b9` net: fix out-of-bounds write in IP fragment reassembly | CVE-2026-71971 |

Recommended additions (no CVE of their own):
- `9b9368b5c4dc24b3b999743db26fb915981d26a9` dlmalloc: Make sure allocation size is within malloc area
- `f447887238822af40582483112cab524926e9258` net: bootp: Prevent out-of-bounds read in dhcp_message_type
- `29cb98d515f96c2330455af4b8cace0220abd00c` fs: ext4fs: Fix: Data abort in ext4fs_log_gdt() (out-of-bounds access in the same ext4 write path as CVE-2025-70293)

If you cannot rebuild soon: the two IP-reassembly CVEs need U-Boot to be on the network. Keep a valid boot medium so the default boot never falls through to the `dhcp` target (or `setenv boot_targets mmc1 mmc2; saveenv`), and avoid network commands on untrusted networks. CVE-2025-70293 needs U-Boot to *write* ext4, which the stock boot flow does not do unless an inserted SD card carries an ext4 partition flagged as an EFI System Partition.

**Secure boot (FIT signature) on BSP 7.0.0–7.7.0.** Upgrade to 7.8.0, or add the two recipe patches from `meta-toradex-bsp-common` commit `2ed62810c9538d6265a8f03222cb23b07faaf060`. They are equivalent to upstream `3059eb0c27dd` + `2092322b31cc`. On every BSP 7 release, also take the five Binarly fixes listed in finding 6. `f3d2ff3f5c3f49216b45a30b4b9a315a1b8d2142` and `7304d569e61521e04625bfbded894f2e5fbe4409` apply cleanly on top of the stock bundle; the other three need adapting.

**Only if you enable the feature:**
- squashfs: `233945eba63e24061dffeeaeb7cd6fe985278356`, `c8e929e5758999933f9e905049ef2bf3fe6b140d`, `4f5cc096bfd0a591f8a11e86999e3d90a9484c34`, `048d795bb5b3d9c5701b4855f5e74bcf6849bf5e`, then `59fd62d71c6a04b3ab9db848414a7c386cfd2cfb` and `561ae28cb56a082cfa90c1c421c4955bc215470b`, in that order
- NFS: no patch is provided. Four upstream fixes are needed together, `d6694018eaddefac6aae974f9cec72fd6e58f1bc` (CVE-2026-29009), `85d82c52327552da9e9bd103342d970d49ec262c`, `1c0aff3a5fbfeee7a8948f624e0b8554e6e0d8fd` (CVE-2026-74221) and `0bbf09859658b8cc9ac13be41af23b516b8ef69a` (CVE-2026-74220), and none applies to v2024.07 because the code later moved to `net/nfs-common.c`. Prefer TFTP.
- wget / TCP: `patches/CVE-2026-29007-29008-backport-v2024.07.patch` (adapted from `a0e2935a4bde` + `cf248526dbd1`)
- ZFS: `c8f0294285f6588322363e1711bc57118e6fc9a3`
- Video with BMP RLE8: `5201e83342d64c2f438ea35158575f28225e752e`, without its hunk that adds `int ret;`
- IPv6 with DHCPv6: `20209a62bc8565fc1e040882bc03c71ff0d73076`
- BOOTP without DHCP: `81e5708cc2c865df606e49aed5415adb2a662171`

## Disclaimer

This is not legal advice and not a conformity assessment under the EU Cyber Resilience Act or any other regulation. It is provided as is, without warranty of any kind. The rulings apply only to the pinned sources and configurations above. Verify them against your own fork, configuration and release before relying on them.

Your fork differs from this one? Open an issue on this repository.
