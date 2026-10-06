/* launcher.rc.h - constants used by launcher.rc
 *
 * Kept as a plain header (no <windows.h>) so the resource script compiles on
 * every toolchain, including from Linux with `zig rc`.
 */
#ifndef PANDORA_LAUNCHER_RC_H
#define PANDORA_LAUNCHER_RC_H

#define CREATEPROCESS_MANIFEST_RESOURCE_ID 1
#define RT_MANIFEST                        24

#define VS_VERSION_INFO                    1
#define VFT_APP                            0x00000001L
#define VFT2_UNKNOWN                       0x00000000L
#define VOS_NT_WINDOWS32                   0x00040004L

#endif
