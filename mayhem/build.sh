#!/usr/bin/env bash
#
# mayhem/build.sh — build the 12 OSS-Fuzz (Intel HBFA) harnesses of edk2, their standalone
# reproducers, and the normal-flags known-answer oracle used by mayhem/test.sh.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem, offline: the pinned
# sources (HBFA and the upstream submodules) were cached under /opt/toolchains/deps by the
# Dockerfile. All build output goes to mayhem/build/ (gitignored) except the final binaries,
# which are /mayhem/<target> and /mayhem/<target>-standalone.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/build"
DEPS=/opt/toolchains/deps

# UBSan `alignment` is relaxed: EDK II reads packed on-disk/wire structures through
# ReadUnaligned*() helpers that cast to UINT16/32/64 pointers (MdePkg/Library/BaseLib/Unaligned.c),
# which is benign on x86 and would halt every harness on its first input.
FUZZ_FLAGS="$SANITIZER_FLAGS -fno-sanitize=alignment $DEBUG_FLAGS"

# name:inf (relative to HBFA/UefiHostFuzzTestCasePkg/TestCase)
TARGETS=(
  TestBmpSupportLib:MdeModulePkg/Library/BaseBmpSupportLib/TestBmpSupportLib.inf
  TestTpm2CommandLib:SecurityPkg/Library/Tpm2CommandLib/TestTpm2CommandLib.inf
  TestPartition:MdeModulePkg/Universal/Disk/PartitionDxe/TestPartition.inf
  TestUdf:MdeModulePkg/Universal/Disk/UdfDxe/TestUdf.inf
  TestPeiUsb:MdeModulePkg/Bus/Usb/UsbBusPei/TestPeiUsb.inf
  TestFmpAuthenticationLibPkcs7:SecurityPkg/Library/FmpAuthenticationLibPkcs7/TestFmpAuthenticationLibPkcs7.inf
  TestFmpAuthenticationLibRsa2048Sha256:SecurityPkg/Library/FmpAuthenticationLibRsa2048Sha256/TestFmpAuthenticationLibRsa2048Sha256.inf
  TestCapsulePei:MdeModulePkg/Universal/CapsulePei/Common/TestCapsulePei.inf
  TestFileName:MdeModulePkg/Universal/Disk/UdfDxe/TestFileName.inf
  TestVirtio10Blk:OvmfPkg/Virtio10BlkDxe/TestVirtio10Blk.inf
  TestVirtioBlk:OvmfPkg/VirtioBlkDxe/TestVirtioBlk.inf
  TestVirtioPciDevice:OvmfPkg/VirtioPciDeviceDxe/TestVirtioPciDevice.inf
)

# 1) The submodules are empty gitlinks in a plain clone, but the DEC files list their include
#    directories and BaseTools links brotli. Fill any empty one from the cached pinned source.
grep -v '^[[:space:]]*#' mayhem/deps.txt | while read -r name sha _ path; do
  [ "$path" != "-" ] || continue
  if [ -z "$(ls -A "$path" 2>/dev/null)" ]; then
    mkdir -p "$path"
    cp -a "$DEPS/${name}-${sha:0:12}/src/." "$path/"
  fi
done
HBFA_SRC=$(echo "$DEPS"/hbfa-fl-*/src)

# 2) EDK II host tools (Trim, GenFw, ...), built in place; every product is gitignored upstream.
export PYTHON_COMMAND=python3 PYTHONDONTWRITEBYTECODE=1
rm -rf "$B"
mkdir -p "$B"
make -C BaseTools -j"$MAYHEM_JOBS" > "$B/basetools.log" 2>&1 || { tail -n 40 "$B/basetools.log" >&2; exit 1; }

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/lsan_off.o"

# prepare_tree <dir> <cc-flags> <link-flags>: a private patched copy of HBFA plus its workspace.
# HBFA's DSC predates upstream's GptLib/Tpm2HelpLib library classes and its tools_def spells the
# toolchain GCC5; both are patched in the copy, never in the edk2 tree.
prepare_tree() {
  local dir="$1" ccflags="$2" ldflags="$3" h="$1/hbfa/HBFA"
  mkdir -p "$dir/hbfa" "$dir/ws" "$dir/Conf"
  cp -a "$HBFA_SRC/HBFA" "$dir/hbfa/"
  sed -i 's/GCC5_/GCC_/g; s/GCC48_/GCC_/g; s/GCC49_/GCC_/g' "$h/UefiHostFuzzTestPkg/Conf/tools_def.customized"
  sed -i 's/GCC\\\\d{1,2}_ALL_CC_FLAGS/GCC\\\\d{0,2}_ALL_CC_FLAGS/' "$h/UefiHostTestTools/HBFAEnvSetup.py"
  sed -i "s#-DTEST_WITH_LIBFUZZER=TRUE\" -O1 -fsanitize=fuzzer,address#-DTEST_WITH_LIBFUZZER=TRUE\" -O1 $ccflags#; \
          s#GCC:\*_LIBFUZZER_\*_DLINK2_FLAGS = -fsanitize=fuzzer,address#GCC:*_LIBFUZZER_*_DLINK2_FLAGS = $ldflags#" \
      "$h/UefiHostFuzzTestPkg/UefiHostFuzzTestBuildOption.dsc"
  # HBFA's PEI services stub ASSERTs (int3) in PeiAllocatePool, so TestPeiUsb died on every input
  # before reaching UsbPeim.c. Back it with AllocatePool and have the harness free the result.
  perl -0pi -e 's/(PeiAllocatePool \(\r?\n.*?\)\r?\n\{\r?\n)  ASSERT \(FALSE\);\r?\n  return  EFI_NOT_AVAILABLE_YET;/$1  *Buffer = AllocatePool (Size);\n  return (*Buffer == NULL) ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;/s; s/#include <Library\/BaseMemoryLib.h>/#include <Library\/BaseMemoryLib.h>\n#include <Library\/MemoryAllocationLib.h>/' \
      "$h/UefiHostTestPkg/Library/PeiServicesTablePointerLibHost/PeiServicesTablePointerLibHost.c"
  perl -0pi -e 's/(  PeiUsbGetAllConfiguration\(NULL, &PeiUsbDevice\);)/$1\n  if (PeiUsbDevice.ConfigurationData != NULL) {\n    FreePool (PeiUsbDevice.ConfigurationData);\n  }/' \
      "$h/UefiHostFuzzTestCasePkg/TestCase/MdeModulePkg/Bus/Usb/UsbBusPei/TestPeiUsb.c"
  # TestPartition/TestUdf feed the whole 512 KiB / 1 MiB disk from the input, but Mayhem caps inputs
  # at 8 KiB (the 1 MiB seeds all collapsed to their zero head), so expand a sparse record list into
  # the image first (mayhem/SparseImage.h). The same code runs in the standalone reproducers.
  local d="$h/UefiHostFuzzTestCasePkg/TestCase/MdeModulePkg/Universal/Disk"
  cp "$SRC/mayhem/SparseImage.h" "$d/PartitionDxe/" && cp "$SRC/mayhem/SparseImage.h" "$d/UdfDxe/"
  perl -0pi -e 's/(#include <Library\/DiskStubLib.h>\r?\n)/$1#include "SparseImage.h"\n/; s/(\n  FixBuffer \(TestBuffer\);\r?\n)/$1  SparseImageExpand ((UINT8 *)TestBuffer, TOTAL_SIZE, TestBufferSize);\n  TestBufferSize = TOTAL_SIZE;\n/' \
      "$d/PartitionDxe/TestPartition.c"
  perl -0pi -e 's/(#include <Library\/DiskStubLib.h>\r?\n)/$1#include "SparseImage.h"\n/; s/(\n  FixBuffer \(TestBuffer\);\r?\n)/$1  SparseImageExpand ((UINT8 *)TestBuffer, TOTAL_SIZE, TestBufferSize);\n/' \
      "$d/UdfDxe/TestUdf.c"
  grep -q 'SparseImageExpand' "$d/PartitionDxe/TestPartition.c" && grep -q 'SparseImageExpand' "$d/UdfDxe/TestUdf.c" \
    || { echo "HBFA sparse-image patch did not apply" >&2; exit 1; }
  # TestVirtioBlk/TestVirtio10Blk never release the ring VirtioBlkInit sets up on success, so every
  # input leaked it and libFuzzer hit its 2 GiB rss limit; undo it the way VirtioBlkUninit does.
  for t in Virtio10BlkDxe/TestVirtio10Blk VirtioBlkDxe/TestVirtioBlk; do
    perl -0pi -e 's/      VirtioBlkInit \(VblkDev\);/      if (!EFI_ERROR (VirtioBlkInit (VblkDev))) {\n        VblkDev->VirtIo->UnmapSharedBuffer (VblkDev->VirtIo, VblkDev->RingMap);\n        VirtioRingUninit (VblkDev->VirtIo, &VblkDev->Ring);\n      }/; s/#include <Library\/VirtioBlkStubLib.h>/#include <Library\/VirtioBlkStubLib.h>\n#include <Library\/VirtioLib.h>/' \
        "$h/UefiHostFuzzTestCasePkg/TestCase/OvmfPkg/$t.c"
    grep -q 'VirtioRingUninit' "$h/UefiHostFuzzTestCasePkg/TestCase/OvmfPkg/$t.c" || { echo "HBFA $t patch did not apply" >&2; exit 1; }
  done
  grep -q 'AllocatePool (Size)' "$h/UefiHostTestPkg/Library/PeiServicesTablePointerLibHost/PeiServicesTablePointerLibHost.c" \
    && grep -q 'FreePool (PeiUsbDevice' "$h/UefiHostFuzzTestCasePkg/TestCase/MdeModulePkg/Bus/Usb/UsbBusPei/TestPeiUsb.c" \
    || { echo "HBFA TestPeiUsb patch did not apply" >&2; exit 1; }
  sed -i "0,/^  BaseLib|UefiHostTestPkg/s##  GptLib|MdeModulePkg/Library/GptLib/GptLib.inf\n  Tpm2HelpLib|SecurityPkg/Library/Tpm2HelpLib/Tpm2HelpLib.inf\n  BaseLib|UefiHostTestPkg#" \
      "$h/UefiHostFuzzTestCasePkg/UefiHostFuzzTestCasePkg.dsc"
}

# build_tree <dir> <inf>...: run the EDK II build for each module (paths under TestCase/).
build_tree() (
  local dir="$1"; shift
  local h="$dir/hbfa/HBFA" infs=("$@")
  export PACKAGES_PATH="$h:$SRC" EDK_TOOLS_PATH="$SRC/BaseTools" CONF_PATH="$dir/Conf" WORKSPACE="$dir/ws"
  set +u
  set --; cd "$SRC"; source edksetup.sh >/dev/null
  set -u
  export PATH="$EDK_TOOLS_PATH/BinWrappers/PosixLike:$PATH"
  cd "$dir"
  python3 -u "$h/UefiHostTestTools/HBFAEnvSetup.py" >/dev/null
  for inf in "${infs[@]}"; do   # build accepts a single -m per invocation
    build -p UefiHostFuzzTestCasePkg/UefiHostFuzzTestCasePkg.dsc -m "UefiHostFuzzTestCasePkg/TestCase/$inf" \
          -a X64 -b DEBUG -t LIBFUZZER --conf "$h/UefiHostFuzzTestPkg/Conf" -n "$MAYHEM_JOBS" >> "$dir/build.log" 2>&1 \
      || { tail -n 60 "$dir/build.log" >&2; exit 1; }
  done
)

# 3) Fuzz build: every harness module, ASan+UBSan(+libFuzzer coverage) instrumented, DWARF <= 3.
prepare_tree "$B/fuzz" \
  "-fsanitize=fuzzer $FUZZ_FLAGS" \
  "-fsanitize=fuzzer $FUZZ_FLAGS $B/lsan_off.o"
infs=(); for t in "${TARGETS[@]}"; do infs+=("${t#*:}"); done
build_tree "$B/fuzz" "${infs[@]}"

OUT="$B/fuzz/ws/Build/UefiHostFuzzTestCasePkg/DEBUG_LIBFUZZER/X64"
for t in "${TARGETS[@]}"; do
  name="${t%%:*}"
  cp "$OUT/$name" "$SRC/$name"
  # Standalone reproducer: the same modules relinked without libFuzzer, so the file-reading
  # driver (not libFuzzer's) is main(). The driver and lsan_off.o come before the archives.
  lst=$(find "$OUT" -path "*/$name/OUTPUT/static_library_files.lst")
  $CC -o "$SRC/$name-standalone" -m64 "$B/lsan_off.o" "$B/standalone_main.o" \
      -Wl,--start-group,@"$lst",--end-group -no-pie $FUZZ_FLAGS
done

# 4) Oracle build: the BaseBmpSupportLib known-answer test with the project's normal flags
#    (no sanitizers, no libFuzzer), the same module graph as TestBmpSupportLib.
prepare_tree "$B/plain" "-g $COVERAGE_FLAGS" "-g $COVERAGE_FLAGS"
cp mayhem/oracle/OracleBmp.c mayhem/oracle/OracleBmp.inf \
   "$B/plain/hbfa/HBFA/UefiHostFuzzTestCasePkg/TestCase/MdeModulePkg/Library/BaseBmpSupportLib/"
sed -i "0,/^\[Components\]/s##[Components]\n  UefiHostFuzzTestCasePkg/TestCase/MdeModulePkg/Library/BaseBmpSupportLib/OracleBmp.inf {\n    <LibraryClasses>\n      BmpSupportLib|MdeModulePkg/Library/BaseBmpSupportLib/BaseBmpSupportLib.inf\n  }\n#" \
    "$B/plain/hbfa/HBFA/UefiHostFuzzTestCasePkg/UefiHostFuzzTestCasePkg.dsc"
build_tree "$B/plain" MdeModulePkg/Library/BaseBmpSupportLib/OracleBmp.inf
mkdir -p "$B/oracle"
cp "$B/plain/ws/Build/UefiHostFuzzTestCasePkg/DEBUG_LIBFUZZER/X64/OracleBmp" "$B/oracle/OracleBmp"
