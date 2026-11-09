/** @file
  Sparse input container for the TestPartition and TestUdf harnesses.

  Their "disk" is 512 KiB / 1 MiB, but a UDF volume is a few dozen small descriptors
  (volume recognition at 32 KiB, anchor, partition and file-set descriptors, file entries,
  directory data) in an otherwise zero image. Mayhem caps libFuzzer inputs at 8 KiB, so a
  whole-image input can only ever reach the first 8 KiB, which is all zeros. The input is
  therefore a list of records applied over a zeroed image:

    UINT32 Offset (little endian, taken modulo the image size)
    UINT16 Length (little endian, cut at the end of the input and of the image)
    UINT8  Data[Length]

  Every byte string is a valid input; a trailing fragment shorter than a record header is ignored.
**/

#ifndef MAYHEM_SPARSE_IMAGE_H_
#define MAYHEM_SPARSE_IMAGE_H_

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#define SPARSE_RECORD_HEADER_SIZE  6

STATIC
VOID
SparseImageExpand (
  IN OUT UINT8  *Image,
  IN UINTN      ImageSize,
  IN UINTN      InputSize
  )
{
  UINT8  *Input;
  UINTN  Pos;
  UINTN  Offset;
  UINTN  Length;
  UINTN  Copy;

  Input = AllocatePool (InputSize + 1);
  if (Input == NULL) {
    return;
  }

  CopyMem (Input, Image, InputSize);
  ZeroMem (Image, ImageSize);

  Pos = 0;
  while (InputSize - Pos >= SPARSE_RECORD_HEADER_SIZE) {
    Offset = ReadUnaligned32 ((CONST UINT32 *)(Input + Pos)) % ImageSize;
    Length = ReadUnaligned16 ((CONST UINT16 *)(Input + Pos + 4));
    Pos   += SPARSE_RECORD_HEADER_SIZE;
    if (Length > InputSize - Pos) {
      Length = InputSize - Pos;
    }

    Copy = Length;
    if (Copy > ImageSize - Offset) {
      Copy = ImageSize - Offset;
    }

    CopyMem (Image + Offset, Input + Pos, Copy);
    Pos += Length;
  }

  FreePool (Input);
}

#endif
