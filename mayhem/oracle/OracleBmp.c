/*
  Known-answer oracle for MdeModulePkg/Library/BaseBmpSupportLib.

  With no arguments: runs built-in cases on hand-built BMP images and prints "PASS <name>" /
  "FAIL <name>" per case. With file arguments: prints one "RESULT <basename> <status> <w> <h> <hash>"
  line per file, where <hash> is FNV-1a over the translated pixels' B,G,R bytes (mayhem/test.sh diffs
  these against mayhem/oracle/golden.txt).
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Uefi.h>
#include <IndustryStandard/Bmp.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BmpSupportLib.h>
#include <Library/MemoryAllocationLib.h>

static int  mFail;

static void
Check (
  const char  *Name,
  int         Ok
  )
{
  printf ("%s %s\n", Ok ? "PASS" : "FAIL", Name);
  if (!Ok) {
    mFail++;
  }
}

static void
PutHeader (
  UINT8   *Buf,
  UINT32  Size,
  UINT32  Offset,
  UINT32  Width,
  UINT32  Height,
  UINT16  Bpp
  )
{
  BMP_IMAGE_HEADER  H;

  memset (&H, 0, sizeof (H));
  H.CharB       = 'B';
  H.CharM       = 'M';
  H.Size        = Size;
  H.ImageOffset = Offset;
  H.HeaderSize  = sizeof (BMP_IMAGE_HEADER) - 14;
  H.PixelWidth  = Width;
  H.PixelHeight = Height;
  H.Planes      = 1;
  H.BitPerPixel = Bpp;
  memcpy (Buf, &H, sizeof (H));
}

static int
PixelIs (
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *P,
  UINT8                          R,
  UINT8                          G,
  UINT8                          B
  )
{
  return P->Red == R && P->Green == G && P->Blue == B;
}

static void
Test24Bit (
  void
  )
{
  UINT8                          Bmp[54 + 16];
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Blt = NULL;
  UINTN                          BltSize = 0, H = 0, W = 0;
  RETURN_STATUS                  S;

  memset (Bmp, 0, sizeof (Bmp));
  PutHeader (Bmp, sizeof (Bmp), 54, 2, 2, 24);
  /* bottom-up rows, BGR, each row padded to 8 bytes */
  static const UINT8  Data[16] = {
    3, 2, 1,    6, 5, 4,    0, 0,   /* bottom row: (R1,G2,B3) (R4,G5,B6) */
    9, 8, 7,    12, 11, 10, 0, 0    /* top row:    (R7,G8,B9) (R10,G11,B12) */
  };

  memcpy (Bmp + 54, Data, 16);
  S = TranslateBmpToGopBlt (Bmp, sizeof (Bmp), &Blt, &BltSize, &H, &W);
  Check ("24bit.status", S == RETURN_SUCCESS);
  Check ("24bit.width", W == 2);
  Check ("24bit.height", H == 2);
  Check ("24bit.bltsize", BltSize == 4 * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
  if ((S == RETURN_SUCCESS) && (Blt != NULL)) {
    Check ("24bit.top-left", PixelIs (&Blt[0], 7, 8, 9));
    Check ("24bit.top-right", PixelIs (&Blt[1], 10, 11, 12));
    Check ("24bit.bottom-left", PixelIs (&Blt[2], 1, 2, 3));
    Check ("24bit.bottom-right", PixelIs (&Blt[3], 4, 5, 6));
  } else {
    Check ("24bit.top-left", 0);
    Check ("24bit.top-right", 0);
    Check ("24bit.bottom-left", 0);
    Check ("24bit.bottom-right", 0);
  }

  if (Blt != NULL) {
    FreePool (Blt);
  }
}

static void
Test8Bit (
  void
  )
{
  UINT8                          Bmp[54 + 1024 + 8];
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Blt = NULL;
  UINTN                          BltSize = 0, H = 0, W = 0;
  RETURN_STATUS                  S;
  BMP_COLOR_MAP                  *Map;
  UINTN                          I;

  memset (Bmp, 0, sizeof (Bmp));
  PutHeader (Bmp, sizeof (Bmp), 54 + 1024, 2, 2, 8);
  Map = (BMP_COLOR_MAP *)(Bmp + 54);
  for (I = 0; I < 256; I++) {
    Map[I].Blue  = (UINT8)(255 - I);
    Map[I].Green = (UINT8)I;
    Map[I].Red   = (UINT8)(I ^ 0x55);
  }

  /* bottom row indices 10,20; top row indices 30,40; rows padded to 4 bytes */
  Bmp[54 + 1024 + 0] = 10;
  Bmp[54 + 1024 + 1] = 20;
  Bmp[54 + 1024 + 4] = 30;
  Bmp[54 + 1024 + 5] = 40;
  S = TranslateBmpToGopBlt (Bmp, sizeof (Bmp), &Blt, &BltSize, &H, &W);
  Check ("8bit.status", S == RETURN_SUCCESS);
  Check ("8bit.width", W == 2);
  Check ("8bit.height", H == 2);
  if ((S == RETURN_SUCCESS) && (Blt != NULL)) {
    Check ("8bit.top-left", PixelIs (&Blt[0], 30 ^ 0x55, 30, 255 - 30));
    Check ("8bit.top-right", PixelIs (&Blt[1], 40 ^ 0x55, 40, 255 - 40));
    Check ("8bit.bottom-left", PixelIs (&Blt[2], 10 ^ 0x55, 10, 255 - 10));
    Check ("8bit.bottom-right", PixelIs (&Blt[3], 20 ^ 0x55, 20, 255 - 20));
  } else {
    Check ("8bit.top-left", 0);
    Check ("8bit.top-right", 0);
    Check ("8bit.bottom-left", 0);
    Check ("8bit.bottom-right", 0);
  }

  if (Blt != NULL) {
    FreePool (Blt);
  }
}

static void
TestRejects (
  void
  )
{
  UINT8                          Bmp[54 + 16];
  UINT8                          Copy[54 + 16];
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Blt;
  UINTN                          BltSize, H, W;

  memset (Bmp, 0, sizeof (Bmp));
  PutHeader (Bmp, sizeof (Bmp), 54, 2, 2, 24);

  Blt = NULL;
  Check ("reject.null-image", TranslateBmpToGopBlt (NULL, sizeof (Bmp), &Blt, &BltSize, &H, &W) == RETURN_INVALID_PARAMETER);

  Blt = NULL;
  Check ("reject.truncated-header", TranslateBmpToGopBlt (Bmp, 20, &Blt, &BltSize, &H, &W) == RETURN_UNSUPPORTED);

  memcpy (Copy, Bmp, sizeof (Bmp));
  Copy[0] = 'X';
  Blt     = NULL;
  Check ("reject.bad-signature", TranslateBmpToGopBlt (Copy, sizeof (Copy), &Blt, &BltSize, &H, &W) == RETURN_UNSUPPORTED);

  memcpy (Copy, Bmp, sizeof (Bmp));
  PutHeader (Copy, sizeof (Copy), 54, 0, 2, 24);
  Blt = NULL;
  Check ("reject.zero-width", TranslateBmpToGopBlt (Copy, sizeof (Copy), &Blt, &BltSize, &H, &W) == RETURN_UNSUPPORTED);

  memcpy (Copy, Bmp, sizeof (Bmp));
  PutHeader (Copy, sizeof (Copy) + 4, 54, 2, 2, 24);
  Blt = NULL;
  Check ("reject.size-mismatch", TranslateBmpToGopBlt (Copy, sizeof (Copy), &Blt, &BltSize, &H, &W) == RETURN_UNSUPPORTED);

  memcpy (Copy, Bmp, sizeof (Bmp));
  ((BMP_IMAGE_HEADER *)Copy)->CompressionType = 1;
  Blt = NULL;
  Check ("reject.compressed", TranslateBmpToGopBlt (Copy, sizeof (Copy), &Blt, &BltSize, &H, &W) == RETURN_UNSUPPORTED);

  memcpy (Copy, Bmp, sizeof (Bmp));
  ((BMP_IMAGE_HEADER *)Copy)->HeaderSize = 12;
  Blt = NULL;
  Check ("reject.bad-headersize", TranslateBmpToGopBlt (Copy, sizeof (Copy), &Blt, &BltSize, &H, &W) == RETURN_UNSUPPORTED);
}

static void
TestRoundTrip (
  void
  )
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  In[6], *Out = NULL;
  UINT8                          *Bmp = NULL;
  UINT32                         BmpSize = 0;
  UINTN                          OutSize = 0, H = 0, W = 0, I;
  BMP_IMAGE_HEADER               *Hdr;
  RETURN_STATUS                  S;
  int                            Same;

  for (I = 0; I < 6; I++) {
    In[I].Red      = (UINT8)(10 * I + 1);
    In[I].Green    = (UINT8)(20 * I + 2);
    In[I].Blue     = (UINT8)(30 * I + 3);
    In[I].Reserved = 0;
  }

  S = TranslateGopBltToBmp (In, 2, 3, (VOID **)&Bmp, &BmpSize);
  Check ("encode.status", S == RETURN_SUCCESS);
  /* 3 px * 3 bytes + 3 bytes padding = 12 per row, 2 rows */
  Check ("encode.size", BmpSize == 54 + 24);
  if ((S != RETURN_SUCCESS) || (Bmp == NULL)) {
    Check ("encode.header", 0);
    Check ("encode.bottom-row-first", 0);
    Check ("roundtrip.status", 0);
    Check ("roundtrip.dims", 0);
    Check ("roundtrip.pixels", 0);
    return;
  }

  Hdr = (BMP_IMAGE_HEADER *)Bmp;
  Check (
    "encode.header",
    Hdr->CharB == 'B' && Hdr->CharM == 'M' && Hdr->Size == 78 && Hdr->ImageOffset == 54 &&
    Hdr->PixelWidth == 3 && Hdr->PixelHeight == 2 && Hdr->BitPerPixel == 24 && Hdr->Planes == 1
    );
  /* first stored row is the last Blt row (pixels 3..5), stored B,G,R */
  Check (
    "encode.bottom-row-first",
    Bmp[54] == In[3].Blue && Bmp[55] == In[3].Green && Bmp[56] == In[3].Red &&
    Bmp[54 + 12] == In[0].Blue && Bmp[54 + 13] == In[0].Green && Bmp[54 + 14] == In[0].Red
    );

  S = TranslateBmpToGopBlt (Bmp, BmpSize, &Out, &OutSize, &H, &W);
  Check ("roundtrip.status", S == RETURN_SUCCESS);
  Check ("roundtrip.dims", W == 3 && H == 2);
  Same = (S == RETURN_SUCCESS) && (Out != NULL);
  for (I = 0; Same && I < 6; I++) {
    Same = PixelIs (&Out[I], In[I].Red, In[I].Green, In[I].Blue);
  }

  Check ("roundtrip.pixels", Same);
  if (Out != NULL) {
    FreePool (Out);
  }

  FreePool (Bmp);
}

static void
Report (
  const char  *Path
  )
{
  FILE                           *F;
  UINT8                          *Buf;
  long                           Len;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Blt = NULL;
  UINTN                          BltSize = 0, H = 0, W = 0, I;
  RETURN_STATUS                  S;
  UINT32                         Hash = 2166136261u;
  const char                     *Base = strrchr (Path, '/');

  Base = Base ? Base + 1 : Path;
  F    = fopen (Path, "rb");
  if (F == NULL) {
    printf ("RESULT %s unreadable 0 0 0\n", Base);
    return;
  }

  fseek (F, 0, SEEK_END);
  Len = ftell (F);
  rewind (F);
  Buf = malloc (Len > 0 ? (size_t)Len : 1);
  if (fread (Buf, 1, (size_t)Len, F) != (size_t)Len) {
    printf ("RESULT %s unreadable 0 0 0\n", Base);
    fclose (F);
    free (Buf);
    return;
  }

  fclose (F);
  S = TranslateBmpToGopBlt (Buf, (UINTN)Len, &Blt, &BltSize, &H, &W);
  if ((S == RETURN_SUCCESS) && (Blt != NULL)) {
    /* B,G,R only: the Reserved byte is not initialised by the library for every depth */
    for (I = 0; I < BltSize / sizeof (*Blt); I++) {
      Hash = (Hash ^ Blt[I].Blue) * 16777619u;
      Hash = (Hash ^ Blt[I].Green) * 16777619u;
      Hash = (Hash ^ Blt[I].Red) * 16777619u;
    }
  } else {
    H = W = 0;
  }

  printf ("RESULT %s 0x%lx %lu %lu %08x\n", Base, (unsigned long)S, (unsigned long)W, (unsigned long)H, Hash);
  if (Blt != NULL) {
    FreePool (Blt);
  }

  free (Buf);
}

int
main (
  int   argc,
  char  **argv
  )
{
  int  I;

  if (argc > 1) {
    for (I = 1; I < argc; I++) {
      Report (argv[I]);
    }

    return 0;
  }

  Test24Bit ();
  Test8Bit ();
  TestRejects ();
  TestRoundTrip ();
  return mFail ? 1 : 0;
}
