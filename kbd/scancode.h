#include <ntddk.h>
#include <ntstrsafe.h>
#include "ntddkbd.h"
#include "source.h"

VOID ConvertScanCodeToKeyCode(PDEVICE_EXTENSION pDevExt, KEY_DATA* kData, char* keys);