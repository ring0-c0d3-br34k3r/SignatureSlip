//-------------------------------------------------------------------------------------------------
#ifndef MAIN_H
#define MAIN_H

#include "ntdll\ntdll.h"
#include "ntdll\ntstatus.h"
#include "SignatureSlip.h"
#include "vbox.h"
#include "vboxdrv.h"
#include "ldasm.h"
#include "rtls\prtl.h"
#include "ntdll\winnative.h"

#define BUFFER_SIZE MAX_PATH * 2
#define VBoxDrvDispName L"Steam Drivers"
#define VBoxDrvRegPath   L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\vboxdrv"
#define VBoxDrvDevName  L"\\Device\\VBoxDrv"

#endif
//-------------------------------------------------------------------------------------------------
