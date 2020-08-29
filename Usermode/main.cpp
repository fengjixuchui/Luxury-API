#include "api.h"


#define CurrentProcess() std::make_unique<CurrentProcInfo>(CurrentProcInfo())


typedef struct {
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;
     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     _ACTIVATION_CONTEXT * EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} LoaderDataTableEntry;


PEB* GetPeb() {
	return reinterpret_cast<PEB*>(__readgsqword(0x60));
}


template <typename T>
void EnumModuleList(T Callback) {
    auto Peb{ GetPeb() };

    auto ListHead{ Peb->Ldr->InMemoryOrderModuleList.Flink };
    auto Next{ ListHead };

    do {

        auto Entry{ reinterpret_cast<LoaderDataTableEntry*>(CONTAINING_RECORD(ListHead, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)) };

        if (!Entry->DllBase) {
            break;
        }

        wchar_t CurName[256]{ 0 };
        memcpy(CurName, Entry->BaseDllName.Buffer, Entry->BaseDllName.Length);

        if (Callback(Entry, CurName))
            return;

        ListHead = Entry->InMemoryOrderLinks.Flink;

    } while (ListHead != Next);
}


typedef struct CurrentProcInfo {
public:

    std::wstring Name;
    DWORD64 Base;
    DWORD Size;
    PEB* Peb;

    CurrentProcInfo() {
        this->Name = PathFindFileNameW(Path.CurrentExecutableW().c_str());
        this->Peb = GetPeb();

        auto Callback {
            [this] ( LoaderDataTableEntry* Module, const wchar_t* ModuleName ) -> bool {
                if (!wcscmp(this->Name.c_str(), ModuleName)) {
                    this->Base = reinterpret_cast<DWORD64>(Module->DllBase);
                    this->Size = Module->SizeOfImage;
                    return true;
                }

                return false;
            }
        };

        EnumModuleList(Callback);
    }
};


class MemoryHeuristics {

public:

	static BYTE* InvalidMemoryScan() {
        bool bDetection{ false };

        DWORD64 Address{ NULL };

		auto Callback { 
            [ &bDetection, Address ] ( LoaderDataTableEntry* Module, const wchar_t* ModuleName ) -> bool {
                if ( Address >= reinterpret_cast <DWORD64> ( Module->DllBase ) 
                    && Address <= reinterpret_cast <DWORD64> ( Module->DllBase ) + Module->SizeOfImage ) {
                    return bDetection = true;
                }

                return bDetection = false;
            }
        };

        SYSTEM_INFO SysInfo{ 0 };
        GetSystemInfo(&SysInfo);

        MEMORY_BASIC_INFORMATION Mbi{ 0 };

        for (SIZE_T i = 0; i <= reinterpret_cast<DWORD64>(SysInfo.lpMaximumApplicationAddress); i += 0x8) {
            if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<PVOID>(i), 0, &Mbi, sizeof(Mbi), nullptr))) {
                if ((Mbi.Protect == PAGE_EXECUTE_READWRITE
                    || Mbi.Protect == PAGE_EXECUTE_READ
                    || Mbi.Protect == PAGE_EXECUTE_WRITECOPY) && Mbi.Type == MEM_MAPPED) {
                    Address = i; 
                    EnumModuleList(Callback);

                    if (bDetection) {
                        return reinterpret_cast<BYTE*>(i);
                    }
                }
            }
        }

        return nullptr; 
	}
};


void thrd() {
     if (auto mem = MemoryHeuristics::InvalidMemoryScan()) {
         MessageBoxA(nullptr, "FOUND", "INVALID MEM", MB_OK);
        std::cout << "Invalid Memory at: 0x" << std::hex << std::uppercase << mem;
    } else {
         MessageBoxA(nullptr, "NONE FOUND", "NO INVALID MEM", MB_OK);
        std::cout << "No Invalid Memory Detected!";
    }
}
int main() {
   
    SpawnThread(thrd);
	getchar();
    return 0;
}