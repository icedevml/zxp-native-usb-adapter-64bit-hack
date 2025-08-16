/**
 * Bug workaround for ZebraNativeUsbAdapter_64.dll
 * This DLL is intended to act as a DLL proxy for MSVCR90.DLL imported by ZebraNativeUsbAdapter_64.dll
 * It will patch the memory allocator with a workaround so everything works under 64 bits.
 *
 * MQALLOC: Absolutely terrible but sufficiently working memory allocator(TM).
 * Ensures that the virtual addresses of the memory allocated with `operator new` or `operator delete`
 * are below 2^32, so there wouldn't be a crash when the pointer is accidentally truncated from uint64_t
 * to uint32_t anywhere in the process (lol).
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(linker, "/export:_lock=MSVCR90._lock")
#pragma comment(linker, "/export:__dllonexit=MSVCR90.__dllonexit")
#pragma comment(linker, "/export:_unlock=MSVCR90._unlock")
#pragma comment(linker, "/export:__clean_type_info_names_internal=MSVCR90.__clean_type_info_names_internal")
#pragma comment(linker, "/export:strncpy_s=MSVCR90.strncpy_s")
#pragma comment(linker, "/export:_strnicmp=MSVCR90._strnicmp")
#pragma comment(linker, "/export:?terminate@@YAXXZ=MSVCR90.?terminate@@YAXXZ")
#pragma comment(linker, "/export:__crt_debugger_hook=MSVCR90.__crt_debugger_hook")
#pragma comment(linker, "/export:__CppXcptFilter=MSVCR90.__CppXcptFilter")
#pragma comment(linker, "/export:__C_specific_handler=MSVCR90.__C_specific_handler")
#pragma comment(linker, "/export:_amsg_exit=MSVCR90._amsg_exit")
#pragma comment(linker, "/export:_decode_pointer=MSVCR90._decode_pointer")
#pragma comment(linker, "/export:_encoded_null=MSVCR90._encoded_null")
#pragma comment(linker, "/export:_initterm_e=MSVCR90._initterm_e")
#pragma comment(linker, "/export:_initterm=MSVCR90._initterm")
#pragma comment(linker, "/export:_malloc_crt=MSVCR90._malloc_crt")
#pragma comment(linker, "/export:_encode_pointer=MSVCR90._encode_pointer")
#pragma comment(linker, "/export:_onexit=MSVCR90._onexit")
#pragma comment(linker, "/export:__CxxFrameHandler3=MSVCR90.__CxxFrameHandler3")
#pragma comment(linker, "/export:?what@exception@std@@UEBAPEBDXZ=MSVCR90.?what@exception@std@@UEBAPEBDXZ")
#pragma comment(linker, "/export:tolower=MSVCR90.tolower")
#pragma comment(linker, "/export:strcpy_s=MSVCR90.strcpy_s")
#pragma comment(linker, "/export:_invalid_parameter_noinfo=MSVCR90._invalid_parameter_noinfo")
#pragma comment(linker, "/export:??1exception@std@@UEAA@XZ=MSVCR90.??1exception@std@@UEAA@XZ")
#pragma comment(linker, "/export:malloc=MSVCR90.malloc")
#pragma comment(linker, "/export:free=MSVCR90.free")
#pragma comment(linker, "/export:?_type_info_dtor_internal_method@type_info@@QEAAXXZ=MSVCR90.?_type_info_dtor_internal_method@type_info@@QEAAXXZ")
#pragma comment(linker, "/export:_CxxThrowException=MSVCR90._CxxThrowException")

// from C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\km\ntifs.h

//@[comment("MVI_tracked")]
_Must_inspect_result_
__drv_allocatesMem(Mem)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_ (*BaseAddress, _Readable_bytes_ (*RegionSize) _Writable_bytes_ (*RegionSize) _Post_readable_byte_size_ (*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    );

//@[comment("MVI_tracked")]
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    );

#define STATUS_NO_MEM_REGION         (0xE000AC01UL)
#define STATUS_TOO_BIG_ALLOC         (0xE000AC02UL)
#define STATUS_OUT_OF_STATIC_POOL    (0xE000AC03UL)
#define STATUS_DOUBLE_FREE           (0xE000AC04UL)
#define STATUS_BAD_FREE              (0xE000AC05UL)
#define STATUS_INIT_FAILED           (0xE000AC06UL)
#define STATUS_MUTEX_OBTAIN          (0xE000AC07UL)
#define STATUS_NO_DEALLOC_ALG        (0xE000AC08UL)

#define ALLOC_CHUNKS_NUM             (1024)
#define ALLOC_CHUNK_SIZE             (280)

#define MEM_REGION_VA_UPPER_BOUND     (0x80000000ULL)
#define MEM_REGION_SIZE               (ALLOC_CHUNKS_NUM * ALLOC_CHUNK_SIZE)
#define MEM_REGION_SEARCH_HIGH_BOUND  (0xFE000000ULL)
#define MEM_REGION_SEARCH_LOW_BOUND   (0x01000000ULL)
#define MEM_REGION_SEARCH_STEP        (0x01000000ULL)

#define err_print(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while (0)
#define dbg_print(...) if (enable_debug) { fprintf(stderr, __VA_ARGS__); fflush(stderr); }

uint8_t enable_debug = FALSE;
uint8_t alloc_stage = 0;
PVOID mem_region = NULL;
volatile uint8_t alloc_table[ALLOC_CHUNKS_NUM];
HANDLE mutex = NULL;

void fail(DWORD excCode) {
    if (excCode != STATUS_MUTEX_OBTAIN) {
        ReleaseMutex(mutex);
    }

    RaiseException(excCode, EXCEPTION_NONCONTINUABLE_EXCEPTION, 0, NULL);
}

#pragma comment(linker, "/export:??2@YAPEAX_K@Z=patch_operator_new")
void *__fastcall patch_operator_new(unsigned __int64 size) {
    DWORD dwWaitResult = WaitForSingleObject(mutex, INFINITE);

    if (dwWaitResult != WAIT_OBJECT_0) {
        err_print("[MQALLOC] BUG! Failed to obtain mutex in patch_operator_new.\n");
        fail(STATUS_MUTEX_OBTAIN);
        return NULL;
    }

    if (mem_region == NULL) {
        err_print("[MQALLOC] BUG! Allocation failed, mem_region is not initialized.\n");
        fail(STATUS_NO_MEM_REGION);
        return NULL;
    }

    if (size > ALLOC_CHUNK_SIZE) {
        err_print("[MQALLOC] BUG! Allocation of %lld bytes failed, we only support "
                  "allocating up to %lld bytes at once.\n", size, (unsigned long long) ALLOC_CHUNK_SIZE);
        fail(STATUS_TOO_BIG_ALLOC);
        return NULL;
    }

    for (int i = 0; i < ALLOC_CHUNKS_NUM; i++) {
        if (alloc_table[i] == 0) {
            alloc_table[i] = TRUE;
            uint64_t off = i * ALLOC_CHUNK_SIZE;

            void* out = (void *) ((uint64_t) mem_region + off);

            dbg_print("[MQALLOC] patch_operator_new(%lld) => allocated 0x%llx\n", size, (unsigned long long) out);

            ReleaseMutex(mutex);
            return out;
        }
    }

    err_print("[MQALLOC] BUG! Unable to allocate memory out of static pool. "
           "More than %d open printers?\n", ALLOC_CHUNKS_NUM);
    fail(STATUS_OUT_OF_STATIC_POOL);
    return NULL;
}

#pragma comment(linker, "/export:??3@YAXPEAX@Z=patch_operator_delete")
void __fastcall patch_operator_delete(void *ptr) {
    DWORD dwWaitResult = WaitForSingleObject(mutex, INFINITE);

    if (dwWaitResult != WAIT_OBJECT_0) {
        err_print("[MQALLOC] BUG! Failed to obtain mutex in patch_operator_delete.\n");
        fail(STATUS_MUTEX_OBTAIN);
        return;
    }

    if (mem_region == NULL) {
        err_print("[MQALLOC] BUG! Deallocation failed, mem_region is not initialized.\n");
        fail(STATUS_NO_MEM_REGION);
        return;
    }

    dbg_print("[MQALLOC] patch_operator_delete(0x%llx)\n", (uint64_t) ptr);

    for (int i = 0; i < ALLOC_CHUNKS_NUM; i++) {
        uint64_t off = i * ALLOC_CHUNK_SIZE;

        if (ptr == (void *)((uint64_t) mem_region + off)) {
            if (!alloc_table[i]) {
                err_print("[MQALLOC] BUG! Freeing region that was not allocated: 0x%llx.\n",
                       (unsigned long long) ptr);
                fail(STATUS_DOUBLE_FREE);
                return;
            }

            alloc_table[i] = FALSE;
            ReleaseMutex(mutex);
            return;
        }
    }

    err_print("[MQALLOC] BUG! Requested to delete unrecognized pointer: 0x%llx\n",
            (unsigned long long) ptr);
    fail(STATUS_BAD_FREE);
}

BOOL alloc_stage1_nt_allocate_zero_bits(VOID) {
    dbg_print("[MQALLOC] Trying to allocate low-address region with NtAllocateVirtualMemory and ZeroBits mask.\n");

    PVOID alloc_ptr = NULL;
    SIZE_T region_size = MEM_REGION_SIZE;
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &alloc_ptr,
        MEM_REGION_VA_UPPER_BOUND - 1,
        &region_size,
        MEM_TOP_DOWN | MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (status) {
        dbg_print("[MQALLOC] BUG! Failed to allocate low-address region. NTSTATUS=0x%lx.\n", status);
        return FALSE;
    }

    if (alloc_ptr >= (PVOID) MEM_REGION_VA_UPPER_BOUND) {
        dbg_print("[MQALLOC] BUG! Allocated region is not low-address: %llx\n", (unsigned long long) alloc_ptr);
        return FALSE;
    }

    mem_region = alloc_ptr;
    alloc_stage = 1;
    return TRUE;
}

VOID free_stage1_nt_allocate_zero_bits(VOID) {
    if (mem_region != NULL) {
        PVOID base_address = mem_region;
        SIZE_T freed_region_size = 0;
        NtFreeVirtualMemory(
            GetCurrentProcess(),
            &base_address,
            &freed_region_size,
            MEM_RELEASE);
    }
}

BOOL alloc_stage2_loop_virtualalloc(VOID) {
    dbg_print("[MQALLOC] Trying to loop VirtualAlloc to find suitable address.\n");

    for (uint64_t iaddr = MEM_REGION_SEARCH_HIGH_BOUND;
            iaddr >= MEM_REGION_SEARCH_LOW_BOUND;
            iaddr -= MEM_REGION_SEARCH_STEP) {
        PVOID alloc_ptr = VirtualAlloc((PVOID) iaddr, MEM_REGION_SIZE,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (alloc_ptr != NULL) {
            mem_region = alloc_ptr;
            alloc_stage = 2;
            return TRUE;
        }
    }

    dbg_print("[MQALLOC] BUG! Failed to find suitable address using VirtualAlloc loop.\n");
    return FALSE;
}

VOID free_stage2_loop_virtualalloc(VOID) {
    if (mem_region != NULL) {
        VirtualFree(mem_region, MEM_REGION_SIZE, MEM_RELEASE);
    }
}

BOOL alloc_low_address_region(VOID) {
    if (alloc_stage1_nt_allocate_zero_bits()) {
        return TRUE;
    }

    if (alloc_stage2_loop_virtualalloc()) {
        return TRUE;
    }

    dbg_print("[MQALLOC] Failure, none of implemented approaches succeeded allocating low-address region.\n");
    return FALSE;
}

VOID free_low_address_region(VOID) {
    dbg_print("[MQALLOC] Freeing low-address region created by stage %d algorithm.\n", alloc_stage);

    if (mem_region == NULL || alloc_stage == 0) {
        dbg_print("[MQALLOC] Nothing to free up, the memory region was not allocated yet.\n");
    }

    if (alloc_stage == 1) {
        free_stage1_nt_allocate_zero_bits();
    } else if (alloc_stage == 2) {
        free_stage2_loop_virtualalloc();
    } else {
        err_print("[MQALLOC] BUG! Memory deallocation algorithm not implemented for that alloc_stage.");
        fail(STATUS_NO_DEALLOC_ALG);
    }
}

BOOL WINAPI DllMain(
        HINSTANCE hinstDLL,
        DWORD fdwReason,
        LPVOID lpReserved )
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpReserved);

    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH:
            char inBuff[256];
            enable_debug = 0;
            DWORD getEnvRes = GetEnvironmentVariable("DEBUG_MQALLOC", inBuff, 256);

            if (getEnvRes > 0 && getEnvRes < 256 && strcmp(inBuff, "1") == 0) {
                enable_debug = TRUE;
            }

            if (enable_debug) {
                err_print("[MQALLOC] Loading ZebraNativeUsbAdapter_64.dll allocator compatibility hack by MQ\n");
                err_print("[MQALLOC] Version: {{BUILD_ID}}\n");
                err_print(""
                       "                       __________.__        __   __                __ ________  \n"
                       "   /\\_/\\               \\____    /|__|__ ___/  |_|  | _______      / / \\_____  \\ \n"
                       "   >^.^<.---.            /     / |  |  |  \\   __\\  |/ /\\__  \\    / /    _(__  < \n"
                       "  _'-`-'     )\\         /     /_ |  |  |  /|  | |    <  / __ \\_  \\ \\   /       \\\n"
                       " (6--\\ |--\\ (`.`-.     /_______ \\|__|____/ |__| |__|_ \\(____  /   \\_\\ /______  /\n"
                       "     --'  --'  ``-'BP          \\/                    \\/     \\/               \\/ \n");
            }

            for (int i = 0; i < ALLOC_CHUNKS_NUM; i++) {
                alloc_table[i] = FALSE;
            }

            if (!alloc_low_address_region()) {
                err_print("[MQALLOC] Failed to allocate low-address region.\n");
                fail(STATUS_INIT_FAILED);
                return FALSE;
            }

            mutex = CreateMutex(NULL, FALSE, NULL);

            if (mutex == NULL) {
                err_print("[MQALLOC] Failed to create mutex.\n");
                fail(STATUS_INIT_FAILED);
                return FALSE;
            }

            dbg_print("[MQALLOC] Allocated low-address region: 0x%llx\n",
                (unsigned long long) mem_region);
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            dbg_print("[MQALLOC] Detaching from the process\n");
            free_low_address_region();
            break;
    }

    return TRUE;
}
