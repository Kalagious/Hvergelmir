#include <iostream>
#include <cstddef>
#include "includes.h"
#include "poolObjects.h"
#include "threadNameManager.h"
#include "pipeManager.h"
#include "Hvergelmir.h"

// Compile-time layout checks (static asserts) for poolObjects.h
/*
int main() {

    Hvergelmir::getInstance().SetOverflowFunctions(nullptr, nullptr, nullptr); // ensure static initialization runs
	Hvergelmir::getInstance().VerifySystem(); // ensure static initialization runs




    // Basic runtime smoke checks
    ThreadNameManager tnm;
    // Ensure we can create and clear a small number of threads without crashing.
    tnm.CreateThreads(4);
    Sleep(100);
    tnm.ClearThreads();

    // LeakData should return NULL when no leakThread is present
    BYTE* leak = tnm.LeakDataMalloc();
    if (leak != NULL) {
        std::cout << "Warning: LeakData returned non-NULL in smoke test.\n";
        free(leak);
    }

    // Invalid GetDataLeak parameters should fail fast
    bool got = tnm.GetDataLeak(0x10, 0x10, 1);
    if (got) {
        std::cout << "Warning: GetDataLeak succeeded unexpectedly.\n";
    }

    // PipeManager smoke test
    PipeManager pm(0x200); // chunk size -> pipeSize = 0x200 - 0x40
    pm.CreatePipes(4);
    Sleep(100);
    bool corrupted = pm.VerifyCorruption();
    std::cout << "PipeManager VerifyCorruption returned: " << (corrupted ? "true" : "false") << "\n";
    // exercise ClearExtraPipes and cleanup
    if (!pm.sPipes.empty()) pm.ClearExtraPipes(0);
    pm.ClearPipes();
    
    std::cout << "Runtime smoke tests completed.\n";
    return 0;
}*/
