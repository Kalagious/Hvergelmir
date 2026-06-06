#include "Hvergelmir.h"
#include <memory>
#include "threadNameManager.h"
#include "ioRingManager.h"

Hvergelmir::Hvergelmir()
    : memoryBroker()
{
    // default state
    systemVerified = false;

    // safe no-op defaults for overflow callbacks
    PrimeOverflow = [](UINT64) {};
    TriggerOverflow = [](BYTE*, UINT64) {};
    PassOverflow = []() {};

    // ensure memoryBroker is default-constructed (already a member)
    // create and register managers so MemoryBroker's weak_ptrs lock
    nameManagerPtr = std::make_shared<ThreadNameManager>();
    ioRingManagerPtr = std::make_shared<IORingManager>();
    pipeManagerPtr = std::make_shared<PipeManager>(CHUNKSIZE);

    memoryBroker.SetNameManager(nameManagerPtr);
    memoryBroker.SetIoRingManager(ioRingManagerPtr);
    memoryBroker.SetPipeManager(pipeManagerPtr);
}

