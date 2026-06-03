#include "Hvergelmir.h"

Hvergelmir::Hvergelmir()
{
    // default state
    systemVerified = false;

    // safe no-op defaults for overflow callbacks
    PrimeOverflow = [](UINT64) {};
    TriggerOverflow = [](BYTE*, UINT64) {};
    PassOverflow = []() {};
}
