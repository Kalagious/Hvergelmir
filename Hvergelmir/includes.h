#pragma once
#include <windows.h>
#include <iostream>
#include <psapi.h>
#include <ioringapi.h>
#include <cstdio>
#include <winternl.h>
#include <functional>
#include <vector>
#include <algorithm>
#include <ntstatus.h>
#include "config.h"



#ifdef DEBUG
#define DEBUG_PRINT(...) std::printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) ((void)0)
#endif