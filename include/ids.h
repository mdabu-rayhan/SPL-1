#pragma once
#include "utils.h"

namespace IDS
{
    void init();
    void shutdown();
    // analyze returns true if suspicious
    bool analyze(const Packet &p);
}
