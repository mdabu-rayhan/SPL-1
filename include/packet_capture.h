#pragma once
#include "packet.h"
#include <string>
using namespace std;

namespace PacketCapture
{
    // start simulated capture in a blocking call; returns when stopped
    void startCapture(const char* device);
    // stop capture by setting global flag (main uses running flag)
    void stopCapture();
}
