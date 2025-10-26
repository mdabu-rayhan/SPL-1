#pragma once
#include "utils.h"
#include <string>
using namespace std;

namespace PacketCapture
{
    // start simulated capture in a blocking call; returns when stopped
    void startCapture(const string &iface);
    // stop capture by setting global flag (main uses running flag)
    void stopCapture();
}
