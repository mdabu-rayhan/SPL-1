#pragma once
#include "packet.h"
#include "../include/firewall.h"

void printPacketLog(const Packet&, const Decision&);
void printLiveStats();

// Call once at start
void initUI();
