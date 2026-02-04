#include <iostream>
#include <thread>

#include "../include/packet_capture_manual.h"
#include "../include/firewall.h"
#include "../include/stats.h"
#include "../include/color.h"

using namespace std;

// Forward declarations in case the header does not declare them
void startCapture(const char* device);
void stopCapture();

int main() {
    
    char device[100]; // = "eth0";   // or "wlan0" / eth0
    cout << CYAN << "Enter Network Interface: " << RESET;
    cin.getline(device, sizeof(device));


    // Run sniffer
    thread captureThread([&]() {
        startCapture(device);
    });

    cout << "Press" << RED << " ENTER " << RESET << "to stop capturing...\n";
    cin.get();   

    stopCapture();     
    captureThread.join();

    cout<< GREEN << "\n                                Program finished.\n" << RESET;
    return 0;
}
