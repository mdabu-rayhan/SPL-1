// ...existing code...
#include <iostream>
#include <thread>
// replace the .cpp include with the header
#include "../include/packet_capture_manual.h"
#include "../include/firewall.h"
#include "../include/stats.h"
#include "../include/color.h"

using namespace std;

// Forward declarations in case the header does not declare them
void startCapture(const char* device);
void stopCapture();

int main() {
    
    const char* device = "lo";   // or "wlan0"

    // Run sniffer in a separate thread
    thread captureThread([&]() {
        startCapture(device);
    });

    cout << "Press" << RED << " ENTER " << RESET << "to stop capturing...\n";
    cin.get();   // Wait for user input

    stopCapture();     // Stop packet loop
    captureThread.join();

    cout<< GREEN << "\n                                Program finished.\n" << RESET;
    return 0;
}
