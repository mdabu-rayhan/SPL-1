// src/main.cpp er update
#include <iostream>
#include <thread>
#include <string> // string use korar jonno

#include "../include/packet_capture_manual.h"
#include "../include/firewall.h"
#include "../include/stats.h"
#include "../include/color.h"
#include "../include/blockchain.h" // Blockchain check korar jonno add kora holo

using namespace std;

void startCapture(const char* device);
void stopCapture();

extern void initUI();

int main() {
    
    char device[100]; // = "eth0";   // or "wlan0" / eth0
    cout << CYAN << "Enter Network Interface: " << RESET;
    cin.getline(device, sizeof(device));

    Blockchain::init();

    // Run sniffer
    thread captureThread([&]() {
        startCapture(device);
    });

    this_thread::sleep_for(chrono::milliseconds(500));

    cout << "Press" << RED << " ENTER " << RESET << "to stop capturing...\n\n";
    cin.get();   

    stopCapture();     
    captureThread.join();

    // ==========================================
    // Immutability Check (New Feature)
    // ==========================================
    cout << YELLOW << "\nDo you want to check logfile immutability? (yes/no): " << RESET;
    string choice;
    getline(cin, choice);

    if (choice == "yes" || choice == "y" || choice == "Y" || choice == "Yes") {
        cout << CYAN << "\nVerifying Blockchain Integrity...\n" << RESET << endl;
        
        if (Blockchain::verifyChain()) {
            cout << GREEN << "[SUCCESS] Blockchain logs are valid. No tampering detected!" << RESET << endl;
        } else {
            cout << RED << "[ALERT] Blockchain integrity failed! Logs have been tampered with!" << RESET << endl;
        }
    }

    cout<< GREEN << "\n                                Program finished.\n" << RESET;
    return 0;
}