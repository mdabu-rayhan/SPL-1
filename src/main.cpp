#include <iostream>
#include <thread>
#include <string> 

#include "../include/packet_capture_manual.h"
#include "../include/firewall.h"
#include "../include/stats.h"
#include "../include/color.h"
#include "../include/blockchain.h" 

using namespace std;

void startCapture(const char* device);
void stopCapture();


int main() {
    
    char device[100]; // "wlan0", "eth0"
    cout << CYAN << "Enter Network Interface: " << RESET;
    cin.getline(device, sizeof(device));

    thread captureThread([&]() {
        startCapture(device);
    });

    this_thread::sleep_for(chrono::milliseconds(500));

    cout << "Press" << RED << " ENTER " << RESET << "to stop capturing...\n\n";
    cin.get();   

    stopCapture();     
    captureThread.join();

    cout << YELLOW << "\nDo you want to check logfile immutability? (yes/no): " << RESET;
    string choice;
    getline(cin, choice);

    if (choice == "yes") {
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



/*
nmap -p 1-100 --min-rate 100 127.0.0.1

sudo hping3 -c 1500 -i u500 -I lo 127.0.0.1

curl http://127.0.0.1 and ping -c 3 127.0.0.1
*/