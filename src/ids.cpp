#include "../include/ids.h"
#include <iostream>
#include <map>
#include <deque>
#include <mutex>
#include "../include/color.h"

using namespace std;

namespace IDS {

    const int DOS_THRESHOLD = 1000; // packets per second
    const int TIME_WINDOW_MS = 1000; // 1 second

    
    struct Flow {
        deque<long long> timestamps;
    };

    
    map<string, Flow> flowTable;
    mutex idsLock;

    void init() {
        cout << "[IDS] " << GREEN << "Intrusion Detection System Initialized" << RESET << endl;
    }

    void shutdown() {
        cout << "[IDS] " << YELLOW << "Shutting down Intrusion Detection System" << RESET << endl;
    }

    
    bool analyze(const Packet &p) {
        lock_guard<mutex> guard(idsLock);

        
        Flow &f = flowTable[p.srcIP];

        {
            f.timestamps.push_back(p.timestamp_ms);

            long long cutoff = p.timestamp_ms - TIME_WINDOW_MS;
            while (!f.timestamps.empty() && f.timestamps.front() < cutoff) {
            f.timestamps.pop_front();
                /*you can think like that first one are not in last 1 second so remove it 
                cause we only care about last 1 second packets number thats why pop from front*/
            }
        } // new one are added at back and old one are removed from front if it's not in the last 1 second
    

        
        if (f.timestamps.size() > DOS_THRESHOLD) {
            return true; 
        }

        return false;
    }
}