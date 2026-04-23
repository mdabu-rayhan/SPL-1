#include "../include/blockchain.h"
#include "../include/sha256.h"
#include "../include/color.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <sstream>

using namespace std;

// Global Chain State
vector<Block> chain;

const string CHAIN_FILE = "logs/blockchain_log.txt";

namespace Blockchain {

    string getCurrentTime() {
        time_t now = time(0);
        char* dt = ctime(&now);
        string t(dt);
        t.pop_back(); //Remove newline character
        return t;
    }

    void saveBlockToFile(const Block &b) {
        ofstream file(CHAIN_FILE, ios::app); //ios::app for appending to the file remaining previous file data
        if (file.is_open()) {
            file << "--------------------------------------------------\n";
            file << "Block Index: " << b.index << "\n";
            file << "Timestamp  : " << b.timestamp << "\n";
            file << "Data       : " << b.data << "\n";
            file << "Prev Hash  : " << b.prevHash << "\n";
            file << "Hash       : " << b.hash << "\n";
            file << "--------------------------------------------------\n";
            file.close();
        }
    }

    void init() {
        Block genesis;
        genesis.index = 0;
        genesis.timestamp = getCurrentTime();
        genesis.data = "Genesis Block";
        genesis.prevHash = "000md0000000abu00000000rayhan000";
        
        SHA256 sha;
        stringstream ss;
        ss << genesis.index << genesis.timestamp << genesis.data << genesis.prevHash;
        genesis.hash = sha.hash(ss.str());

        chain.push_back(genesis);
        
        ofstream file(CHAIN_FILE, ios::trunc); // ios::trunc for removing old data and start with fresh data
        file.close();

        saveBlockToFile(genesis);
        cout << "[Blockchain] " << GREEN << "Initialized with Genesis Block." << RESET << endl;
    }

    void addBlock(const string &data) {
        if (chain.empty()) init();

        Block newBlock;
        Block &lastBlock = chain.back();

        newBlock.index = chain.size();
        newBlock.timestamp = getCurrentTime();
        newBlock.data = data;
        newBlock.prevHash = lastBlock.hash;

        SHA256 sha;
        stringstream ss;
        ss << newBlock.index << newBlock.timestamp << newBlock.data << newBlock.prevHash;
        newBlock.hash = sha.hash(ss.str());

        chain.push_back(newBlock);
        saveBlockToFile(newBlock);
    }

    int size() {
        return chain.size();
    }

    
    bool verifyChain() {
        ifstream file(CHAIN_FILE);
        if (!file.is_open()) {
            cout << RED << "Error: Cannot open " << CHAIN_FILE << " for verification!" << RESET << endl;
            return false;
        }

        string line, b_index, b_time, b_data, b_prev, b_hash;

        while (getline(file, line)) {
            // Jokhon-i divider line pabe, tar mane ekta block shuru hocche
            if (line.find("--------------------------------------------------") != string::npos) {
                
                if (!getline(file, b_index)) break; 
                
                getline(file, b_time);
                getline(file, b_data);
                getline(file, b_prev);
                getline(file, b_hash);
                getline(file, line);

                // shurute 13 ta character er prefix ache jemon "Block Index: " oita remove korar jonno
                string idx = b_index.substr(13);
                string time = b_time.substr(13);
                string data = b_data.substr(13);
                string prev = b_prev.substr(13);
                string hash = b_hash.substr(13);

                int current_idx = stoi(idx); 

                // jodi extra fake block thake
                if (current_idx >= chain.size()) {
                    cout << RED << BOLD << "\n[ALERT] BLOCKCHAIN TAMPERED!\n" << RESET << endl;
                    cout << YELLOW << "=> Extra fake block found in file at Index: " << RED << idx << RESET << endl;
                    cout << endl;
                    return false;
                }

                // Direct RAM (chain vector) er sathe shob kichu exactly match kora
                if (hash != chain[current_idx].hash || 
                    data != chain[current_idx].data || 
                    time != chain[current_idx].timestamp || 
                    prev != chain[current_idx].prevHash) {
                     
                    cout << RED << BOLD << "\n[ALERT] BLOCKCHAIN TAMPERED!\n" << RESET << endl;
                    cout << YELLOW << "=> Immutability broken at Block Index: " << RED << idx << RESET << endl;
                    cout << endl;
                    return false;
                }
            }
        }
        return true;
    }
}