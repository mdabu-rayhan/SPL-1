// src/blockchain.cpp er update
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

// Path change kore logs/ folder e deya holo
const string CHAIN_FILE = "logs/blockchain_log.txt";

namespace Blockchain {

    string getCurrentTime() {
        time_t now = time(0);
        char* dt = ctime(&now);
        string t(dt);
        t.pop_back(); 
        return t;
    }

    void saveBlockToFile(const Block &b) {
        ofstream file(CHAIN_FILE, ios::app);
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
        genesis.data = "Genesis Block - Network Monitor Started";
        genesis.prevHash = "000md0000000abu00000000rayhan000";
        
        SHA256 sha;
        stringstream ss;
        ss << genesis.index << genesis.timestamp << genesis.data << genesis.prevHash;
        genesis.hash = sha.hash(ss.str());

        chain.push_back(genesis);
        
        ofstream file(CHAIN_FILE, ios::trunc); 
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
        string expected_prev_hash = "000md0000000abu00000000rayhan000"; 
        bool isGenesis = true;

        // File theke line by line read korbe
        while (getline(file, line)) {
            // Jokhon-i divider line pabe, tar mane ekta block shuru hocche
            if (line.find("--------------------------------------------------") != string::npos) {
                
                if (!getline(file, b_index)) break; // File shesh hoye gele break
                
                getline(file, b_time);
                getline(file, b_data);
                getline(file, b_prev);
                getline(file, b_hash);
                getline(file, line); // Nicher divider line ta skip korar jonno

                // String theke asol value gulo extract kora hocche
                // (Protyekta line er shurute 13 ta character er prefix ache jemon "Block Index: ")
                string idx = b_index.substr(13);
                string time = b_time.substr(13);
                string data = b_data.substr(13);
                string prev = b_prev.substr(13);
                string hash = b_hash.substr(13);

                // Hash calculation
                SHA256 sha;
                stringstream ss;
                ss << idx << time << data << prev;
                string calculated_hash = sha.hash(ss.str());

                // 1. Check jodi Block er data change kora hoy (hash mismatch)
                // 2. Check jodi kono block delete kore deya hoy (chain link broken)
                if (calculated_hash != hash || (!isGenesis && prev != expected_prev_hash)) {
                    cout << RED << BOLD << "\n[ALERT] BLOCKCHAIN TAMPERED!\n" << RESET << endl;
                    cout << YELLOW << "=> Immutability broken at Block Index: " << RED << idx << RESET << endl;
                    cout << endl;
                    return false;
                }
                
                // Porer block er jonno expected previous hash update kora
                expected_prev_hash = hash;
                isGenesis = false;
            }
        }
        return true;
    }
}