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
const string CHAIN_FILE = "blockchain_log.txt";

namespace Blockchain {

    string getCurrentTime() {
        time_t now = time(0);
        char* dt = ctime(&now);
        string t(dt);
        t.pop_back(); // remove newline
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
        // Genesis Block
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
        
        // Clear old log file on start
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

        // Proof of Work / Hashing
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
}