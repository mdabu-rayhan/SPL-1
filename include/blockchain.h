#pragma once
#include <string>
#include <vector>
using namespace std;

struct Block
{
    int index;
    string timestamp;
    string data;
    string prevHash;
    string hash;
};

namespace Blockchain
{
    void init();
    void addBlock(const string &data);
    int size();
}
