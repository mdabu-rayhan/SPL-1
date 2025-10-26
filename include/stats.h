#pragma once
using namespace std;
namespace Stats
{
    extern int total;
    extern int allowed;
    extern int blocked;
    extern int suspicious;
    void printSummary();
    void reset();
}
