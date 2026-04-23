#include "../include/sha256.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint> 

using namespace std;

// ROTRIGHT is a circular right shift. If bits fall off the right, they wrap around to the left.
#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))

// Sigma functions for stretching the message
#define SSIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

// Sigma functions for the main compression loop
#define BSIG0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define BSIG1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))

// Choice and Majority formulas
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))


string SHA256::hash(const string str) {
    
    // The 64 round constants (fractional parts of cube roots of first 64 primes)
    const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    // Initial mixing bowls (fractional parts of square roots of first 8 primes)
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Prepping the message(1)
    uint64_t len = str.length();
    uint64_t inputLenBits = len * 8; // We need the length in bits for the end padding

    // Refactor later to process data in 64-byte chunks directly from a stream.
    vector<unsigned char> data(str.begin(), str.end());

    // Append the '1' bit (0x80 is 10000000 in binary)
    data.push_back(0x80);

    // Pad with zeros until we are exactly 8 bytes (64 bits) shy of a 64-byte (512-bit) block
    while ((data.size() * 8 + 64) % 512 != 0) {
        data.push_back(0x00);
    }

    // Append the original message length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        data.push_back((inputLenBits >> (i * 8)) & 0xFF);
    }

    // Process the padded data in 512-bit (64-byte) blocks(2)
    for (size_t i = 0; i < data.size(); i += 64) {
        
        uint32_t w[64]; // The message schedule array
        
        // Break the 64-byte chunk into 16 32-bit words
        for (int j = 0; j < 16; ++j) {
            w[j] = (data[i + j * 4] << 24) | 
                   (data[i + j * 4 + 1] << 16) | 
                   (data[i + j * 4 + 2] << 8) | 
                   (data[i + j * 4 + 3]);
        }
            
        // Stretch the 16 words into 64 words
        for (int j = 16; j < 64; ++j) {
            w[j] = SSIG1(w[j - 2]) + w[j - 7] + SSIG0(w[j - 15]) + w[j - 16];
        }

        // Setup working variables for this round
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        // The 64 rounds of the compression function(3) 
        for (int j = 0; j < 64; ++j) {
            uint32_t t1 = hh + BSIG1(e) + CH(e, f, g) + k[j] + w[j];
            uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
            
            // Shift everything down
            hh = g; 
            g = f; 
            f = e; 
            e = d + t1;
            d = c; 
            c = b; 
            b = a; 
            a = t1 + t2;
        }

        // Add the compressed chunk to the current hash value
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    // Convert the final hash into a clean hex string(4)
    stringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << hex << setfill('0') << setw(8) << h[i];
    }
    
    return ss.str();
}