#include <fstream>

#include <botan/rng.h>
#include <botan/processor_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>

std::ofstream fout("key.txt");

int main() {
  Botan::Processor_RNG rng;

  Botan::secure_vector<uint8_t> key = rng.random_vec(64);
  fout << Botan::hex_encode(key) << '\n';

  return 0;
}
