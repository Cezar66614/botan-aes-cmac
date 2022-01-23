#include <iostream>
#include <fstream>

#include <botan/rng.h>
#include <botan/processor_rng.h>
#include <botan/cipher_mode.h>
#include <botan/mac.h>
#include <botan/hex.h>

std::ifstream fin;

std::string encrypt(std::string plain) {
  Botan::Processor_RNG rng;
  std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/SIV", Botan::ENCRYPTION); // Define encryption alg
  std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create("CMAC(AES-256)")); // define the MAC to use
  if(!enc || !mac)
    return "error";

  std::string x, xs; // read key
  fin.open("key.txt"); fin >> x; fin.close();
  for (int i = 0; i < 128; i += 2) xs += x[i];
  const std::vector<uint8_t> aesKey = Botan::hex_decode(x); x = " ";
  const std::vector<uint8_t> macKey = Botan::hex_decode(xs); xs = " ";

  enc->set_key(aesKey);
  mac->set_key(macKey);

  Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length()); // generate iv

  Botan::secure_vector<uint8_t> pt(plain.data(), plain.data()+plain.length()); // put message into a secure vector

  enc->start(iv);
  enc->finish(pt);

  // Create tag
  std::vector<uint8_t> package = Botan::hex_decode(Botan::hex_encode(iv) + Botan::hex_encode(pt));
  mac->update(package);

  Botan::secure_vector<uint8_t> tag = mac->final();

  return Botan::hex_encode(iv) + Botan::hex_encode(tag) + Botan::hex_encode(pt); // return iv + macTag + actual cipher
}

std::string decrypt(std::string cipher) {
  Botan::Processor_RNG rng;
  std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-256/SIV", Botan::DECRYPTION); // Define decryption alg (same as the encryption)
  std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create("CMAC(AES-256)")); // define the MAC to use
  if(!dec || !mac)
    return "error";

  std::string x, xs; // read key
  fin.open("key.txt"); fin >> x; fin.close();
  for (int i = 0; i < 128; i += 2) xs += x[i];
  const std::vector<uint8_t> aesKey = Botan::hex_decode(x); x = " ";
  const std::vector<uint8_t> macKey = Botan::hex_decode(xs); xs = " ";

  dec->set_key(aesKey);
  mac->set_key(macKey);

  for (int i = 0; i < 24; i++) x += cipher[i]; // get the iv from package
  std::vector<uint8_t> iv(Botan::hex_decode(x)); x = " ";

  for (int i = 24; i < 56; i++) x += cipher[i]; // get the tag from package
  Botan::secure_vector<uint8_t> tag = Botan::hex_decode_locked(x); x = " ";

  int i = 56;
  while (cipher[i]) { x += cipher[i]; i++; } // get the cipher from package
  Botan::secure_vector<uint8_t> et(Botan::hex_decode_locked(x));

  dec->start(iv);
  dec->finish(et);
  
  x = Botan::hex_encode(iv) + x;
  Botan::secure_vector<uint8_t> cipherNoTag(Botan::hex_decode_locked(x)); x = " ";
  mac->update(cipherNoTag);

  return std::string(et.data(), et.data()+et.size()) + '\n' +(mac->verify_mac(tag) ? "success" : "failure"); // return the decrypted text
}

int main() {
  const std::string plainText("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");

  std::string encrypted = encrypt(plainText);
  if (encrypted != "error") std::cout << encrypted << '\n';
  else {
    std::cout << "An error in creating the algorithm has appeared\n";
    return 0;
  }
  
  std::string decrypted = decrypt(encrypted);
  if (decrypted != "error") std::cout << decrypted << '\n';
  else {
    std::cout << "An error in creating the algorithm has appeared\n";
    return 0;
  }
  return 0;
}
