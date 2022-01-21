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
  if(!enc)
    return "error";

  std::string x; // read key
  fin.open("key.txt"); fin >> x; fin.close();
  const std::vector<uint8_t> key = Botan::hex_decode(x); x = " ";

  enc->set_key(key);

  Botan::secure_vector<uint8_t> iv = rng.random_vec(enc->default_nonce_length()); // generate iv

  Botan::secure_vector<uint8_t> pt(plain.data(), plain.data()+plain.length()); // put message into a secure vector

  enc->start(iv);
  enc->finish(pt);

  return Botan::hex_encode(iv) + Botan::hex_encode(pt); // return the cipher + the iv
}

std::string decrypt(std::string cipher) {
  Botan::Processor_RNG rng;
  std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-256/SIV", Botan::DECRYPTION); // Define decryption alg (same as the encryption)
  if(!dec)
    return "error";

  std::string x; // read key
  fin.open("key.txt"); fin >> x; fin.close();
  const std::vector<uint8_t> key = Botan::hex_decode(x); x = " ";

  dec->set_key(key);

  for (int i = 0; i < 24; i++) x += cipher[i]; // get the iv from package
  std::vector<uint8_t> iv(Botan::hex_decode(x)); x = " ";

  int i = 24;
  while (cipher[i]) { x += cipher[i]; i++; } // get the cipher from package
  Botan::secure_vector<uint8_t> et(Botan::hex_decode_locked(x)); x = " ";

  dec->start(iv);
  dec->finish(et);
  
  return std::string(et.data(), et.data()+et.size()); // return the decrypted text
}

std::string mac(std::string package, bool u = 0) {
  std::unique_ptr<Botan::MessageAuthenticationCode> mac(Botan::MessageAuthenticationCode::create("CMAC(AES-256)")); // define the MAC to use
  if(!mac)
    return "error";
  
  fin.open("key.txt"); // read MAC key
  std::string key_s, x;
  fin >> x; fin.close();
  for (int i = 0; i < 128; i += 2) key_s += x[i]; x = " ";

  const std::vector<uint8_t> key = Botan::hex_decode(key_s); key_s = " ";

  mac->set_key(key);

  if (!u) { // Add MAC to cipher
    std::vector<uint8_t> data = Botan::hex_decode(package);
    mac->update(data);

    Botan::secure_vector<uint8_t> tag = mac->final();
    
    std::string iv;
    for (int i = 0; i < 24; i++) iv += package[i]; // get the iv from package

    std::string cipher;
    int i = 24;
    while (package[i]) { cipher += package[i]; i++; } // get the cipher from package

    return iv + Botan::hex_encode(tag) + cipher;

  } else { // Verify MAC of cipher
    std::string macTag;
    for (int i = 24; i < 56; i++) macTag += package[i]; // get the tag from package
    Botan::secure_vector<uint8_t> tag = Botan::hex_decode_locked(macTag); macTag = " ";

    std::string packageWithoutMAC;
    for (int i = 0; i < 24; i++) packageWithoutMAC += package[i]; // get the iv from package

    int i = 56;
    while (package[i]) { packageWithoutMAC += package[i]; i++; } // get the cipher from package

    std::vector<uint8_t> data = Botan::hex_decode(packageWithoutMAC);
    mac->update(data);

    return (mac->verify_mac(tag) ? "success\n" : "failure\n");

  }

  return "error";
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

  std::string encryptedWithMacTag = mac(encrypted);

  std::cout << encryptedWithMacTag << '\n';

  std::cout << "Verification: " << mac(encryptedWithMacTag, 1);
  return 0;
}
