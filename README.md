# botan-aes-cmac
This is a program to learn the functions of Botan, AES-256-SIV and CMAC. It's secure..., I think. :))

I made this on my own using the examples on their website and my own luck.
It is very simple to use since it has only 3 functions:
1) Encrypt - encrypts the plain text with a key
2) Decrypt - decrypts the cipher text using the same key (works only if there is no MAC Tag)
3) MAC - it adds or verifies the MAC Tag of a message

key_gen.cpp creates a key for the 256 AES encryption
