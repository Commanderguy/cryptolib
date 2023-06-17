project(CryptoLib)

add_library(cryptolib STATIC 
md5.cpp md5.h 
hashbase.h 
sha2.cpp sha2.h 
sha3.cpp sha3.h 
debugutil.cpp debugutil.h
keccak.cpp keccak.h)