#include PRECOMPILED_HEADER
#include "utils.h"

bool utils::get_rsa_key_from_hex_string(CryptoPP::RSAFunction& key, char* string, size_t size)
{
	try
	{
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::HexDecoder decoder;
		decoder.Put((const byte*)string, size);
		decoder.MessageEnd();

		key.Load(decoder);

		return key.Validate(rng, 3);
	}
	catch(std::exception&)
	{
		return false;
	}
}

CryptoPP::SecByteBlock utils::get_random_aes_key()
{
	
	CryptoPP::AutoSeededRandomPool rnd;
	CryptoPP::SecByteBlock key(nullptr, CryptoPP::AES::DEFAULT_KEYLENGTH);
	rnd.GenerateBlock(key, key.size());

	return key;
}

CryptoPP::SecByteBlock utils::get_random_aes_iv()
{
	CryptoPP::AutoSeededRandomPool rnd;
	CryptoPP::SecByteBlock key(nullptr, CryptoPP::AES::DEFAULT_KEYLENGTH);
	rnd.GenerateBlock(key, key.size());

	return key;
}
