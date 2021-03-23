#pragma once

namespace utils
{
	/* add crypto functions here */
	bool get_rsa_key_from_hex_string(CryptoPP::RSAFunction& key, char* string, size_t size);

	CryptoPP::SecByteBlock get_random_aes_key();
	CryptoPP::SecByteBlock get_random_aes_iv();

	/* todo test */
	__forceinline void encrypt_rsa(CryptoPP::RSAFunction& key, byte* plain, size_t plain_size,
		byte* cipher, size_t cipher_size)
	{
		CryptoPP::AutoSeededRandomPool rng;
		const CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);
		CryptoPP::ByteQueue queue;
		CryptoPP::ArraySource as(plain, plain_size, true,
			new CryptoPP::PK_EncryptorFilter(rng, encryptor, new CryptoPP::Redirector(queue)));
		
		CryptoPP::ArraySink sink(cipher, cipher_size);
		queue.TransferTo(sink);
	}
	/* todo test */
	__forceinline void decrypt_rsa(CryptoPP::RSAFunction& key, byte* cipher, size_t cipher_size,
		byte* plain, size_t plain_size)
	{
		CryptoPP::AutoSeededRandomPool rng;
		const CryptoPP::RSAES_OAEP_SHA_Decryptor decryption(key);
		CryptoPP::ByteQueue queue;
		CryptoPP::ArraySource as(cipher, cipher_size, true, new CryptoPP::PK_DecryptorFilter(rng, decryption, new
			CryptoPP::Redirector(queue)));
		
		CryptoPP::ArraySink sink(plain, plain_size);
		queue.TransferTo(sink);
	}

	__forceinline void decrypt_aes(byte* buffer, size_t size, CryptoPP::SecByteBlock* key, CryptoPP::SecByteBlock* iv)
	{
		/* not protected because the functions that use this inlined function will be protected */
		CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cfb_decryption(key->BytePtr(), key->size(), iv->BytePtr());
		cfb_decryption.ProcessData(buffer, buffer, size);
	}

	__forceinline void encrypt_aes(byte* buffer, size_t size, CryptoPP::SecByteBlock* key, CryptoPP::SecByteBlock* iv)
	{
		CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cfb_encryption(key->BytePtr(), key->size(), iv->BytePtr());
		cfb_encryption.ProcessData(buffer, buffer, size);
	}
}
