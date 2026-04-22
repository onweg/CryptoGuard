#include "crypto_guard_ctx.h"
#include <openssl/evp.h>

namespace CryptoGuard {

class CryptoGuardCtx::Impl{
  public:
    struct AesCipherParams {
		static const size_t KEY_SIZE = 32;             // AES-256 key size
		static const size_t IV_SIZE = 16;              // AES block size (IV length)
		const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm
		int encrypt;                              // 1 for encryption, 0 for decryption
		std::array<unsigned char, KEY_SIZE> key;  // Encryption key
		std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
	};

	using EVP_CIPHER_CTX_PTR = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX ctx){ EVP_CIPHER_CTX_free(ctx); })>(EVP_CIPHER_CTX_new(););

	Impl() {
        OpenSSL_add_all_algorithms();
	}
	~Impl() {
        EVP_cleanup();
	}

	void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
		EncryptDecryptStream(inStream, outStream, password, 1);
	}

	void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
		EncryptDecryptStream(inStream, outStream, password, 0);	
	}

	std::string CalculateChecksum(std::iostream &inStream) { 
		return "NOT_IMPLEMENTED"; 
	}

  private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
		AesCipherParams params;
		constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};
		int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
									reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
									params.key.data(), params.iv.data());
		if (result == 0) {
			throw std::runtime_error{"Failed to create a key from password"};
		}
		return params;
	}

	void EncryptDecryptStream(std::iostream &inStream, std::iostream &outStream, std::string_view password, const bool encryptMode) {
		if (!inStream || !outStream) {
			throw std::exception("Stream is invalid");
		}
		auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = encryptMode;
        EVP_CIPHER_CTX_PTR ctx;
        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;
        std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
		std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
        EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
        std::print("String encoded successfully. Result: '{}'\n\n", output);
	}
}

CryptoGuardCtx::CryptoGuardCtx() :pImpl_(std::make_unique<Impl>()) {
}

CryptoGuardCtx::~CryptoGuardCtx() {
}

}  // namespace CryptoGuard
