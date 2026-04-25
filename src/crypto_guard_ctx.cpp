#include "crypto_guard_ctx.h"
#include <openssl/evp.h>

namespace CryptoGuard {

namespace constants {

constexpr uint8_t BLOCK = 16;

}

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

	using EVP_CIPHER_CTX_PTR = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX ctx){ EVP_CIPHER_CTX_free(ctx); })>;
	using EVP_MD_CTX_PTR = std::unique_ptr<EVP_MD_CTX, decltype(()[EVP_MD_CTX* ctx]{ EVP_MD_CTX_free(ctx); })>;

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
		if (inStream.bad()) {
			throw std:: runtime_error("input stream is bad");
		}
		if (!inStream.good()) {
			throw std::runtime_error("input stream is not good");
		}
		if (!inStream) {
			throw std::runtime_error("input stream is not good");
		}
		EVP_MD_CTX_PTR ctx (EVP_MD_CTX_new());
		if (!ctx) {
			throw std:: runtime_error("ctx is invalid");
		}
		if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
			throw std:: runtime_error("Dint init algorithm");
		}
		std::vector<unsigned char> inBuf(constants::BLOCK);
		while (1) {
			inStream.read(reinterpret_cast<char*>(inBuf.data()), constants::BLOCK);
			const auto bytesRead = inStream.gcount();
			if (inStream.bad()) {
				throw std:: runtime_error("failed input steam");
			}
			if (bytesRead == 0) {
				break;
			}
			int result = EVP_DigestUpdate(ctx.get(), inBuf.data(), static_cast<int>(bytesRead));
			if (!result) {
				throw std:: runtime_error("filed EVP_DigestUpdate");
			}
		}
		unsigned char md_value_buf[EVP_MAX_MD_SIZE];
		unsigned int size_buf, i;
		if (EVP_DigestFinal_ex(ctx.get(), md_value_buf, &size_buf) != 1) {
			throw std:: runtime_error("EVP_DigestFinal_ex failed");
		}
		std::stringstream ss;
		for (unsigned int i = 0; i < size_buf; i++) {
			ss << std::hex << std::setw(2) << std::setfill('0') << (int)md_value_buf[i];
		}
		return ss.str();
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
		auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = encryptMode;
        EVP_CIPHER_CTX_PTR ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
		if (!ctx) {
			throw std::exception("Failed to create EVP_CIPHER_CTX_PTR");
		}
        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        std::vector<unsigned char> outBuf(constants::BLOCK + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(constants::BLOCK);
        int outLen;
		while (1) {
			inStream.read(reinterpret_cast<char*>(inBuf.data()), constants::BLOCK);
			const auto bytesRead = inStream.gcount();
			if (inStream.bad()) {
				std:: runtime_error("input stream is bad");
			}
			if (!bytesRead) {
				break;
			}
			int result = EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(),  static_cast<int>(bytesRead));
			if (!result) {
				throw std:: runtime_error("chipper error");
			}
			if (!(outLen >=0 && outLen <= static_cast<int>(outBuf.count()))) {
				throw std:: runtime_error("couldnt do EVP_CipherUpdate");
			}
			outStream.write(reinterpret_cast<char*>(outBuf), outLen);
			if (!outStream) {
				throw std:: runtime_error("write error");
			}
		}
        int result = EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen);
		if (!result) {
			throw std:: runtime_error("final error");
		}
		if (outLen > 0) {
			outStream.write(reinterpret_cast<char*>(outBuf), outLen);
		}
        std::print("String {} successfully. Result: '{}'\n\n", encryptMode == 1 ? "encrypt" : "decrypt", output);
	}


}

CryptoGuardCtx::CryptoGuardCtx() :pImpl_(std::make_unique<Impl>()) {
}

CryptoGuardCtx::~CryptoGuardCtx() {
}

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) { pImpl_->EncryptFile(inStream, outStream, password); }
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) { pImpl_->DecryptFile(inStream, outStream, password); }
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
