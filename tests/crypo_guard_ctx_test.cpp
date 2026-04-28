#include <gtest/gtest.h>
#include <sstream>
#include "crypto_guard_ctx.h"

using namespace CryptoGuard;

class EncryptTest : public ::testing::Test {
protected:
    CryptoGuardCtx ctx;
    const std::string password  = "StrongPassword123!";
    const std::string plaintext = "Hello, CryptoGuard! This is a test message.";
};

TEST_F(EncryptTest, EncryptedOutputDiffersFromPlaintext) {
    std::stringstream in(plaintext), out;
    ctx.EncryptFile(in, out, password);
    EXPECT_FALSE(out.str().empty());
    EXPECT_NE(out.str(), plaintext);
}

TEST_F(EncryptTest, EncryptThenDecryptRestoresOriginal) {
    std::stringstream in(plaintext), encrypted, decrypted;
    ctx.EncryptFile(in, encrypted, password);
    ctx.DecryptFile(encrypted, decrypted, password);
    EXPECT_EQ(decrypted.str(), plaintext);
}

TEST_F(EncryptTest, EmptyPasswordThrowsException) {
    std::stringstream in(plaintext), out;
    ASSERT_THROW(ctx.EncryptFile(in, out, ""), std::runtime_error);
}

class DecryptTest : public ::testing::Test {
protected:
    CryptoGuardCtx ctx;
    const std::string password  = "StrongPassword123!";
    const std::string plaintext = "Hello, CryptoGuard! This is a test message.";

    std::stringstream makeEncrypted() {
        std::stringstream in(plaintext), encrypted;
        ctx.EncryptFile(in, encrypted, password);
        return encrypted;
    }
};

TEST_F(DecryptTest, DecryptRestoresOriginalPlaintext) {
    auto encrypted = makeEncrypted();
    std::stringstream decrypted;
    ctx.DecryptFile(encrypted, decrypted, password);
    EXPECT_EQ(decrypted.str(), plaintext);
}

TEST_F(DecryptTest, WrongPasswordThrowsException) {
    auto encrypted = makeEncrypted();
    std::stringstream decrypted;
    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, "WrongPassword!"), std::runtime_error);
}

TEST_F(DecryptTest, CorruptedDataThrowsException) {
    auto encrypted = makeEncrypted();
    std::string corrupted = encrypted.str();
    corrupted[corrupted.size() / 2] ^= 0xFF;
    std::stringstream corruptedStream(corrupted), decrypted;
    ASSERT_THROW(ctx.DecryptFile(corruptedStream, decrypted, password), std::runtime_error);
}

TEST(CalculateChecksumTest, KnownInput) {
    CryptoGuardCtx ctx;  // вызов через объект, не свободная функция
    std::stringstream ss("hello world");
    std::string result = ctx.CalculateChecksum(ss);
    EXPECT_EQ(result, "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576bc75d0d29f5f7a96");
}

TEST(CalculateChecksumTest, EmptyInput) {
    CryptoGuardCtx ctx;
    std::stringstream ss("");
    std::string result = ctx.CalculateChecksum(ss);
    EXPECT_EQ(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}