#include <gtest/gtest.h>
#include "ProgramOptions.hpp"

using namespace CryptoGuard;

static std::vector<char*> MakeArgv(std::vector<std::string>& args) {
    std::vector<char*> argv;
    for (auto& s : args) {
        argv.push_back(s.data());
    }
    argv.push_back(nullptr);
    return argv;
}

TEST(ProgramOptionsTest, ParseCommandEncrypt) {
    std::vector<std::string> args = {
        "app", "--command", "encrypt",
        "--input", "in.txt", "--output", "out.txt", "--password", "pass"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptionsTest, ParseCommandDecrypt) {
    std::vector<std::string> args = {
        "app", "--command", "decrypt",
        "--input", "in.txt", "--output", "out.txt", "--password", "pass"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptionsTest, ParseCommandChecksum) {
    std::vector<std::string> args = {
        "app", "--command", "checksum",
        "--input", "in.txt"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptionsTest, ParseCommandUnknown) {
    std::vector<std::string> args = {
        "app", "--command", "unknown",
        "--input", "in.txt"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()));
}

TEST(ProgramOptionsTest, ParseInputFile) {
    std::vector<std::string> args = {
        "app", "--command", "encrypt",
        "--input", "/path/to/input.dat",
        "--output", "out.dat",
        "--password", "secret"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(opts.GetInputFile(), "/path/to/input.dat");
}

TEST(ProgramOptionsTest, ParseOutputFile) {
    std::vector<std::string> args = {
        "app", "--command", "encrypt",
        "--input", "in.dat",
        "--output", "/path/to/output.dat",
        "--password", "secret"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(opts.GetOutputFile(), "/path/to/output.dat");
}

TEST(ProgramOptionsTest, ParsePassword) {
    std::vector<std::string> args = {
        "app", "--command", "decrypt",
        "--input", "in.dat",
        "--output", "out.dat",
        "--password", "my_super_password_123"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(opts.GetPassword(), "my_super_password_123");
}

TEST(ProgramOptionsTest, ParseEmptyPassword) {
    std::vector<std::string> args = {
        "app", "--command", "encrypt",
        "--input", "in.dat",
        "--output", "out.dat",
        "--password", ""
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());

    EXPECT_EQ(opts.GetPassword(), "");
}

TEST(ProgramOptionsTest, ParseChecksumMinimalArgs) {
    std::vector<std::string> args = {
        "app", "--command", "checksum",
        "--input", "file.bin"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;

    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()));
    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptionsTest, InvalidCommandValue) {
    std::vector<std::string> args = {
        "app", "--command", "INVALID_CMD",
        "--input", "in.dat"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;

    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()));
}