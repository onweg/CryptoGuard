#include <gtest/gtest.h>
#include "cmd_options.h"
#include <filesystem>
#include <fstream>

using namespace CryptoGuard;

static std::vector<char*> MakeArgv(std::vector<std::string>& args) {
    std::vector<char*> argv;
    for (auto& s : args) argv.push_back(s.data());
    argv.push_back(nullptr);
    return argv;
}

// Вспомогательный класс — создаёт временный файл и удаляет после теста
struct TempFile {
    std::string path;
    explicit TempFile(const std::string& name) : path(name) {
        std::ofstream f(path);
        f << "test content";
    }
    ~TempFile() { std::filesystem::remove(path); }
};

TEST(ProgramOptionsTest, ParseCommandEncrypt) {
    TempFile input("test_in_enc.txt");
    std::vector<std::string> args = {
        "app", "--command", "encrypt",
        "--input", input.path, "--output", "out.txt", "--password", "pass"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()));
    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptionsTest, ParseCommandDecrypt) {
    TempFile input("test_in_dec.txt");
    std::vector<std::string> args = {
        "app", "--command", "decrypt",
        "--input", input.path, "--output", "out.txt", "--password", "pass"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()));
    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptionsTest, ParseCommandChecksum) {
    TempFile input("test_in_chk.txt");
    std::vector<std::string> args = {
        "app", "--command", "checksum",
        "--input", input.path
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()));
    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptionsTest, ParseCommandUnknown) {
    std::vector<std::string> args = {
        "app", "--command", "INVALID_CMD",
        "--input", "in.dat"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    // неизвестная команда должна бросать исключение
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()), std::runtime_error);
}

TEST(ProgramOptionsTest, ParseInputFile) {
    TempFile input("test_input_path.dat");
    std::vector<std::string> args = {
        "app", "--command", "encrypt",
        "--input", input.path,
        "--output", "out.dat",
        "--password", "secret"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());
    EXPECT_EQ(opts.GetInputFile(), input.path);
}

TEST(ProgramOptionsTest, ParseOutputFile) {
    TempFile input("test_in_out.dat");
    std::vector<std::string> args = {
        "app", "--command", "encrypt",
        "--input", input.path,
        "--output", "/tmp/test_output.dat",
        "--password", "secret"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());
    EXPECT_EQ(opts.GetOutputFile(), "/tmp/test_output.dat");
}

TEST(ProgramOptionsTest, ParsePassword) {
    TempFile input("test_in_pwd.dat");
    std::vector<std::string> args = {
        "app", "--command", "decrypt",
        "--input", input.path,
        "--output", "out.dat",
        "--password", "my_super_password_123"
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());
    EXPECT_EQ(opts.GetPassword(), "my_super_password_123");
}

TEST(ProgramOptionsTest, ParseEmptyPassword) {
    TempFile input("test_in_emptypwd.dat");
    std::vector<std::string> args = {
        "app", "--command", "encrypt",
        "--input", input.path,
        "--output", "out.dat",
        "--password", ""
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    opts.Parse(static_cast<int>(argv.size()) - 1, argv.data());
    EXPECT_EQ(opts.GetPassword(), "");
}

TEST(ProgramOptionsTest, ParseChecksumMinimalArgs) {
    TempFile input("test_in_minimal.bin");
    std::vector<std::string> args = {
        "app", "--command", "checksum",
        "--input", input.path
    };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    EXPECT_NO_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()));
    EXPECT_EQ(opts.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptionsTest, MissingCommandThrows) {
    std::vector<std::string> args = { "app" };
    auto argv = MakeArgv(args);
    ProgramOptions opts;
    EXPECT_THROW(opts.Parse(static_cast<int>(argv.size()) - 1, argv.data()), std::runtime_error);
}