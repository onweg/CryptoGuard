#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <format>
#include <fstream>

using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::CryptoGuardCtx cryptoCtx;
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream ifs(options.GetInputFile(), std::ios::in);
            std::fstream ofs(options.GetOutputFile(), std::ios::out | std::ios::trunc);
            cryptoCtx.EncryptFile(ifs, ofs, options.GetPassword());
            std::cout << "File encoded successfully\n";
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream ifs(options.GetInputFile(), std::ios::in);
            std::fstream ofs(options.GetOutputFile(), std::ios::out | std::ios::trunc);
            cryptoCtx.DecryptFile(ifs, ofs, options.GetPassword());
            std::cout << "File decoded successfully\n";
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream ifs(options.GetInputFile(), std::ios::in);
            std::cout << "Checksum: " << cryptoCtx.CalculateChecksum(ifs) << "\n";
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std:: runtime_error &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}