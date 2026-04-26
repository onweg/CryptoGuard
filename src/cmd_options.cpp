#include "cmd_options.h"

#include <filesystem>
#include <string>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
	desc_.add_options()
		(constants::kHelpProgOptStr, "список доступных опций")
		(constants::kCommandProgOptStr, boost::program_options::value<std::string>()->required(), "команда encrypt, decrypt или checksum")
		(constants::kInputProgOptStr, boost::program_options::value<std::string>(), "путь до входного файла")
		(constants::kOutputProgOptStr, boost::program_options::value<std::string>(), "путь до файла, в котором будет сохранён результат")
		(constants::kPasswordProgOptStr, boost::program_options::value<std::string>(), "пароль для шифрования и дешифрования")
	;	
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
	boost::program_options::variables_map vm;
	try {
		po::store(po::parse_command_line(args, argv, desc_), vm);
		if (vm.count["help"]) {
			cout << desc_ << std::endl;
			return;
		}
		boost::program_options::notify(vm);
	} catch (const po::required_options& e) {
		throw std::runtime_error("Missing arguments: ", e.what()) << "\n\n" << desc_ << "\n";
	} catch (const po::po_error &e) {
		throw std::runtime_error("Argument error: " + e.what());
	}
	command_ = commandMapping_[vm[constants::kCommandProgOptStr].as<std::string>];
	if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
		if (vm.contains(constants::kInputProgOptStr)) {
			if (!std::filesystem::is_regular_file(inputFile_)) { throw std::runtime_error("Not found file: " + inputFile_); }
		} else { 
			throw std::runtime_error("Нет параметра input"); 
		}
		if (vm.contains(constants::kOutputProgOptStr)) { throw std::runtime_error("Нет параметра output"); }
		if (!vm.contains(constants::kPasswordProgOptStr)) { throw std::runtime_error("Нет параметра password"); }
		inputFile_ = vm[constants::kInputProgOptStr];
		outputFile_ = vm[constants::kOutputProgOptStr];
		password_ = vm[constants::kPasswordProgOptStr];
	} else if (command_ == COMMAND_TYPE::CHECKSUM) {
		if (vm.contains(constants::kInputProgOptStr)) {
			if (!std::filesystem::is_regular_file(inputFile_)) { throw std::runtime_error("Not found file: " + inputFile_); }
		} else {
			throw std::runtime_error("Нет параметра input");
		}
		inputFile_ = vm[constants::kInputProgOptStr];
	}
}

}  // namespace CryptoGuard
