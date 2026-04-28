#include "cmd_options.h"

#include <iostream>
#include <filesystem>
#include <string>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
	desc_.add_options()
		(constants::kHelpProgOptStr, "список доступных опций")
		("command", boost::program_options::value<std::string>()->required(), "команда encrypt, decrypt или checksum")
		("input,i", boost::program_options::value<std::string>(), "путь до входного файла")
		("output,o", boost::program_options::value<std::string>(), "путь до файла, в котором будет сохранён результат")
		("password,p", boost::program_options::value<std::string>(), "пароль для шифрования и дешифрования")
	;	
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
	boost::program_options::variables_map vm;
	try {
		boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);
		if (vm.count(constants::kHelpProgOptStr)) {
			std::cout << desc_ << std::endl;
			return;
		}
		boost::program_options::notify(vm);
	} catch (const boost::program_options::required_option& e) {
		throw std::runtime_error("Missing arguments: " + std::string(e.what()));
	} catch (const boost::program_options::error &e) {
		throw std::runtime_error("Argument error: " + std::string(e.what()));
	}
	if (commandMapping_.count(vm[constants::kCommandProgOptStr].as<std::string>())) {
		command_ = commandMapping_.at(vm[constants::kCommandProgOptStr].as<std::string>());
	} else {
		throw std::runtime_error(std::string("Нет такого варинта команды: ") + vm[constants::kCommandProgOptStr].as<std::string>());
	}	
	if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
		if (vm.contains(constants::kInputProgOptStr)) {
			inputFile_ = vm[constants::kInputProgOptStr].as<std::string>();
			if (!std::filesystem::is_regular_file(inputFile_)) { throw std::runtime_error("Not found file: " + inputFile_); }
		} else { 
			throw std::runtime_error("Нет параметра input"); 
		}
		if (!vm.contains(constants::kOutputProgOptStr)) { throw std::runtime_error("Нет параметра output"); }
		if (!vm.contains(constants::kPasswordProgOptStr)) { throw std::runtime_error("Нет параметра password"); }
		outputFile_ = vm[constants::kOutputProgOptStr].as<std::string>();
		password_ = vm[constants::kPasswordProgOptStr].as<std::string>();
	} else if (command_ == COMMAND_TYPE::CHECKSUM) {
		if (vm.contains(constants::kInputProgOptStr)) {
			inputFile_ = vm[constants::kInputProgOptStr].as<std::string>();
			if (!std::filesystem::is_regular_file(inputFile_)) { throw std::runtime_error("Not found file: " + inputFile_); }
		} else {
			throw std::runtime_error("Нет параметра input");
		}
	}
}

}  // namespace CryptoGuard
