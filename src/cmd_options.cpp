#include "cmd_options.h"

#include <string>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
	desc_.add_options()
		(constants::kHelpProgOptStr, "список доступных опций")
		(constants::kCommandProgOptStr, boost::program_options::value<std::string>(), "команда encrypt, decrypt или checksum")
		(constants::kInputProgOptStr, boost::program_options::value<std::string>(), "путь до входного файла")
		(constants::kOutputProgOptStr, boost::program_options::value<std::string>(), "путь до файла, в котором будет сохранён результат")
		(constants::kPasswordProgOptStr, boost::program_options::value<std::string>(), "пароль для шифрования и дешифрования")
	;	
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
	boost::program_options::variables_map vm;
	boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);
	boost::program_options::notify(vm);
	
	if (vm.count(constants::kHelpProgOptStr)) {
		std::cout << desc_ << std::endl;
	}
	if (vm.count(constants::kCommandProgOptStr)) {
		if (commandMapping_.count(vm[constants::kCommandProgOptStr].as<std::string>)) {
			command_ = commandMapping_[constants::kCommandProgOptStr];
		} else {
			command_ = commandMapping_[constants::kUnknowStr];
			std::cout << "Нет такого параметра: " << vm[constants::kCommandProgOptStr].as<std::string> << endl;
		}
	} else {
		std::cout << "Нет параметра с флагом --command" << std::endl;
	}
	if (vm.count(constants::kInputProgOptStr)) {
		inputFile_ = vm[constants::kInputProgOptStr].as<std::string>;
	} else {
		std::cout << "Нет параметра с флагом --input" << std::endl;
	}
	if (vm.count(constants::kOutputProgOptStr)) {
		outputFile_ = vm[constants::kOnputProgOptStr].as<std::string>;
	} else {
		std::cout << "Нет параметра с флагом --output" << std::endl;
	}
	if (vm.count(constants::kPasswordProgOptStr)) {
		password_ = vm[constants::kPasswordProgOptStr].as<std::string>;
	} else {
		std::cout << "Нет параметра с флагом --password" << std::endl;
	}
}

}  // namespace CryptoGuard
