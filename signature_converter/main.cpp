#include <iostream>
#include <string>

void code_to_ida(std::string& sig)
{
	for (int i = 0; i < sig.size(); i++) {
		const auto is_x00 = sig[i] == 'x' && sig[i + 1] == '0' && sig[i + 2] == '0';
		const auto is_00 = sig[i] == '0' && sig[i + 1] == '0';
		const auto is_x = sig[i] == 'x';
		const auto is_backslash = sig[i] == '\\';

		if (is_backslash) {
			sig[i] = ' ';
		}
			
		if (is_x00) {
			sig.replace(sig.find("x00"), sizeof("x00") - 1, "?");
		}
			
		if (is_x) {
			sig.replace(sig.find("x"), sizeof("x") - 1, "");
		}

		if (is_00) {
			sig.replace(sig.find("0"), sizeof("0") - 1, "?");
		}	
	}

	std::cout << "IDA Signature:" << sig << std::endl;
}

void ida_to_code(const std::string& sig)
{
	std::string code{}, mask{};

	code.append("\\x");
	code.append(sig);

	for (int i = 0; i < code.size(); i++) {
		const auto is_empty = code[i] == ' ';
		const auto is_unk = code[i] == '?';

		if (is_empty) {
			code.replace(code.find(" "), sizeof(" ") - 1, "\\x");
		}

		if (is_unk) {
			code.replace(code.find("?"), sizeof("?") - 1, "00");
		}
	}

	for (int i = 0; i < code.size(); i++) {
		const auto is_00 = code[i] == '0' && code[i + 1] == '0';
		const auto is_end_of_sequence = code[i] != '0' && code[i + 1] != '0' && code[i + 1] == '\\' || code[i + 1] == '\0';

		if (is_00) {
			mask.append("?");
		}
			
		if (is_end_of_sequence) {
			mask.append("x");
		}
	}

	std::cout << "Code Signature: " << code << std::endl;
	std::cout << "Mask: " << mask << std::endl;
}

int main()
{
	while (true) {
		system("cls");
		std::string signature{}, input{};

		std::cout << "1) Convert Code to IDA" << std::endl;
		std::cout << "2) Convert IDA to Code" << std::endl;
		std::cout << "\nChoice: ";
		std::getline(std::cin, input);

		if (input == "1") {
			std::cout << "Pattern: ";
			std::getline(std::cin, signature);
			code_to_ida(signature);
		}
		else {
			std::cout << "Pattern: ";
			std::getline(std::cin, signature);
			ida_to_code(signature);
		}
		system("pause");
	}
}

//Original Code
//\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x49\x8B\xf8\x4C\x8D\x05
//xxxx?xxxx?xxxxxx

//Original IDA
//48 89 5C 24 ? 57 48 83 EC ? 49 8B f8 4C 8D 05

//Generated IDA
//48 89 5C 24 ? 57 48 83 EC ? 49 8B f8 4C 8D 05

//Generated
//\x48\x89\x5C\x24\x00\x57\x48\x83\xEC\x00\x49\x8B\xf8\x4C\x8D\x05
//xxxx?xxxx?xxxxxx