#include "VMPImportFixer.hpp"
#include"util.h"
bool IsFileArchX64(std::filesystem::path path, bool* parsed = nullptr);

template<size_t BitSize>
IVMPImportFixer* VifFactory_GenerateFixer(std::string_view vmpsn,std::string_view textsn, std::vector<std::string> vecScanIATSections) noexcept
{
	return new VMPImportFixer<BitSize>(vmpsn, textsn, vecScanIATSections);
}

int main(int argc, const char** argv)
{
	logger = spdlog::stdout_color_mt("console");
	//logger = spdlog::basic_logger_mt("basic_logger", "logs/basic-log.txt");
	logger->set_level(spdlog::level::debug);
	logger->set_pattern("[%^%l%$] %v");

	if (argc > 1)
	{
		std::string_view sFilePathOrProc {};
		std::string_view sTargetModule {};
		std::string_view sVMPSectionName { ".vmp0" };
		std::string_view sTextSectionName{ ".text" };
		DWORD			 dwProcessId { 0ul };
		std::vector<std::string> vecScanIATSections = { ".rdata",".idata" };

		//
		// Parse out arguments
		for (int i = 1; i < argc; ++i)
		{
			if (_stricmp(argv[i], "-p") == 0 && (i + 1) < argc)
			{
				const char* szArg = argv[++i];

				if (szArg[0] != '\'')
				{
					dwProcessId = std::atoi(szArg);
					if (dwProcessId == 0)
					{
						logger->critical("Invalid process id '{}'", szArg);
						return EXIT_FAILURE;
					}
				}
				else
				{
					std::string sArgProc = std::string(szArg).substr(1, strlen(szArg) - 2);
					spdlog::stopwatch sw;

					//
					// Search for process with the name
					while ((dwProcessId = VifSearchForProcess(sArgProc)) == static_cast<DWORD>(-1))
					{
						if (std::chrono::duration_cast<std::chrono::milliseconds>(sw.elapsed()).count() > 10000)
						{
							logger->critical("Timed out searching for process {}.", sArgProc);
							return EXIT_FAILURE;
						}

						std::this_thread::sleep_for(std::chrono::milliseconds(100));
					}
				}
			}

			if (_stricmp(argv[i], "-f") == 0 && (i + 1) < argc && dwProcessId == 0)
			{
				sFilePathOrProc = argv[++i];
			}

			if (_stricmp(argv[i], "-mod") == 0 && (i + 1) < argc)
			{
				sTargetModule = argv[++i];
			}

			if (_stricmp(argv[i], "-section") == 0 && (i + 1) < argc)
			{
				sVMPSectionName = argv[++i];
			}

			if (_stricmp(argv[i], "-textsec") == 0 && (i + 1) < argc)
			{
				sTextSectionName = argv[++i];
			}

			if (_stricmp(argv[i], "-iatsecs") == 0 && (i + 1) < argc)
			{
				vecScanIATSections.clear();
				util::split(argv[++i], vecScanIATSections, ';');
			}
		}

		if (!sFilePathOrProc.empty() && std::filesystem::exists(sFilePathOrProc))
		{
			bool bWasParsed = false;
			bool bIsArchX64 = IsFileArchX64(sFilePathOrProc, &bWasParsed);

			if (bWasParsed)
			{
				//
				// TODO: Load DLL or process into memory (LoadLibraryEx/CreateProcess), unpack and fix IAT.
			}
		}
		else
		{
			if (dwProcessId != 0)
			{
				IVMPImportFixer* pImportFixer = nullptr;
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
				BOOL bIsWow64 = FALSE;
				
				if (hProcess == INVALID_HANDLE_VALUE)
				{
					logger->critical("Unable to open a handle to the process!");
					return EXIT_FAILURE;
				}
				
				IsWow64Process(hProcess, &bIsWow64);

				if (bIsWow64)
					pImportFixer = VifFactory_GenerateFixer<32>(sVMPSectionName, sTextSectionName,vecScanIATSections);
				else
					pImportFixer = VifFactory_GenerateFixer<64>(sVMPSectionName, sTextSectionName,vecScanIATSections);

				std::filesystem::create_directories("dumps");

				pImportFixer->DumpInMemory(hProcess, sTargetModule);


				delete pImportFixer;
				pImportFixer = nullptr;

				return EXIT_SUCCESS;
			}

			logger->critical("Invalid process!");
		}
	}
	else
	{
		std::cout << "Code modified from github.com/mike1k" << std::endl;
		
		std::cout <<
			"Example usages:\n"
			"*\tVMPImportFixer -p 123456 -mod test.exe -section .name0(可选默认为.vmp0) -textsec .name(可选默认为.text) -iatsecs .sec1;.sec2(可选默认为.rdata和.idata)\n" <<
			std::endl;

		std::cout << std::endl;
	}
	return EXIT_FAILURE;
}

bool IsFileArchX64(std::filesystem::path path, bool* parsed)
{
	pepp::io::File file{ path.string(), pepp::io::FILE_BINARY | pepp::io::FILE_INPUT };

	if (file.GetSize() > 0)
	{
		std::vector<uint8_t> file_buf = file.Read();

		IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)file_buf.data();
		//
		// We don't need arch specific as FILE_HEADER is the second member and it is the same size on both archs.
		IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(file_buf.data() + dos->e_lfanew);

		if (dos->e_magic == IMAGE_DOS_SIGNATURE)
		{
			if (nt->Signature == IMAGE_NT_SIGNATURE)
			{
				if (parsed)
					*parsed = true;

				if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
				{
					return true;
				}
			}
		}
	}

	if (parsed)
		*parsed = false;

	return false;
}

