#include "VMPImportFixer.hpp"
#include "util.h"


std::shared_ptr<spdlog::logger> logger;

// Explicit templates.
template class VMPImportFixer<32>;
template class VMPImportFixer<64>;

class UnicornEngine
{
	uc_engine* ptr;
public:
	UnicornEngine(uc_engine* eng) noexcept
		: ptr(eng)
	{}

	~UnicornEngine() noexcept
	{
		if (ptr)
			uc_close(ptr);
	}
};

template<size_t BitSize>
void VMPImportFixer<BitSize>::UcCleanRegs(uc_engine* uc)
{
	const uc_x86_reg* reg_table = BitSize == 32 ? reg_x86_table : reg_x64_table;
	static uint64_t value = 0;
	for (int i = 0;i < _countof(reg_x86_table);i++)
	{
		uc_reg_write(uc, reg_table[i], &value);
	}
}

//除了esp外的其他寄存器
template<size_t BitSize>
uint64_t VMPImportFixer<BitSize>::GetNonzeroReg(uc_engine* uc, bool& bonlyone, int& reg_index)
{
	const uc_x86_reg* reg_table = BitSize == 32 ? reg_x86_table : reg_x64_table;
	uint64_t value = 0, ret_value = 0;
	int nonzero_count = 0;
	for (int i = 0;i < _countof(reg_x86_table); i++)
	{
		if (i == reg_table_index::isp)
			continue;
		uc_reg_read(uc, reg_table[i], &value);
		if (value)
		{
			nonzero_count++;
			ret_value = value;
			reg_index = i;
		}
	}
	if (nonzero_count != 1)
	{
		bonlyone = false;
		for (int i = 0; i < _countof(reg_x86_table); i++)
		{
			uc_reg_read(uc, reg_table[i], &value);
			if (value)
			{
				logger->critical("{} reg -> {:X}", value);
			}
		}
	}
	else
		bonlyone = true;
	return ret_value;
}

template<size_t BitSize>
inline void VMPImportFixer<BitSize>::DumpInMemory(HANDLE hProcess, std::string_view sModName)
{
	//
	// Define types for the current mode.

	static constexpr uc_mode EMULATION_MODE = BitSize == 32 ? UC_MODE_32 : UC_MODE_64;
	static constexpr uc_x86_reg STACK_REGISTER = BitSize == 32 ? UC_X86_REG_ESP : UC_X86_REG_RSP;
	static ZydisMachineMode ZY_MACHINE_MODE = BitSize == 32 ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32 : ZYDIS_MACHINE_MODE_LONG_64;
	static ZydisAddressWidth ZY_ADDRESS_WIDTH = BitSize == 32 ? ZYDIS_ADDRESS_WIDTH_32 : ZYDIS_ADDRESS_WIDTH_64;

	//
	// Initialize unicorn.
	uc_engine* uc{};
	uc_hook code_hook{};
	uc_err err = uc_open(UC_ARCH_X86, EMULATION_MODE, &uc);
	UnicornEngine _scoped_unicorn_free(uc);

	if (err != UC_ERR_OK)
	{
		logger->critical("Unable to open Unicorn in X86-{} mode (err: {})", BitSize, err);
		return;
	}

	if (ZyanStatus zs; !ZYAN_SUCCESS((zs = ZydisDecoderInit(&m_decoder, ZY_MACHINE_MODE, ZY_ADDRESS_WIDTH))))
	{
		logger->critical("Unable to initialize Zydis (err: {:X})", BitSize, zs);
		return;
	}

	vif::nt::Process proc(hProcess);
	m_pTargetImg = nullptr;


	if (proc.handle() == INVALID_HANDLE_VALUE)
	{
		return;
	}


	if (!VifFindModulesInProcess(hProcess, m_vecModuleList) || m_vecModuleList.empty())
	{
		logger->critical("Unable to fetch module list from process.");
		return;
	}

	int Idx{}, mIdx{};

	for (auto& mod : m_vecModuleList)
	{
		size_t nLastSize = 0;
		std::unique_ptr<std::uint8_t> pModBuffer(new std::uint8_t[mod.module_size]{});
		MEMORY_BASIC_INFORMATION mbi{};

		//
		// Loop through the module's memory and insert into the buffer.
		while (VirtualQueryEx(proc.handle(), (PVOID)(mod.base_address + nLastSize), &mbi, sizeof(mbi)))
		{
			if (proc.ReadMemory(mbi.BaseAddress, &pModBuffer.get()[nLastSize], mbi.RegionSize))
				; // logger->info("Read memory at {} with size {}", mbi.BaseAddress, mbi.RegionSize);
			else
				// Log the faliure, but that is all. We will still try to parse.
				logger->critical("Unable to read memory at {:X}", (std::uintptr_t)mbi.BaseAddress);

			nLastSize += mbi.RegionSize;

			if (nLastSize >= mod.module_size)
				break;
		}

		logger->info("Pushing module {} located @ 0x{:X}", mod.module_path, mod.base_address);

		m_vecImageList.push_back(std::move(pepp::Image<BitSize>::FromRuntimeMemory(pModBuffer.get(), mod.module_size)));

		if (m_vecImageList.back().magic() != IMAGE_DOS_SIGNATURE)
		{
			logger->error("Failed parsing image: {}", mod.module_path);
			continue;
		}

		if (!sModName.empty() && mod.module_path.find(sModName) != std::string::npos)
			mIdx = Idx;

		logger->info("{:X} ", mod.base_address);

		++Idx;
	}

	for (int i = 0;i < m_vecModuleList.size();i++ )
	{
		auto& mod = m_vecModuleList[i];
		m_ImageMap[mod.base_address] = &m_vecImageList[i];
	}

	if (!sModName.empty())
		m_pTargetImg = &m_vecImageList[mIdx];

	//
	// If no target module is selected, we default to the base process.
	if (m_pTargetImg == nullptr)
		m_pTargetImg = &m_vecImageList.front();


	Address uImageBase = m_pTargetImg->GetPEHeader().GetOptionalHeader().GetImageBase();

	logger->info("Using base address: {:X}", uImageBase.uintptr());

	//
	// By default, we scan the .text section by name. If the target binary for whatever reason
	// has another name other than .text for it's code section, you will need to change this.
	pepp::SectionHeader secText = m_pTargetImg->GetSectionHeader(m_strTextSectionName);

	if (secText.GetName() == ".dummy")
	{
		logger->critical("Unable to find {} section!", m_strTextSectionName);
		return;
	}

	logger->info("Found .text section at virtual address {:X}", secText.GetVirtualAddress());

	pepp::SectionHeader secVMP = m_pTargetImg->GetSectionHeader(m_strVMPSectionName);
	if (secVMP.GetName() == ".dummy")
	{
		logger->critical("Unable to find {} section!", m_strVMPSectionName);
		return;
	}

	logger->info("Found {} section at virtual address {:X}", m_strVMPSectionName, secVMP.GetVirtualAddress());

	//
	// Find all call sequences in the .text section.
	std::vector<uint32_t> vecCallMatches =
		m_pTargetImg->FindBinarySequence(&secText, "E8 ? ? ? ?");

	if (vecCallMatches.empty())
	{
		logger->critical("Unable to find any call/jmp sequences in the .text section!");
		return;
	}

	for (int i = 0; i < m_pTargetImg->GetNumberOfSections(); i++)
	{
		pepp::SectionHeader& secOne = m_pTargetImg->GetSectionHeader(i);
		logger->info("uc_map {} section", secOne.GetName());
		Address uMappedSecAddress = (uImageBase + secOne.GetVirtualAddress());
		Address uMappedSecSize = pepp::Align4kb(secOne.GetVirtualSize());

		err = uc_mem_map(uc, uMappedSecAddress.uintptr(), uMappedSecSize.uintptr(), UC_PROT_ALL);
		if (err != UC_ERR_OK)
		{
			logger->critical("Could not map in {} section => uc_mem_map() failed with error: {}", secOne.GetName(), uc_strerror(err));
			//return;
		}

		err = uc_mem_write(uc, uMappedSecAddress.uintptr(), &m_pTargetImg->buffer()[secOne.GetVirtualAddress()], secOne.GetVirtualSize());
		if (err != UC_ERR_OK)
		{
			logger->critical("Could not map in {} section => uc_mem_write() failed with error: {}", secOne.GetName(), uc_strerror(err));
			//return;
		}
	}
	
	std::string scan_pattern;
	std::vector<std::string> vecScanSections = m_vecScanIATSections;

	//8B XX mov reg,ds:[xxx]
	//mov reg,ds:[xxx]
	for (int i = 0; i < 8; i++)
	{
		if (BitSize == 32)
			scan_pattern = std::format("8B {:02X} ? ? ? ?", 5 + i * 8);
		else
			scan_pattern = std::format("48 8B {:02X} ? ? ? ?", 5 + i * 8);
		ScanDirectIATEncrypt(vecScanSections, scan_pattern);
	}
	
	//FF 15 call ds:[xxx] 
	//FF 25 jmp  ds:[xxx]
	//FF 35 push ds:[xxx]
	for (int i = 0; i < 3; i++)
	{
		scan_pattern = std::format("FF {:02X} ? ? ? ?", 0x15 + i * 0x10);
		ScanDirectIATEncrypt(vecScanSections, scan_pattern);
	}
	
	//mov eax,ds:[xxx]
	{
		if (BitSize == 32)
			scan_pattern = "A1 ? ? ? ?";
		else
			scan_pattern = "48 A1 ? ? ? ? ? ? ? ?";
		ScanDirectIATEncrypt(vecScanSections, scan_pattern);
	}

	secText = m_pTargetImg->GetSectionHeader(m_strTextSectionName);
	secVMP = m_pTargetImg->GetSectionHeader(m_strVMPSectionName);

	//
	// Write the stack address and registers
	uc_err ee;
	static uintptr_t STACK_SIZE = 0x2000;
	static uintptr_t STACK_START = 0x1000;
	static uintptr_t STACK_SPACE = STACK_START + STACK_SIZE / 2;//(uMappedVmpAddress.uintptr() + (uMappedVmpSize.uintptr() - 0x1000)) & -0x10;
	char* zerobuf = new char[STACK_SIZE];
	memset(zerobuf, 0, STACK_SIZE);
	uc_reg_write(uc, STACK_REGISTER, &STACK_SPACE);
	uc_mem_map(uc, STACK_START, STACK_SIZE, UC_PROT_ALL);
	uc_mem_write(uc, STACK_START, zerobuf, STACK_SIZE);
	//
	// Temp data to hold info about resolved imports..

	static std::pair<std::string, pepp::ExportData_t> ExpResolved{};
	static AddressType e8_call_ret_address{};
	static E8_CALL_TYPE e8_call_type = E8_CALL_TYPE::E8_CALL_UNKNOWN;
	static int reg_index = 0;
	static VMP_CALL_IAT_TYPE call_iat_type = VMP_CALL_IAT_TYPE::CALL_IAT_UNKNOWN;

	static ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
	static ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_32);
	static uint8_t jmp_retn_x = BitSize == 32 ? 4 : 8;
	//
	// We need to monitor every instruction that executes (since it seems like we cannot hook the 
	// exact instruction we need (RET))
	auto VifCodeHook = +[](uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
	{
		IVMPImportFixer* pUd = (IVMPImportFixer*)user_data;

		uint8_t insnbuf[0xf];
		uc_mem_read(uc, address, insnbuf, size);

		ExpResolved.first.clear();

		//ZydisDecodedInstruction instruction;
		//char buffer[256];
		//if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer((const ZydisDecoder*)&decoder, insnbuf, 0xf, &instruction)))
		//{
		//	ZydisFormatterFormatInstruction(&formatter, &instruction, &buffer[0], sizeof(buffer),
		//		0);
		//	ZYAN_PRINTF(" %s\n", &buffer[0]);
		//}

		if (call_iat_type == VMP_CALL_IAT_TYPE::CALL_IAT_UNKNOWN)
		{
			//Analyze stack
			AddressType stack_value[3] = { 0 ,0};
			uc_mem_read(uc, STACK_SPACE, stack_value, sizeof(AddressType)* _countof(stack_value));
			/*
			push reg
			call vmp0
			------------
			vmp0:
			pop reg
			xchg reg,[esp]	-->		[STACK_START+4]=retn_address
			*/
			if (stack_value[1] == e8_call_ret_address)
			{
				call_iat_type = VMP_CALL_IAT_TYPE::CALL_IAT_1_5_PUSH;
			}
			/*
			pop reg
			call vmp0
			------------
			xchg reg,[esp]	-->		[STACK_START] = [STACK_START+4] = 0
			push reg
			*/
			else if (stack_value[0] == 0 && stack_value[1] == 0)
			{
				call_iat_type = VMP_CALL_IAT_TYPE::CALL_IAT_1_5_POP;
			}
		}
		

		//
		// Did we hit a RET?
		if (insnbuf[0] == 0xC3 || insnbuf[0] == 0xC2)
		{
			//
			// Real import address is stored in [sp reg]
			AddressType uImportAddress{};
			AddressType uReturnAddress{};
			VIFModuleInformation_t mod{};
			pepp::ExportData_t exp{};

			uc_reg_read(uc, STACK_REGISTER, &uImportAddress);
			uc_mem_read(uc, uImportAddress + sizeof(AddressType), &uReturnAddress, sizeof(AddressType));
			uc_mem_read(uc, uImportAddress, &uImportAddress, sizeof(uImportAddress));
			if (uImportAddress >= e8_call_ret_address && uImportAddress < e8_call_ret_address + 2)
			{
				//mov reg,xxx

				AddressType mov_reg_value = 0;
				bool bonlyone = true;				
				mov_reg_value = ((VMPImportFixer*)pUd)->GetNonzeroReg(uc, bonlyone, reg_index);
				if (bonlyone)
				{
					uImportAddress = mov_reg_value;
					e8_call_type = E8_CALL_TYPE::E8_CALL_MOV_REG;
					if (call_iat_type != VMP_CALL_IAT_TYPE::CALL_IAT_1_5_POP && call_iat_type != VMP_CALL_IAT_TYPE::CALL_IAT_1_5_PUSH)
					{
						//非push reg情况，此时判断返回地址，如果返回地址+1了则是E8 Call+1字节，反之则是mov eax,ds:[xxx]的5字节
						if (uImportAddress == e8_call_ret_address && reg_index == reg_table_index::iax)
						{
							call_iat_type = VMP_CALL_IAT_TYPE::CALL_IAT_5;
						}
						else if(uImportAddress == e8_call_ret_address+1 )
						{
							call_iat_type = VMP_CALL_IAT_TYPE::CALL_IAT_5_1;
						}
						else
						{
							logger->error("unknown call_iat_type {:X} -> ", e8_call_ret_address - 5);
						}
					}
				}
				else
				{
					logger->critical("[Error] Nonzero reg not one {:X} -> ", e8_call_ret_address - 5);
				}
			}
			else
			{
				e8_call_type = E8_CALL_TYPE::E8_CALL_CALL;
				if (uReturnAddress == e8_call_ret_address + 1 && call_iat_type == VMP_CALL_IAT_TYPE::CALL_IAT_UNKNOWN)
				{
					call_iat_type = VMP_CALL_IAT_TYPE::CALL_IAT_5_1;
				}
			}

			//jmp ds:[xxx]		32-> retn 4		64-> retn 8
			if (insnbuf[0] == 0xC2 && insnbuf[1] == jmp_retn_x)
			{
				// jmp ds:[xxx]
				e8_call_type = E8_CALL_TYPE::E8_CALL_JMP;
				if (call_iat_type != VMP_CALL_IAT_TYPE::CALL_IAT_1_5_POP && call_iat_type != VMP_CALL_IAT_TYPE::CALL_IAT_1_5_PUSH)
				{
					call_iat_type = CALL_IAT_5_1;
				}
			}
			if (pUd->GetModuleFromAddress(uImportAddress, &mod))
			{
				//
				// Stop emulation so we don't get a memory fetch error.
				uc_emu_stop(uc);


				if (!pUd->GetExportData(mod.base_address, uImportAddress - mod.base_address, &ExpResolved.second))
				{
					logger->critical("Could not find export from address {:X}", uImportAddress);
					return;
				}

				ExpResolved.first = std::filesystem::path(mod.module_path).filename().string();

				logger->info("Resolved a call to {}!{}", ExpResolved.first, ExpResolved.second.name);	
			}
			else
			{
				logger->critical("Could not find module from address {:X}", uImportAddress);
				uc_emu_stop(uc);
				return;
			}
		}
	};

	if ((err=uc_hook_add(uc,
		&code_hook,
		UC_HOOK_CODE,
		VifCodeHook,
		this,
		1,
		0)) != UC_ERR_OK)
	{
		logger->critical("Could not install a code hook: {}", err);
		return;
	}

	//
	// Locations of vmp import calls
	std::vector<std::pair<Address, Address>> vecVmpImportCalls{};

	for (auto match : vecCallMatches)
	{
		ZydisDecodedInstruction insn{};
		std::uint8_t* insnbuf = &m_pTargetImg->buffer()[match];

		if (DecodeInsn(insnbuf, insn))
		{
			AddressType uDestAddress 
				= CalculateAbsoluteAddress((uImageBase.uintptr() + match), insn);
			if (uDestAddress == 0)
				continue;

			if (secVMP.HasVirtualAddress(uDestAddress - uImageBase.uintptr()))
			{
				if(m_pTargetImg->buffer().deref<uint8_t>(uDestAddress - uImageBase.uintptr()) != 0x90)
				{
					continue;		//不是0x90开头直接不要
				}
				logger->info("Found call to {} in {} @ {:X} (call to {:X})",
					m_strVMPSectionName,
					m_strTextSectionName,
					(AddressType)(uImageBase + match).uintptr(),
					uDestAddress);

				vecVmpImportCalls.emplace_back((uint64_t)match, uDestAddress);
			}
		}
	}

	for (auto& address : vecVmpImportCalls)
	{
		// Clean Reg
		UcCleanRegs(uc);
		//
		// Reset stack.
		uc_err e = uc_reg_write(uc, STACK_REGISTER, &STACK_SPACE);
		// Clean stack
		e = uc_mem_write(uc, STACK_START, zerobuf, STACK_SIZE);	

		// call iat type
		call_iat_type = VMP_CALL_IAT_TYPE::CALL_IAT_UNKNOWN;
		reg_index = 0;
		
		//
		// Write the return address as if we just entered a CALL.
		uintptr_t stackptr{};
		uintptr_t rtnaddress{};
		rtnaddress = uImageBase.uintptr() + address.first.uintptr() + 5;

		e = uc_reg_read(uc, STACK_REGISTER, &stackptr);
		e = uc_mem_write(uc, stackptr, &rtnaddress, sizeof(rtnaddress));

		e8_call_type = E8_CALL_TYPE::E8_CALL_UNKNOWN;
		e8_call_ret_address = rtnaddress;

		//
		// Begin emulation.
		logger->info("start emu address 0x{:X} -> 0x{:X}", uImageBase.uintptr() + address.first.uintptr(),address.second.uintptr());
		
		//uc_mem_write(uc, 0x13C953E, &xx, 1);	
		uc_err uerr = uc_emu_start(uc, address.second.uintptr(), 0, 0, 0);

		if (uerr != UC_ERR_OK)
		{
			logger->error("Emulation failed with error: {}", uc_strerror(uerr));
			continue;
		}

		if (m_pTargetImg->buffer().deref<uint8_t>(address.second.uintptr() - uImageBase.uintptr()) != 0x90)
		{
			logger->error("emu success but != 0x90");
		}

		if (ExpResolved.first.empty())
		{
			logger->error("Failed to resolve import @ emu address {:X}", address.second.uintptr());
			continue;
		}

		switch (e8_call_type)
		{
		case E8_CALL_TYPE::E8_CALL_MOV_REG:
			logger->info("mov reg type");
			break;
		case E8_CALL_TYPE::E8_CALL_CALL:
			logger->info("call ds:[xxx] type");
			break;
		case E8_CALL_TYPE::E8_CALL_JMP:
			logger->info("jmp ds:[xxx] type");
			break;
		default:
			logger->error("Unknown e8 call type");
			break;
		}

		switch (call_iat_type)
		{
		case CALL_IAT_1_5_POP:
			logger->info("1_5_POP");
			break;
		case CALL_IAT_1_5_PUSH:
			logger->info("1_5_PUSH");
			break;
		case CALL_IAT_5_1:
			logger->info("5_1");
			break;
		case CALL_IAT_5:
			logger->info("5");
			break;
		default:
			logger->error("[Error] Unknown call_iat_type");
			break;
		}

		VMP_ENCIAT_DETAIL vmp_enciat_detail;
		vmp_enciat_detail.e8_call_type = e8_call_type;
		vmp_enciat_detail.call_iat_type = call_iat_type;
		vmp_enciat_detail.direct_enc_type = DIRECT_ENC_TYPE::DIRECT_UNKNOWN;
		vmp_enciat_detail.code_rva = address.first.uintptr();
		m_AddedImports[ExpResolved.first][ExpResolved.second.name].push_back(vmp_enciat_detail);
	}

	std::unordered_map< std::string, std::vector<std::string> > iatdata;
	for (auto &mod :m_AddedImports)
	{
		std::vector<std::string>imports;
		imports.clear();
		for (auto &import:mod.second)
		{
			imports.push_back(import.first);
		}
		iatdata[mod.first] = imports;
	}
	m_pTargetImg->GetImportDirectory().RebuildIAT(iatdata);

	for (auto& mod : m_AddedImports)
	{
		std::string mod_name = mod.first;

		for (auto & mod_import:mod.second)
		{
			std::uint32_t uImportRVA{};
			std::uint64_t uImportVA{};
			std::string import_name = mod_import.first;

			if (!m_pTargetImg->GetImportDirectory().HasModuleImport(mod_name, import_name, &uImportRVA))
			{
				logger->error("[Error] !!!import not found {}:{}", mod_name, import_name);
				continue;
			}
			uImportVA = uImageBase.uintptr() + uImportRVA;
		
			for (auto & enc_detail :mod_import.second)
			{
				uint8_t patch_buf[8];
				uint32_t patch_rva = 0;
				uint32_t patch_size = 0;

				if (enc_detail.direct_enc_type != DIRECT_UNKNOWN)
				{
					switch (enc_detail.direct_enc_type)
					{
					case DIRECT_ENC_TYPE::DIRECT_8BXX:
						patch_rva = enc_detail.code_rva + 2;
						patch_size = 4;
						if constexpr (BitSize == 64)
						{
							*(std::uint32_t*)(&patch_buf[0]) = (std::uint32_t)(uImportVA - (uImageBase.uintptr() + enc_detail.code_rva) - 7);	//48 8b xx ? ? ? ?
							patch_rva += 1;	//48 prefix
						}
						else
							*(std::uint32_t*)(&patch_buf[0]) = (std::uint32_t)(uImportVA);
						break;
					case DIRECT_ENC_TYPE::DIRECT_FFXX:
						patch_rva = enc_detail.code_rva + 2;
						patch_size = 4;
						if constexpr (BitSize == 64)
							*(std::uint32_t*)(&patch_buf[0]) = (std::uint32_t)(uImportVA - (uImageBase.uintptr() + enc_detail.code_rva) - 6);	//ff xx ? ? ? ?
						else
							*(std::uint32_t*)(&patch_buf[0]) = (std::uint32_t)(uImportVA);
						break;
					case DIRECT_ENC_TYPE::DIRECT_A1:
						patch_rva = enc_detail.code_rva + 1;
						patch_size = 4;
						if constexpr (BitSize == 64)
						{
							patch_rva += 1;//48 prefix
							*(std::uint32_t*)(&patch_buf[0]) = (std::uint64_t)(uImportVA);	// 48 A1 ? ? ? ? ? ? ? ?
						}
						else
							*(std::uint32_t*)(&patch_buf[0]) = (std::uint32_t)(uImportVA);	//A1 ? ? ? ?
						break;	
					default:
						break;
					}
				}
				else
				{
					if (enc_detail.call_iat_type != VMP_CALL_IAT_TYPE::CALL_IAT_UNKNOWN && enc_detail.e8_call_type != E8_CALL_TYPE::E8_CALL_UNKNOWN)
					{
						switch (enc_detail.e8_call_type)
						{
						case E8_CALL_TYPE::E8_CALL_CALL:
							patch_buf[0] = 0xff;
							patch_buf[1] = 0x15;
							patch_size = 6;
							break;
						case E8_CALL_TYPE::E8_CALL_MOV_REG:
							if (call_iat_type == VMP_CALL_IAT_TYPE::CALL_IAT_5)
							{
								patch_buf[0] = 0xa1;
								patch_size = 5;
							}
							else
							{
								patch_buf[0] = 0x8b;
								patch_buf[1] = 0x5 + 8 * reg_index;
								patch_size = 6;
							}
							break;
						case E8_CALL_TYPE::E8_CALL_JMP:
							patch_buf[0] = 0xff;
							patch_buf[1] = 0x25;
							patch_size = 6;
							break;
						default:
							break;
						}

						switch (enc_detail.call_iat_type)
						{
						case VMP_CALL_IAT_TYPE::CALL_IAT_1_5_POP:
						case VMP_CALL_IAT_TYPE::CALL_IAT_1_5_PUSH:
							patch_rva = enc_detail.code_rva - 1;
							break;
						case VMP_CALL_IAT_TYPE::CALL_IAT_5_1:
						case VMP_CALL_IAT_TYPE::CALL_IAT_5:
							patch_rva = enc_detail.code_rva;
							break;
						default:
							break;
						}

						if (enc_detail.call_iat_type != VMP_CALL_IAT_TYPE::CALL_IAT_5)
						{
							if constexpr (BitSize == 64)
								*(std::uint32_t*)(&patch_buf[2]) = (std::uint32_t)(uImportVA - (uImageBase.uintptr() + patch_rva) - 6);
							else
							{
								*(std::uint32_t*)(&patch_buf[2]) = (std::uint32_t)(uImportVA);
							}
						}
						else
						{						
							if constexpr (BitSize == 64)
								logger->error("64 bit not E8 CALL -> A1 ? ? ? ?");
							else
								*(std::uint32_t*)(&patch_buf[1]) = (std::uint32_t)(uImportVA);
						}
					}
				}

				//
				// Patch in
				m_pTargetImg->buffer().copy_data(
					patch_rva,
					patch_buf,
					patch_size
				);

				logger->info("Patched import call @ 0x{:X} to {}!{} at newva:{:X}",
					enc_detail.code_rva,
					mod_name,
					import_name,
					uImportVA);
			}
		}
	}

	std::string outpath = "dumps/";
	if (sModName.empty()) 
	{
		outpath += std::filesystem::path(m_vecModuleList[0].module_path).filename().string() + ".fixed";
	}
	else
	{
		outpath += std::string(sModName) + ".fixed";
	}

	logger->info("Finished, writing to {}", outpath);

	m_pTargetImg->WriteToFile(outpath);
}

template<size_t BitSize>
bool VMPImportFixer<BitSize>::DecodeInsn(pepp::Address<> address, ZydisDecodedInstruction& insn) const noexcept
{
	return ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_decoder, address.as_ptr<void>(), 0xff, &insn));
}

template<size_t BitSize>
std::uintptr_t VMPImportFixer<BitSize>::CalculateAbsoluteAddress(std::uintptr_t runtime_address, ZydisDecodedInstruction& insn) const noexcept
{
	std::uintptr_t result{};

	if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &insn.operands[0], (ZyanU64)runtime_address, (ZyanU64*)&result)))
		return result;

	return 0ull;
}

template<size_t BitSize>
bool VMPImportFixer<BitSize>::GetModuleFromAddress(std::uintptr_t ptr, VIFModuleInformation_t* pmod)
{
	if (m_vecModuleList.empty())
		return false;

	for (auto& mod : m_vecModuleList)
	{
		if (ptr >= mod.base_address && ptr <= mod.base_address + mod.module_size)
		{
			*pmod = mod;
			return true;
		}
	}

	return false;
}

template<size_t BitSize>
bool VMPImportFixer<BitSize>::GetExportData(std::uintptr_t mod, std::uintptr_t rva, pepp::ExportData_t* exp)
{
	pepp::Image<BitSize>* pImage = m_ImageMap[mod];
	bool bFound = false;

	if (pImage)
	{
		pImage->GetExportDirectory().TraverseExports([&bFound, &exp, rva](pepp::ExportData_t* tmp)
			{
				if (tmp->rva == rva)
				{
					*exp = *tmp;
					bFound = true;
				}
			});
	}

	return bFound;
}

template<size_t BitSize>
bool VMPImportFixer<BitSize>::GetExportInfoFromAddr(AddressType funcaddr, std::pair<std::string, pepp::ExportData_t>& expinfo)
{
	AddressType uImportAddress{};
	uImportAddress = funcaddr;
	VIFModuleInformation_t mod{};
	std::pair<std::string, pepp::ExportData_t> ExpInfo{};
	if (GetModuleFromAddress(uImportAddress, &mod))
	{
		if (!GetExportData(mod.base_address, uImportAddress - mod.base_address, &ExpInfo.second))
		{
			//logger->critical("Could not find export from address {:X}", uImportAddress);
			return false;
		}

		ExpInfo.first = std::filesystem::path(mod.module_path).filename().string();

		//logger->info("Resolved a call to {}!{}", ExpInfo.first, ExpInfo.second.name);
	}
	else
	{
		//logger->critical("Could not find module from address {:X}", uImportAddress);
		return false;
	}
	expinfo = ExpInfo;
	return true;
}

template<size_t BitSize>
void VMPImportFixer<BitSize>::ScanDirectIATEncrypt(std::vector<std::string> vecScanSectionName, std::string scanPattern)
{
	uint32_t direct_enc_type = DIRECT_UNKNOWN;
	if (scanPattern.find("FF") != std::string::npos)
	{
		direct_enc_type = DIRECT_FFXX;
	}
	else if (scanPattern.find("8B") != std::string::npos)
	{
		direct_enc_type = DIRECT_8BXX;
	}
	else if (scanPattern.find("A1") != std::string::npos)
	{
		direct_enc_type = DIRECT_A1;
	}
	Address uImageBase = m_pTargetImg->GetPEHeader().GetOptionalHeader().GetImageBase();
	size_t match_oft = 0;
	bool bA1 = false;
	std::vector<std::string> vecScanBytes;
	util::split(scanPattern, vecScanBytes, ' ');
	for (int i = 0;i < vecScanBytes.size();i++)
	{
		if (vecScanBytes[i] == "A1")
			bA1 = true;
		if (vecScanBytes[i] == "?")
		{
			match_oft = i;
			break;
		}
	}
	VMP_ENCIAT_DETAIL vmp_enciat_detail;
	pepp::SectionHeader secText = m_pTargetImg->GetSectionHeader(m_strTextSectionName);
	std::vector<pepp::SectionHeader> vecDstSection;
	for (auto secName : vecScanSectionName)
	{
		pepp::SectionHeader tmpSec = m_pTargetImg->GetSectionHeader(secName);
		if (tmpSec.GetName() == ".dummy")
			logger->info("Error GetSection {} failed", secName);
		else
			vecDstSection.push_back(tmpSec);
	}
	std::vector<uint32_t> vecFindRva = m_pTargetImg->FindBinarySequence(&secText, scanPattern);
	for (auto match : vecFindRva)
	{
		uint32_t rva;
		if (BitSize == 32)
		{
			rva = m_pTargetImg->buffer().deref<uint32_t>(match + match_oft) - uImageBase.uintptr();
		}
		else
		{
			if (bA1)
				rva = m_pTargetImg->buffer().deref<uint64_t>(match + match_oft) - uImageBase.uintptr();
			else
				rva = match + m_pTargetImg->buffer().deref<uint32_t>(match + match_oft) + vecScanBytes.size();
		}

		for (int i = 0;i < vecDstSection.size();i++)
		{
			if (vecDstSection[i].HasVirtualAddress(rva))
			{
				AddressType uImportAddress = m_pTargetImg->buffer().deref<AddressType>(rva);
				std::pair<std::string, pepp::ExportData_t> ExpInfo{};
				bool bFindExpInfo = false;

				if (m_CacheDirectExpInfo.find(uImportAddress) == m_CacheDirectExpInfo.end())
				{
					if (GetExportInfoFromAddr(uImportAddress, ExpInfo))
					{
						m_CacheDirectExpInfo[uImportAddress] = ExpInfo;
						bFindExpInfo = true;
					}
				}
				else
				{
					ExpInfo = m_CacheDirectExpInfo[uImportAddress];
					bFindExpInfo = true;
				}

				if (bFindExpInfo)
				{
					logger->info("Found {} in {} {:X} -> {:X} at {}!{}",
						scanPattern,
						vecScanSectionName[i],
						(AddressType)(uImageBase + match).uintptr(),
						uImportAddress,
						ExpInfo.first,
						ExpInfo.second.name);

					vmp_enciat_detail.e8_call_type = E8_CALL_TYPE::E8_CALL_UNKNOWN;
					vmp_enciat_detail.call_iat_type = VMP_CALL_IAT_TYPE::CALL_IAT_UNKNOWN;
					vmp_enciat_detail.direct_enc_type = direct_enc_type;
					vmp_enciat_detail.code_rva = match;
					m_AddedImports[ExpInfo.first][ExpInfo.second.name].push_back(vmp_enciat_detail);
				}
				else
				{
					logger->info("Not Found {} in {} {:X} -> {:X}",
						scanPattern,
						vecScanSectionName[i],
						(AddressType)(uImageBase + match).uintptr(),
						uImportAddress);
				}
			}
		}
	}
}
