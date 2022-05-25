#pragma once

//
// Emulation engine.
#include <unicorn/unicorn.h>

#include <Windows.h>
#include <psapi.h>
#include <string>
#include <string_view>
#include <map>
#include <vector>
#include <TlHelp32.h>
#include <algorithm>
#include <memory>
#include <inttypes.h>
#include <filesystem>
#pragma comment(lib, "psapi.lib")

//! PE parsing and manipulation and some other utils.
#include "msc/Process.hpp"
#include "msc/ScopedHandle.hpp"
#include <pepp/PELibrary.hpp>

//! Include Zydis disassembler
#include <zydis/include/Zydis/Zydis.h>
#include <zycore/include/Zycore/Format.h>
#include <zycore/include/Zycore/LibC.h>

//! Include spdlog
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/stopwatch.h>
#include <spdlog/fmt/bin_to_hex.h>

#include "VIFTools.hpp"

enum VMP_CALL_IAT_TYPE { CALL_IAT_UNKNOWN, CALL_IAT_1_5_POP, CALL_IAT_1_5_PUSH, CALL_IAT_5_1, CALL_IAT_5 };
enum E8_CALL_TYPE { E8_CALL_UNKNOWN, E8_CALL_CALL, E8_CALL_MOV_REG, E8_CALL_JMP };
enum DIRECT_ENC_TYPE { DIRECT_UNKNOWN, DIRECT_FFXX, DIRECT_8BXX, DIRECT_A1 };

enum reg_table_index { iax = 0, icx, idx, ibx, isp, ibp, isi, idi };
const static uc_x86_reg reg_x86_table[] = { UC_X86_REG_EAX ,UC_X86_REG_ECX ,UC_X86_REG_EDX,UC_X86_REG_EBX,UC_X86_REG_ESP ,UC_X86_REG_EBP ,UC_X86_REG_ESI ,UC_X86_REG_EDI };
const static uc_x86_reg reg_x64_table[] = { UC_X86_REG_RAX ,UC_X86_REG_RCX ,UC_X86_REG_RDX,UC_X86_REG_RBX,UC_X86_REG_RSP ,UC_X86_REG_RBP ,UC_X86_REG_RSI ,UC_X86_REG_RDI };

typedef struct VMP_ENCIAT_DETAIL
{
	uint32_t e8_call_type;
	uint32_t call_iat_type;	//对应e8_call -> mov reg,xx / jmp ds:[xx] / call ds:[xx]

	uint32_t direct_enc_type;	//对应直接->rdata段

	uint32_t code_rva;			//需要补丁指令的地址
}VMP_ENCIAT_DETAIL;

class IVMPImportFixer
{
public:
	virtual ~IVMPImportFixer() = default;
	virtual bool GetModuleFromAddress(std::uintptr_t ptr, VIFModuleInformation_t* mod) = 0;
	virtual void DumpInMemory(HANDLE hProcess, std::string_view sModName) = 0;
	virtual bool GetExportData(std::uintptr_t mod, std::uintptr_t rva, pepp::ExportData_t* exp) = 0;
};

template<size_t BitSize>
class VMPImportFixer : public pepp::msc::NonCopyable, public IVMPImportFixer
{
	using AddressType = pepp::detail::Image_t<BitSize>::Address_t;
	using Address = pepp::Address<AddressType>;
public:
	VMPImportFixer(std::string_view vmpsn, std::string_view textsn, std::vector<std::string> vecScanIATSections) noexcept;
	
	void DumpInMemory(HANDLE hProcess, std::string_view sModName) final override;

	//! Zydis disassemble an instruction.
	bool DecodeInsn(pepp::Address<> address, ZydisDecodedInstruction& insn) const noexcept;
	std::uintptr_t CalculateAbsoluteAddress(std::uintptr_t runtime_address, ZydisDecodedInstruction& insn) const noexcept;

	bool GetModuleFromAddress(std::uintptr_t ptr, VIFModuleInformation_t* mod) final override;
	bool GetExportData(std::uintptr_t mod, std::uintptr_t rva, pepp::ExportData_t* exp) final override;
	bool GetExportInfoFromAddr(AddressType funcaddr, std::pair<std::string, pepp::ExportData_t>&expinfo);

	void ScanDirectIATEncrypt(std::vector<std::string> vecScanSectionName, std::string scanPattern);
	void UcCleanRegs(uc_engine* uc);
	uint64_t GetNonzeroReg(uc_engine* uc, bool& bonlyone, int& reg_index);
private:
	ZydisDecoder						m_decoder;
	std::string							m_strVMPSectionName;
	std::string							m_strTextSectionName;
	std::vector<std::string>			m_vecScanIATSections;
	std::vector<VIFModuleInformation_t>	m_vecModuleList;
	std::vector<pepp::Image<BitSize>>	m_vecImageList;
	std::map<pepp::Address<>, pepp::Image<BitSize>*> m_ImageMap;

	pepp::Image<BitSize>*				m_pTargetImg;
	std::unordered_map<AddressType, std::pair<std::string, pepp::ExportData_t>> m_CacheDirectExpInfo;
	std::unordered_map<std::string, std::unordered_map<std::string, std::vector<VMP_ENCIAT_DETAIL>>> m_AddedImports;
};



extern std::shared_ptr<spdlog::logger> logger;

template<size_t BitSize>
inline VMPImportFixer<BitSize>::VMPImportFixer(std::string_view vmpsn, std::string_view textsn, std::vector<std::string> vecScanIATSections) noexcept
	: m_strVMPSectionName(vmpsn)
	,m_strTextSectionName(textsn)
	,m_vecScanIATSections(vecScanIATSections)
{
}


