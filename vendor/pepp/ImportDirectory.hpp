#pragma once

#include <string_view>
#include <functional>
#include <variant>
#include<map>
#include<string>

namespace pepp
{
	struct ModuleImportData_t
	{
		std::uint32_t								module_name_rva;
		std::string									module_name;
		std::uint32_t								import_name_rva;
		std::variant<std::string, std::uint64_t>	import_variant;
		std::uint32_t								import_rva;
		bool										ordinal;
	};

	static constexpr auto IMPORT_ORDINAL_FLAG_32 = IMAGE_ORDINAL_FLAG32;
	static constexpr auto IMPORT_ORDINAL_FLAG_64 = IMAGE_ORDINAL_FLAG64;

	template<unsigned int bitsize>
	class ImportDirectory : pepp::msc::NonCopyable
	{
		friend class Image<32>;
		friend class Image<64>;

		Image<bitsize>*							m_image;
		detail::Image_t<>::ImportDescriptor_t*	m_base;
		detail::Image_t<>::ImportDescriptor_t*  m_newiidbase;
		detail::Image_t<>::ImportAddressTable_t m_iat_base;
	private:
		detail::Image_t<>::ImportDescriptor_t* GetIIDEnd();
		size_t GetAddedIIDNumber();
		detail::Image_t<>::ImportDescriptor_t* GetAddedIIDFromModule(std::string_view module);
		uint32_t GetEmptyOffsetAtNamePage();
		uint32_t GetEmptyOffsetAtThunkData(size_t nPageIndex);
		uint32_t GetEmptyOffsetAtImp(size_t nPageIndex);
 
	public:
		ImportDirectory() = default;

		bool ImportsModule(std::string_view module, std::uint32_t* name_rva = nullptr) const;
		bool HasModuleImport(std::string_view module, std::string_view import, std::uint32_t* rva = nullptr) const;
		void AddModuleImport(std::string_view module, std::string_view import, std::uint32_t* rva = nullptr);
		void AddModuleImports(std::string_view module, std::initializer_list<std::string_view> imports, std::uint32_t* rva = nullptr);
		void TraverseImports(const std::function<void(ModuleImportData_t*)>& cb_func);
		void CleanModuleImport();
		void RebuildIAT(std::unordered_map<std::string, std::vector<std::string>>& iattable);

		void SetCharacteristics(std::uint32_t chrs) {
			m_base->Characteristics = chrs;
		}

		std::uint32_t GetCharacteristics() const {
			return m_base->Characteristics;
		}
		
		void SetTimeDateStamp(std::uint32_t TimeDateStamp) {
			m_base->TimeDateStamp = TimeDateStamp;
		}

		std::uint32_t GetTimeDateStamp() const {
			return m_base->TimeDateStamp;
		}

		//! Util
		template<typename T>
		bool IsImportOrdinal(T ord) const requires pepp::msc::MemoryAddress<T> {
			if constexpr (bitsize == 64)
				return (ord & IMPORT_ORDINAL_FLAG_64) != 0;
			return (ord & IMPORT_ORDINAL_FLAG_32) != 0;
		}

		void GetIATOffsets(std::uint32_t& begin, std::uint32_t& end) noexcept;

	private:
		//! Setup the directory
		void _setup(Image<bitsize>* image) {
			m_image = image;
			m_base = reinterpret_cast<decltype(m_base)>(
				&image->base()[image->GetPEHeader().RvaToOffset(
					image->GetPEHeader().GetOptionalHeader().GetDataDirectory(DIRECTORY_ENTRY_IMPORT).VirtualAddress)]);		
			m_iat_base = reinterpret_cast<decltype(m_iat_base)>(
				&image->base()[image->GetPEHeader().RvaToOffset(
					image->GetPEHeader().GetOptionalHeader().GetDataDirectory(DIRECTORY_ENTRY_IAT).VirtualAddress)]);
		}
	};
}