#include "PELibrary.hpp"

using namespace pepp;

static constexpr std::uint32_t ONE_IID_PAGE_SIZE = PAGE_SIZE * 4;
static constexpr std::uint32_t NEW_SECTION_SIZE = PAGE_SIZE * 2 + ONE_IID_PAGE_SIZE * 100;

// Explicit templates.
template class ImportDirectory<32>;
template class ImportDirectory<64>;

template<unsigned int bitsize>
bool ImportDirectory<bitsize>::ImportsModule(std::string_view module, std::uint32_t* name_rva) const
{
	auto descriptor = m_base;
	mem::ByteVector const* buffer = &m_image->buffer();

	while (descriptor->FirstThunk != 0 && descriptor->Name != 0) {
		std::uint32_t offset = m_image->GetPEHeader().RvaToOffset(descriptor->Name);

		std::string_view modname = buffer->as<const char*>(offset);

		if (_stricmp(modname.data(), module.data()) == 0)
		{
			if (name_rva)
				*name_rva = descriptor->Name;

			return true;
		}

		descriptor++;
	}

	if (name_rva)
		*name_rva = 0;

	return false;
}

template<unsigned int bitsize>
bool ImportDirectory<bitsize>::HasModuleImport(std::string_view module, std::string_view import, std::uint32_t* rva) const
{
	auto descriptor = m_base;
	mem::ByteVector const* buffer = &m_image->buffer();

	while (descriptor->Characteristics != 0 && descriptor->Name != 0) {
		std::uint32_t offset = m_image->GetPEHeader().RvaToOffset(descriptor->Name);

		if (_stricmp(buffer->as<const char*>(offset), module.data()) == 0)
		{
			std::int32_t index = 0;
			typename detail::Image_t<bitsize>::ThunkData_t* firstThunk =
				buffer->as<decltype(firstThunk)>(m_image->GetPEHeader().RvaToOffset(descriptor->OriginalFirstThunk));

			while (firstThunk->u1.AddressOfData)
			{
				//
				// TODO: Ordinals not handled here.
				if (IsImportOrdinal(firstThunk->u1.Ordinal))
				{
					index++;
					firstThunk++;
					continue;
				}

				IMAGE_IMPORT_BY_NAME* _imp =
					buffer->as<decltype(_imp)>(m_image->GetPEHeader().RvaToOffset(firstThunk->u1.AddressOfData));

				if (import == _imp->Name)
				{
					if (rva)
						*rva = descriptor->FirstThunk + (index * m_image->GetWordSize());

					return true;
				}

				index++;
				firstThunk++;
			}
		}

		descriptor++;
	}

	if (rva)
		*rva = 0;

	return false;
}

template<unsigned int bitsize>
void ImportDirectory<bitsize>::AddModuleImport(std::string_view module, std::string_view import, std::uint32_t* rva)
{
	using ImageThunkData_t = typename detail::Image_t<bitsize>::ThunkData_t;
	// TODO: Clean this up and optimize some things.
	//std::cout << "module : " << module << "\timport : " << import << std::endl;

	auto descriptor = m_base;
	mem::ByteVector* buffer = &m_image->buffer();

	std::unique_ptr<std::uint8_t> descriptors;
	std::uint32_t vsize = 0, rawsize = 0;

	vsize = m_image->GetPEHeader()
		.GetOptionalHeader()
		.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).Size;

	SectionHeader newSec;

	//
	// Create a new section for the descriptors
	if (newSec = m_image->GetSectionHeader(".pepp"); newSec.GetName() == ".dummy")
	{
		descriptors.reset(new uint8_t[vsize]);
		memset(descriptors.get(), 0, vsize);
		//
		// Add in all the descriptors, so we can relocate them.
		// 
		while (descriptor->Characteristics != 0 && descriptor->Name != 0)
		{
			std::memcpy(&descriptors.get()[rawsize], descriptor, sizeof(*descriptor));
			rawsize += sizeof detail::Image_t<>::ImportDescriptor_t;

			std::memset(descriptor, 0x0, sizeof(*descriptor));

			descriptor++;
		}
		//
		// We split a new section into two portions
		// The first part contains IAT addresses, or IMAGE_IMPORT_BY_NAME structs.
		// The second part contains import descriptors
		// NOTE: The section size may need to be modified depending on how many imports need to be added
		// This is using quite a large section due to a IAT rebuilding tool I created previously.
		m_image->AppendSection(
			".pepp",
			NEW_SECTION_SIZE,
			SCN_MEM_READ |
			SCN_MEM_WRITE | 
			SCN_CNT_INITIALIZED_DATA |
			SCN_MEM_EXECUTE, &newSec);

		memset(buffer->as<void*>(newSec.GetPointerToRawData()), 0, newSec.GetSizeOfRawData());

		newSec.SetPointerToRelocations(0);
		newSec.SetPointerToLinenumbers(0);
		newSec.SetNumberOfRelocations(0);
		newSec.SetNumberOfLinenumbers(0);

		// Ghetto, needed for now.
		memcpy(&m_image->GetSectionHeader(".pepp"), &newSec, sizeof newSec);

		//
		// Set the new base.从0开始
		m_base = reinterpret_cast<decltype(m_base)>(
			&m_image->base()[m_image->GetPEHeader().RvaToOffset(
				newSec.GetVirtualAddress())]);

		//拷贝原来的IID数组到开头
		std::memcpy(&buffer->at(newSec.GetPointerToRawData()), descriptors.get(), vsize);

		m_newiidbase = GetIIDEnd();

		//
		// Set the new directory
		// 0偏移存放原来的IID数组
		m_image->GetPEHeader()
			.GetOptionalHeader()
			.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).VirtualAddress
			= newSec.GetVirtualAddress();
	}
	
	detail::Image_t<>::ImportDescriptor_t* target_iid = GetAddedIIDFromModule(module);
	size_t target_idd_page_index;

	//这个模块还不存在
	if (target_iid == NULL)
	{
		// 新增一个IID的大小
		m_image->GetPEHeader()
			.GetOptionalHeader()
			.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).Size
			= vsize + sizeof detail::Image_t<>::ImportDescriptor_t;

		//新增的IID偏移
		std::uint32_t descriptor_offset = newSec.GetPointerToRawData() + vsize;

		//新增的IID地址
		target_iid = (detail::Image_t<>::ImportDescriptor_t *) & ((*buffer)[descriptor_offset]);
		target_idd_page_index = ((uint32_t)target_iid - (uint32_t)m_newiidbase) / sizeof(detail::Image_t<>::ImportDescriptor_t) * ONE_IID_PAGE_SIZE / PAGE_SIZE + 2;

		//
		// Fill in default values, we don't use these
		target_iid->ForwarderChain = 0;
		target_iid->TimeDateStamp = 0;

		uint32_t NewNameOffsetAtNamePage = GetEmptyOffsetAtNamePage();
		uint32_t NewNameOffset = newSec.GetPointerToRawData() + NewNameOffsetAtNamePage;
		target_iid->Name = m_image->GetPEHeader().OffsetToRva(NewNameOffset);
		memcpy(buffer->as<char*>(NewNameOffset), module.data(), module.size());

		target_iid->OriginalFirstThunk = m_image->GetPEHeader().OffsetToRva(newSec.GetPointerToRawData() + target_idd_page_index * PAGE_SIZE);
		target_iid->FirstThunk = target_iid->OriginalFirstThunk;
	}

	//第一个页面存放iid数组，第二个页面存放iid->Name，之后每两个页面存放iid的image_thunk_data数组以及image_import_by_name
	target_idd_page_index = ((uint32_t)target_iid - (uint32_t)m_newiidbase) / sizeof(detail::Image_t<>::ImportDescriptor_t) * ONE_IID_PAGE_SIZE / PAGE_SIZE + 2;
	
	uint32_t NewThunkDataOffset = GetEmptyOffsetAtThunkData(target_idd_page_index);
	uint32_t NewImpDataOffset = GetEmptyOffsetAtImp(target_idd_page_index);
	
	ImageThunkData_t* pThunkData = buffer->as<ImageThunkData_t*>(newSec.GetPointerToRawData() + NewThunkDataOffset);
	IMAGE_IMPORT_BY_NAME* pImp = buffer->as<IMAGE_IMPORT_BY_NAME*>(newSec.GetPointerToRawData() + NewImpDataOffset);

	pThunkData->u1.AddressOfData = m_image->GetPEHeader().OffsetToRva(newSec.GetPointerToRawData() + NewImpDataOffset);

	pImp->Hint = 0;
	memcpy(pImp->Name, import.data(), import.size());

	if(rva)
	{
		*rva = m_image->GetPEHeader().OffsetToRva(newSec.GetPointerToRawData() + NewThunkDataOffset);
	}
}

template<unsigned int bitsize>
void ImportDirectory<bitsize>::AddModuleImports(std::string_view module, std::initializer_list<std::string_view> imports, std::uint32_t* rva)
{
	// TODO: Clean this up and optimize some things.

	auto descriptor = m_base;
	mem::ByteVector* buffer = &m_image->buffer();

	std::unique_ptr<std::uint8_t> descriptors;
	std::uint32_t vsize = 0, rawsize = 0;

	vsize = m_image->GetPEHeader()
		.GetOptionalHeader()
		.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).Size;


	descriptors.reset(new uint8_t[vsize]);
	memset(descriptors.get(), 0, vsize);

	SectionHeader newSec;

	//
	// Add in all the descriptors, so we can relocate them.
	while (descriptor->Characteristics != 0)
	{
		std::memcpy(&descriptors.get()[rawsize], descriptor, sizeof(*descriptor));
		rawsize += sizeof detail::Image_t<>::ImportDescriptor_t;

		std::memset(descriptor, 0x0, sizeof(*descriptor));

		descriptor++;
	}

	//
	// For the null term.
	rawsize += sizeof detail::Image_t<>::ImportDescriptor_t;

	//
	// Create a new section for the descriptors
	if (newSec = m_image->GetSectionHeader(".pepp"); newSec.GetName() == ".dummy")
	{
		//
		// We split a new section into two portions
		// The first part contains IAT addresses, or IMAGE_IMPORT_BY_NAME structs.
		// The second part contains import descriptors
		m_image->AppendSection(
			".pepp",
			2 * PAGE_SIZE,
			SCN_MEM_READ |
			SCN_MEM_WRITE |
			SCN_CNT_INITIALIZED_DATA |
			SCN_MEM_EXECUTE, &newSec);

		memset(buffer->as<void*>(newSec.GetPointerToRawData()), 0xcc, newSec.GetSizeOfRawData());

		newSec.SetPointerToRelocations(0);
		newSec.SetPointerToLinenumbers(0);
		newSec.SetNumberOfRelocations(0);
		newSec.SetNumberOfLinenumbers(0);

		// Ghetto, needed for now.
		memcpy(&m_image->GetSectionHeader(".pepp"), &newSec, sizeof newSec);

		//
		// Set the new base.
		m_base = reinterpret_cast<decltype(m_base)>(
			&m_image->base()[m_image->GetPEHeader().RvaToOffset(
				newSec.GetVirtualAddress() + PAGE_SIZE)]);
	}

	//
	// Fill in the original descriptors
	std::memcpy(&buffer->at(newSec.GetPointerToRawData() + PAGE_SIZE), descriptors.get(), vsize);

	//
	// Set the new directory
	m_image->GetPEHeader()
		.GetOptionalHeader()
		.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).VirtualAddress
		= newSec.GetVirtualAddress() + PAGE_SIZE;
	m_image->GetPEHeader()
		.GetOptionalHeader()
		.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).Size
		= vsize + sizeof detail::Image_t<>::ImportDescriptor_t;

	std::uint32_t descriptor_offset = newSec.GetPointerToRawData() + PAGE_SIZE + vsize - sizeof(*descriptor);
	descriptor = (decltype(descriptor)) & ((*buffer)[descriptor_offset]);

	//
	// Fill in default values, we don't use these
	descriptor->ForwarderChain = 0;
	descriptor->TimeDateStamp = 0;

	//
	// 1) Check if requested module already exists as string, and use that RVA
	std::uint32_t name_rva = 0;
	std::uint32_t tmp_offset = 0;
	std::uint32_t iat_rva = 0;
	std::uint32_t tmp_rva = 0;
	std::uint32_t oft_offset = 0;
	std::uint32_t oft_rva = 0;

	if (!ImportsModule(module, &name_rva))
	{
		// 2) If 1 isn't possible, add a section or extend the data section (hard)
		// and add in the module name manually
		// 	   - set descriptor->Name to that rva
		tmp_offset = m_image->FindPadding(&newSec, 0xcc, module.size() + 1);
		name_rva = m_image->GetPEHeader().OffsetToRva(tmp_offset);

		std::memcpy(buffer->as<char*>(tmp_offset), module.data(), module.size());
		buffer->as<char*>(tmp_offset)[module.size()] = 0;
	}

	descriptor->Name = name_rva;

	using ImageThunkData_t = typename detail::Image_t<bitsize>::ThunkData_t;


	std::size_t thunksize = (imports.size() + 1) * sizeof(ImageThunkData_t);


	// 3) Add in FirstThunk
	tmp_offset = m_image->FindPadding(&newSec, 0xcc, thunksize, m_image->GetWordSize());
	iat_rva = m_image->GetPEHeader().OffsetToRva(tmp_offset);

	//
	// Fill in values so that it doesn't get taken up next time this function is called
	// Also, these need to be zero.
	memset(buffer->as<void*>(tmp_offset), 0x00, thunksize);

	ImageThunkData_t* firstThunk = m_image->buffer().as<ImageThunkData_t*>(tmp_offset);
	firstThunk->u1.AddressOfData = iat_rva;

	descriptor->FirstThunk = iat_rva;
	


	// 4) Add in OriginalFirstThunk
	tmp_offset = m_image->FindPadding(&newSec, 0xcc, thunksize, m_image->GetWordSize());
	tmp_rva = m_image->GetPEHeader().OffsetToRva(tmp_offset);

	//
	// Fill in values so that it doesn't get taken up next time this function is called
	// Also, these need to be zero.
	memset(buffer->as<void*>(tmp_offset), 0x00, thunksize);


	ImageThunkData_t* ogFirstThunk = m_image->buffer().as<ImageThunkData_t*>(tmp_offset);

	int i = 0;
	for (auto it = imports.begin(); it != imports.end(); it++)
	{
		oft_offset = m_image->FindPadding(&newSec, 0xcc, sizeof(std::uint16_t) + it->size() + 1, m_image->GetWordSize());
		oft_rva = m_image->GetPEHeader().OffsetToRva(oft_offset);
		//
		// Copy in name to the oft rva
		IMAGE_IMPORT_BY_NAME* imp = buffer->as<IMAGE_IMPORT_BY_NAME*>(oft_offset);
		imp->Hint = 0x0000;

		memcpy(&imp->Name[0], it->data(), it->size());
		imp->Name[it->size()] = '\0';

		if (rva)
			rva[i] = iat_rva + (m_image->GetWordSize() * i++);

		ogFirstThunk->u1.AddressOfData = oft_rva;
		ogFirstThunk++;
	}

	
	ogFirstThunk->u1.AddressOfData = 0;
	descriptor->OriginalFirstThunk = tmp_rva;

	//
	// Finally null terminate
	memset((descriptor + 1), 0, sizeof(decltype(*descriptor)));
}

template<unsigned int bitsize>
void ImportDirectory<bitsize>::TraverseImports(const std::function<void(ModuleImportData_t*)>& cb_func)
{
	auto descriptor = m_base;
	mem::ByteVector const* buffer = &m_image->buffer();

	while (descriptor->Characteristics != 0) {
		std::uint32_t offset = m_image->GetPEHeader().RvaToOffset(descriptor->Name);
		const char* module = buffer->as<const char*>(offset);
		std::int32_t index = 0;
		typename detail::Image_t<bitsize>::ThunkData_t* firstThunk =
			buffer->as<decltype(firstThunk)>(m_image->GetPEHeader().RvaToOffset(descriptor->OriginalFirstThunk));

		ModuleImportData_t data{};
		data.module_name_rva = descriptor->Name;
		data.module_name = module;
		data.import_rva = -1;

		while (firstThunk->u1.AddressOfData)
		{
			IMAGE_IMPORT_BY_NAME* _imp =
				buffer->as<decltype(_imp)>(m_image->GetPEHeader().RvaToOffset(firstThunk->u1.AddressOfData));

			if (IsImportOrdinal(firstThunk->u1.Ordinal))
			{
				data.ordinal = true;
				data.import_variant = (std::uint64_t)firstThunk->u1.Ordinal;
				data.import_name_rva = 0;
			}
			else
			{
				data.import_variant = static_cast<char*>(_imp->Name);
				data.import_name_rva = firstThunk->u1.AddressOfData + sizeof(std::uint16_t);
			}

			data.import_rva = descriptor->FirstThunk + (index * m_image->GetWordSize());

			//
			// Call the callback
			cb_func(&data);

			index++;
			firstThunk++;
		}

		descriptor++;
	}
}

template<unsigned int bitsize>
void pepp::ImportDirectory<bitsize>::CleanModuleImport()
{
	auto descriptor = m_base;
	memset(descriptor, 0, sizeof(*descriptor));
	m_image->GetPEHeader()
		.GetOptionalHeader()
		.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).Size
		= 0;
}

template<unsigned int bitsize>
void pepp::ImportDirectory<bitsize>::RebuildIAT(std::unordered_map<std::string, std::vector<std::string>>& iattable)
{
	CleanModuleImport();
	using ImageThunkData_t = typename detail::Image_t<bitsize>::ThunkData_t;
	mem::ByteVector* buffer = &m_image->buffer();

	SectionHeader newSec;
	if (newSec = m_image->GetSectionHeader(".pepp"); newSec.GetName() == ".dummy")
	{
		m_image->AppendSection(
			".pepp",
			NEW_SECTION_SIZE,
			SCN_MEM_READ |
			SCN_MEM_WRITE |
			SCN_CNT_INITIALIZED_DATA |
			SCN_MEM_EXECUTE, &newSec);

		memset(buffer->as<void*>(newSec.GetPointerToRawData()), 0, newSec.GetSizeOfRawData());

		newSec.SetPointerToRelocations(0);
		newSec.SetPointerToLinenumbers(0);
		newSec.SetNumberOfRelocations(0);
		newSec.SetNumberOfLinenumbers(0);

		// Ghetto, needed for now.
		memcpy(&m_image->GetSectionHeader(".pepp"), &newSec, sizeof newSec);

		//
		// Set the new base.从0开始
		m_base = reinterpret_cast<decltype(m_base)>(
			&m_image->base()[m_image->GetPEHeader().RvaToOffset(
				newSec.GetVirtualAddress())]);

		m_newiidbase = GetIIDEnd();
		//
		// Set the new directory
		// 0偏移存放原来的IID数组
		m_image->GetPEHeader()
			.GetOptionalHeader()
			.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).VirtualAddress
			= newSec.GetVirtualAddress();
	}

	uint32_t newSecRva = newSec.GetVirtualAddress();
	uint32_t newSecRaw = newSec.GetPointerToRawData();
	uint32_t IIDOffset = 0;
	uint32_t ModNameOffset = PAGE_SIZE * 1;
	uint32_t ThunkDataOffset = PAGE_SIZE * 3;
	uint32_t ImpOffset = PAGE_SIZE * 20;
	IMAGE_IMPORT_DESCRIPTOR iid;

	for(auto& mod:iattable)
	{
		memset(&iid, 0, sizeof(iid));

		iid.Name = newSecRva + ModNameOffset;
		iid.FirstThunk = newSecRva + ThunkDataOffset;
		iid.OriginalFirstThunk = iid.FirstThunk;
		iid.ForwarderChain = 0;
		iid.TimeDateStamp = 0;

		memcpy(buffer->as<IMAGE_IMPORT_DESCRIPTOR*>(newSecRaw + IIDOffset), &iid, sizeof(iid));
		IIDOffset += sizeof(iid);
		m_image->GetPEHeader()
			.GetOptionalHeader()
			.GetDataDirectory(DIRECTORY_ENTRY_IMPORT).Size
			+= sizeof(IMAGE_IMPORT_DESCRIPTOR);

		strcpy(buffer->as<char*>(newSecRaw + ModNameOffset), mod.first.c_str());
		ModNameOffset += mod.first.size() + 2;

		for (auto import : mod.second)
		{
			ImageThunkData_t* pThunkData = buffer->as<ImageThunkData_t*>(newSecRaw + ThunkDataOffset);
			pThunkData->u1.AddressOfData = ImpOffset + newSecRva;
			ThunkDataOffset += sizeof(ImageThunkData_t);
			IMAGE_IMPORT_BY_NAME* pImp = buffer->as<IMAGE_IMPORT_BY_NAME*>(newSecRaw + ImpOffset);
			pImp->Hint = 0;
			strcpy(pImp->Name, import.c_str());
			ImpOffset += sizeof(pImp->Hint) + import.size() + 2;
		}
		ThunkDataOffset += sizeof(ImageThunkData_t);
	}
}






template<unsigned int bitsize>
detail::Image_t<>::ImportDescriptor_t* pepp::ImportDirectory<bitsize>::GetIIDEnd()
{
	detail::Image_t<>::ImportDescriptor_t* piidend = m_base;
	while (piidend->Characteristics != 0 && piidend->Name != 0)
		piidend++;
	return piidend;
}

template<unsigned int bitsize>
size_t pepp::ImportDirectory<bitsize>::GetAddedIIDNumber()
{
	size_t nAddedIID = 0;
	detail::Image_t<>::ImportDescriptor_t* newiid = m_newiidbase;
	while(newiid->Name != 0 && newiid->Characteristics!= 0)
	{
		nAddedIID++;
	}
	return nAddedIID;
}

template<unsigned int bitsize>
detail::Image_t<>::ImportDescriptor_t* pepp::ImportDirectory<bitsize>::GetAddedIIDFromModule(std::string_view module)
{
	detail::Image_t<>::ImportDescriptor_t* target_iid = NULL;
	detail::Image_t<>::ImportDescriptor_t* added_iid = m_newiidbase;
	mem::ByteVector* buffer = &m_image->buffer();

	while (added_iid->Name != 0 && added_iid->Characteristics != 0)
	{
		char* iid_mod_name = buffer->as<char*>(m_image->GetPEHeader().RvaToOffset(added_iid->Name));
		if (iid_mod_name == module)
		{
			target_iid = added_iid;
			break;
		}
		added_iid++;
	}
	return target_iid;
}

template<unsigned int bitsize>
uint32_t pepp::ImportDirectory<bitsize>::GetEmptyOffsetAtNamePage()
{
	SectionHeader newSec;
	newSec = m_image->GetSectionHeader(".pepp");
	mem::ByteVector* buffer = &m_image->buffer();

	char* NamePageBuffer = buffer->as<char*>(newSec.GetPointerToRawData() + 1 * PAGE_SIZE);

	for (int i = 0;i < PAGE_SIZE - 1;i++)
	{
		if (NamePageBuffer[i] == 0 && NamePageBuffer[i+1] == 0)
		{
			return i + PAGE_SIZE + 1;
		}
	}

	return 0;
}

template<unsigned int bitsize>
uint32_t pepp::ImportDirectory<bitsize>::GetEmptyOffsetAtThunkData(size_t nPageIndex)
{
	using ThunkData_t = typename detail::Image_t<bitsize>::ThunkData_t;
	uint32_t start_page = nPageIndex * PAGE_SIZE;
	SectionHeader newSec;
	newSec = m_image->GetSectionHeader(".pepp");
	mem::ByteVector* buffer = &m_image->buffer();
	char* ThunkDataBuf = buffer->as<char*>(newSec.GetPointerToRawData() + start_page);
	for (int i = 0;i < PAGE_SIZE/2;i+=sizeof(ThunkData_t))
	{
		if (((ThunkData_t*)(ThunkDataBuf+i))->u1.AddressOfData == 0)
			return i + start_page;
	}
	//ASSERT(0);
	MessageBoxA(0, "GetEmptyOffsetAtThunkData 0", 0, 0);
	return 0;
}

template<unsigned int bitsize>
uint32_t pepp::ImportDirectory<bitsize>::GetEmptyOffsetAtImp(size_t nPageIndex)
{
	uint32_t start_page = nPageIndex * PAGE_SIZE;
	SectionHeader newSec;
	newSec = m_image->GetSectionHeader(".pepp");
	mem::ByteVector* buffer = &m_image->buffer();
	char* ImpBuffer = buffer->as<char*>(newSec.GetPointerToRawData() + start_page);
	
	for (int i= PAGE_SIZE / 2;i< ONE_IID_PAGE_SIZE;i+=sizeof(DWORD))
	{
		if (*(PDWORD)(ImpBuffer+i) == 0)
		{
			return i + start_page;
		}
	}
	//ASSERT(0);
	MessageBoxA(0, "GetEmptyOffsetAtImp 0", 0, 0);
	return 0;
}

template<unsigned int bitsize>
void ImportDirectory<bitsize>::GetIATOffsets(std::uint32_t& begin, std::uint32_t& end) noexcept
{
	//
	// Null out.
	begin = end = 0;

	IMAGE_DATA_DIRECTORY const& iat = m_image->GetPEHeader().GetOptionalHeader().GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IAT);
	if (iat.Size == 0)
		return;


	begin = m_image->GetPEHeader().RvaToOffset(iat.VirtualAddress);
	end = begin + iat.Size;
}
