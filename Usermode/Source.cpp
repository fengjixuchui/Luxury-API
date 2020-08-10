#include "api.h"

using std::string;
using std::vector;

void OnValueChanged(SliderObject* Slider) {
	return;
}

void OnExit(SliderObject* Slider) {
	return;
}

void OnTick(SliderObject* Slider) {
	return;
}

//int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
//	std::thread( [] () { SliderObject().Init(OnValueChanged, OnExit, OnTick); } );
//}


typedef struct SMBIOSData {
private:

	struct RawSMBIOSData {
		BYTE	Used20CallingMethod;
		BYTE	SMBIOSMajorVersion;
		BYTE	SMBIOSMinorVersion;
		BYTE	DmiRevision;
		DWORD	Length;
		BYTE	SMBIOSTableData[ANY_SIZE];
	};

	struct DMI_HEADER {
		BYTE Type;
		BYTE Length;
		WORD Handle;
	};

	struct MoboData {
		DMI_HEADER Header;
		UCHAR	Manufacturer;
		UCHAR	Product;
		UCHAR	Version;
		UCHAR	SerialNumber;
	};

	typedef struct SMBIOS {
		const char* Manufacturer;
		const char* Product;
		const char* Version;
		const char* SerialNumber;
		const char* UUID;
		const char* SKU;
		const char* Family;
	};


	const char* GetUUID(const BYTE* Header, short Version) {
		this->Version = Version;
		int _0xFF{ 1 };

		for (int i = 0; i < 16 && _0xFF; i++) {
			if (!Header[i]) {
				return "null";
			} if (Header[i] != 0xFF) {
				_0xFF = 0;
			}
		} 
		
		if (_0xFF) {
			return "null";
		}

		if (Version >= 0x206) {
			return reinterpret_cast<const char*>(
				Header[3], Header[2], Header[1], Header[0], Header[5], Header[4], Header[7], Header[6],
				Header[8], Header[9], Header[10], Header[11], Header[12], Header[13], Header[14], Header[15]
			);
		} else {
			return reinterpret_cast<const char*>(
				Header[0], Header[1], Header[2], Header[3], Header[4], Header[5], Header[6], Header[7],
				Header[8], Header[9], Header[10], Header[11], Header[12], Header[13], Header[14], Header[15]
			);
		}
	}


	const char* ToString(const DMI_HEADER* Header, BYTE s) {
		auto HeaderString{ const_cast<char*>(reinterpret_cast<const char*>(Header)) };
		SIZE_T i{ 0 };

		if (s == 0) {
			return "null";
		}

		HeaderString += Header->Length;

		while (s > 1 && *HeaderString) {
			HeaderString += strlen(HeaderString);
			HeaderString++;
			s--;
		}

		if (!*HeaderString) {
			return "null";
		}

		SIZE_T Length{ strlen(HeaderString) };

		for (i = 0; i < Length; i++) {
			if (HeaderString[i] < 32 || HeaderString[i] == 127) {
				HeaderString[i] = '.';
			}
		}

		return HeaderString;
	}

public:

	DWORD Version{ 0 };
	SMBIOS* Motherboard{ new SMBIOS };


	SMBIOSData() {
		DWORD RequiredSize{ GetSystemFirmwareTable('RSMB', 0, NULL, 0) };

		if (auto FirmwareTable{ static_cast<RawSMBIOSData*>( malloc( GetSystemFirmwareTable('RSMB', 0, nullptr, 0) ) ) }) {
			GetSystemFirmwareTable('RSMB', 0, FirmwareTable, RequiredSize);

			for (int i = 0; i < FirmwareTable->Length; i++) {
				auto Header = (DMI_HEADER*)&FirmwareTable->SMBIOSTableData;

				if (Header->Type == 1) {
					this->Motherboard->Manufacturer = ToString(Header, reinterpret_cast<BYTE*>(Header)[0x4]);
					this->Motherboard->Product = ToString(Header, reinterpret_cast<BYTE*>(Header)[0x5]);
					this->Motherboard->Version = ToString(Header, reinterpret_cast<BYTE*>(Header)[0x6]);
					this->Motherboard->SerialNumber = ToString(Header, reinterpret_cast<BYTE*>(Header)[0x7]);
					this->Motherboard->UUID = GetUUID(reinterpret_cast<BYTE*>(Header) + 0x8, FirmwareTable->SMBIOSMajorVersion * 0x100 + FirmwareTable->SMBIOSMinorVersion);
					this->Motherboard->SKU = ToString(Header, reinterpret_cast<BYTE*>(Header)[0x19]);
					this->Motherboard->Family = ToString(Header, reinterpret_cast<BYTE*>(Header)[0x1a]);
					free(FirmwareTable);
					return;
				}

				Header += Header->Length;

				while (*reinterpret_cast<USHORT*>(Header) != 0) {
					Header++;
				} Header += 2;
			}
		}
	}

	SMBIOS* Get() {
		return this->Motherboard;
	}

	~SMBIOSData() {
		delete Motherboard;
	}
};


class HardwareId : public SMBIOSData {

public:

	struct HardwareIdData {
	private:

		DWORD Version;

	public:

		DWORD64 Hash{ 0 };

		struct {
			const char* SerialNumber;
			const char* Vendor;
			const char* Product;
		} Disk;

		struct {
			const char* Manufacturer;
			const char* Product;
			const char* Version;
			const char* SerialNumber;
			const char* UUID;
			const char* SKU;
			const char* Family;
		} SMBIOS;
		
		struct {
			std::vector <DWORD> *Features{ new std::vector <DWORD> };
			WORD Architecture;
			WORD ProcessorLevel;
			DWORD64 ActiveProcessorMask;
			DWORD64 Hash;
		} CPU;

		struct {
			const char* MachineGUID;
			const char* ComputerHardwareId;
			const char* SQMClientMachineId;
			const char* BuildLab;
			DWORD64 InstallTime;
			DWORD64 InstallDate;
			DWORD64 BuildGUID;
		} Windows;

		void Init(DWORD Version) {
			this->Version = Version;

			if (auto Disk{ QueryDiskInformation() }) {
				this->Disk.SerialNumber = reinterpret_cast<char*>(Disk) + Disk->SerialNumberOffset;
				this->Disk.Vendor = reinterpret_cast<char*>(Disk) + Disk->VendorIdOffset;
				this->Disk.Product = reinterpret_cast<char*>(Disk) + Disk->ProductIdOffset;
			}

			SYSTEM_INFO ProcessorInfo{ 0 };
			GetSystemInfo(&ProcessorInfo);

			this->CPU.Architecture = ProcessorInfo.wProcessorArchitecture;
			this->CPU.ProcessorLevel = ProcessorInfo.wProcessorLevel;
			this->CPU.ActiveProcessorMask = ProcessorInfo.dwActiveProcessorMask;

			static vector <DWORD> CPUFeatures({ 25, 24, 26, 27, 18, 7, 16, 2, 14, 15, 23, 1, 0, 3, 12, 9, 8, 22, 20, 13, 21, 6, 10, 17, 29, 30, 31, 34 });

			for (int i = 0; i < CPUFeatures.size(); i++) {
				if (IsProcessorFeaturePresent(CPUFeatures.at(i))) {
					this->CPU.Features->push_back(CPUFeatures.at(i));
					this->CPU.Hash += CPUFeatures.at(i) * CPUFeatures.at(i);
				} else {
					CPUFeatures.erase(CPUFeatures.begin() + i);
				}
			} this->CPU.Features = &CPUFeatures;

			this->Windows.MachineGUID		 = GetHKLM("SOFTWARE\\Microsoft\\Cryptography",						   "MachineGuid");
			this->Windows.ComputerHardwareId = GetHKLM("SYSTEM\\CurrentControlSet\\Control\\SystemInformation",	   "ComputerHardwareId");
			this->Windows.SQMClientMachineId = GetHKLM("SOFTWARE\\Microsoft\\SQMClient",						   "MachineId");
			this->Windows.BuildLab			 = GetHKLM("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",		   "BuildLab");
			this->Windows.InstallTime		 = GetHKLM<DWORD64>("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallTime");
			this->Windows.InstallDate		 = GetHKLM<DWORD64>("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate");
			this->Windows.BuildGUID			 = GetHKLM<DWORD64>("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "BuildGUID");

			GenerateHWID();
		}

		DWORD64 GenerateHWID() {
			this->Hash = 
				this->Hash ? 
				this->Hash : 
				this->CPU.Hash * std::stoull(this->Disk.SerialNumber) * this->SMBIOS.Product[0, 3] * this->SMBIOS.Manufacturer[0, 3];

			return this->Hash;
		}

		template <typename T>
		T GetHKLM(const char* SubKey, const char* Value) {
			DWORD Size{};

			RegGetValueA(HKEY_LOCAL_MACHINE, SubKey, Value, RRF_RT_ANY, nullptr, nullptr, &Size);
			static T* Buffer{ reinterpret_cast<T*>(VirtualAlloc(nullptr, Size, MEM_COMMIT, PAGE_READWRITE)) };
			RegGetValueA(HKEY_LOCAL_MACHINE, SubKey, Value, RRF_RT_ANY, nullptr, (PVOID)Buffer, &Size);

			return *Buffer;
		}

		const char* GetHKLM(const char* SubKey, const char* Value) {
			DWORD Size{};
			std::string Ret{};

			RegGetValueA(HKEY_LOCAL_MACHINE, SubKey, Value, RRF_RT_REG_SZ, nullptr, nullptr, &Size);
			Ret.resize(Size);
			RegGetValueA(HKEY_LOCAL_MACHINE, SubKey, Value, RRF_RT_REG_SZ, nullptr, &Ret[0], &Size);

			return Ret.c_str();
		}


		void PrintUUID() {
			printf(
				(this->Version >= 0x206 
				? 
				"UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n" 
				: 
				"UUID: -%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n"
			), this->SMBIOS.UUID);
		}

	} HWID;

	HardwareId() {
		this->HWID.SMBIOS.Manufacturer = Motherboard->Manufacturer;
		this->HWID.SMBIOS.Product = Motherboard->Product;
		this->HWID.SMBIOS.Version = Motherboard->Version;
		this->HWID.SMBIOS.SerialNumber = Motherboard->SerialNumber;
		this->HWID.SMBIOS.UUID = Motherboard->UUID;
		this->HWID.SMBIOS.SKU = Motherboard->SKU;
		this->HWID.SMBIOS.Family = Motherboard->Family;
		
		this->HWID.Init(this->Version);
	};

	HardwareIdData* Get() {
		return &this->HWID;
	}
};



int main() {
	auto HWID{ HardwareId().Get() };

	PrintS("DISK\n");
	PrintS("Serial Number: ", HWID->Disk.SerialNumber);
	PrintS("Vendor: ", HWID->Disk.Vendor);
	PrintS("Product: ", HWID->Disk.Product);

	PrintS("\nSMBIOS\n");
	PrintS("Manufacturer: ", HWID->SMBIOS.Manufacturer);
	PrintS("Product: ", HWID->SMBIOS.Product);
	PrintS("Version: ", HWID->SMBIOS.Version);
	PrintS("SerialNumber: ", HWID->SMBIOS.SerialNumber);
	HWID->PrintUUID();
	PrintS("SKU: ", HWID->SMBIOS.SKU);
	PrintS("Family: ", HWID->SMBIOS.Family);

	PrintS("\nWINDOWS\n");
	PrintS("Machine GUID: ", HWID->Windows.MachineGUID);
	PrintS("Computer Hardware Id: ", HWID->Windows.ComputerHardwareId);
	PrintS("SQM Client Machine Id: ", HWID->Windows.SQMClientMachineId);
	std::flush(std::cout);
	std::cout << "Install Time: " << HWID->Windows.InstallTime << std::endl;
	std::flush(std::cout);
	std::cout << "Install Data: " << HWID->Windows.InstallDate << std::endl;
	std::flush(std::cout);
	std::cout << "Build GUID: " << HWID->Windows.BuildGUID << std::endl;
	std::flush(std::cout);
	PrintS("Build Lab: ", HWID->Windows.BuildLab);
	std::flush(std::cout);


	PrintS("\nPROCESSOR\n");
	std::flush(std::cout);

	std::cout << "Archetecture: " << HWID->CPU.Architecture << std::endl;
	std::flush(std::cout);
	std::cout << "Level: " << HWID->CPU.ProcessorLevel << std::endl;
	std::flush(std::cout);
	std::cout << "Mask: " << HWID->CPU.ActiveProcessorMask << std::endl;
	std::flush(std::cout);

	std::cout << HWID->CPU.Features->size() << std::endl;
	std::flush(std::cout);

	for (int i = 0; i < HWID->CPU.Features->size(); i++) {
		std::cout << "Feature: " << HWID->CPU.Features->at(i) << std::endl;
		std::flush(std::cout);
	}

	std::cout << "Hash: " << HWID->CPU.Hash << std::endl;
	std::flush(std::cout);

	PrintS("\nHARDWARE ID\n");
	std::flush(std::cout);
	PrintHex(HWID->Hash);

	getchar();
    return 0;
}