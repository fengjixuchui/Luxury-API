//#include "LuxuryAPI.h"
#include "api.h"

int main()
{	
	Process Notepad(L"notepad.exe");

	if (Notepad.IsValid()) {
		std::cout << "Notepad Is Valid!\n\n";
	}
	else {
		std::cout << "Notepad Is Not Valid!\n\n";
	} getchar();

	Notepad.Print();
	getchar();

	auto r = Notepad.Read<int>(0x21945BE0B68, sizeof(int));
	std::cout << std::dec << r;
	getchar();

	Notepad.Write<int>(0x21945BE0B68, 69, sizeof(int));
	getchar();

	auto b = Notepad.IsDebuggerPresent();

	std::cout << (b == true ? "Debugger Is Present!" : "Debugger Is Not Present") << "\n";
	getchar();

	auto Addr = Notepad.Scan(
		"\x48\x76\xD8\x45\x19\x02\x00\x00", 
		"xxxxxxxx"
	);

	PrintHexS(Addr);
	getchar();

	std::cout << (Notepad.IsRunning() == true ? "Notepad Is Running!\n" : "Notepad Is Not Running!\n");
	getchar();

	std::cout << (Notepad.IsConnectedToTCPTable() == true ? "Notepad Is Connected!\n" : "Notepad Is Not Connected!\n");
	getchar();

	Process PerfWatson(L"PerfWatson2.exe");

	if (PerfWatson.IsValid()) {
		std::cout << "PerfWatson Is Valid!\n\n";
	}
	else {
		std::cout << "PerfWatson Is Not Valid!\n\n";
	} getchar();

	PerfWatson.Print();
	getchar();

	std::cout << (PerfWatson.IsRunning() == true ? "PerfWatson Is Running!\n" : "ProcessHacker Is Not Running!\n");
	getchar();

	std::cout << (PerfWatson.IsConnectedToTCPTable() == true ? "PerfWatson Is Connected!\n" : "PerfWatson Is Not Connected!\n");
	getchar();

	auto Chrome = KernelProcess(L"chrome.exe");

	HANDLE Handle = Chrome.ElevateHandle();
	return 0;
}


/*VOID Test()
{
	INT Value = 10;

	Luxury::Launch("C:\\Windows\\notepad.exe");
	Sleep(1000);

	DWORD PID = Luxury::GetProcessID(L"notepad.exe"); // get process id
	std::cout << "Notepad Process ID: " << PID << "\n\n";


	HANDLE hNotepad = Luxury::GetHandle(L"notepad.exe"); // get handle (ALL_ACCESS)
	if (hNotepad != INVALID_HANDLE_VALUE)
		std::cout << "Handle opened!\n\n";


	ULONGLONG Base = Luxury::GetBaseAddress(L"notepad.exe", hNotepad); // get base address
	std::cout << "Notepad Base Address: ";
	Luxury::PrintHex(Base);


	INT Buffer = Luxury::ReadMemory<INT>(hNotepad, Base + 0x2B1A0, sizeof(INT)); // read memory
	std::cout << "\n\nRead Value: " << Buffer << "\n\n";

	Luxury::WriteMemory(hNotepad, Base + 0x2B1A0, &Value, sizeof(INT)); // write memory
	std::cout << "Memory Written!\n\n";


	INT Buffer2 = Luxury::CopyProcessMemory<INT>(hNotepad, Base + 0x2B1A0, sizeof(INT), TRUE, NULL); // read memory 2
	std::cout << "\n\nRead Value 2: " << Buffer2 << "\n\n";

	Luxury::CopyProcessMemory<INT>(hNotepad, Base + 0x2B1A0, sizeof(INT), FALSE, 20); // write memory 2
	std::cout << "Memory Written 2!\n\n";


	BOOL IsRunning = Luxury::IsProcessRunning(L"notepad.exe"); // check if process is running

	if (IsRunning)
		std::cout << "Notepad is running!\n\n";
	else
		std::cout << "Notepad is not running!\n\n";


	std::string RandomString = Luxury::GenerateRandomStringA(10, TRUE, RANDOM_MIXED); // generate a random string 10 chars long, with numbers, and with both capitalized and non-capitalized chars
	std::cout << "Random String generated: " << RandomString << "\n\n";


	BOOL IsBeingDebugged = Luxury::BeingDebugged(FALSE, L"notepad.exe"); // check if remote process is being debugged

	if (IsBeingDebugged)
		std::cout << "Notepad is being debugged!\n\n";
	else
		std::cout << "Notepad is not being debugged!\n\n";


	BOOL IsCurrentBeingDebugged = Luxury::BeingDebugged(TRUE, nullptr); // check if current process is being debugged

	if (IsCurrentBeingDebugged)
		std::cout << "The current process is being debugged!\n\n";
	else
		std::cout << "The current process is not being debugged!\n\n";


	BOOL CheckFile = Luxury::DoesFileExist("C:\\Users\\xan\\Desktop\\Forcer.exe"); // check if file exists

	if (CheckFile)
		std::cout << "C:\\Users\\xan\\Desktop\\Forcer.exe exists!\n\n";
	else
		std::cout << "C:\\Users\\xan\\Desktop\\Forcer.exe does not exist!\n\n";


	BOOL stob = Luxury::StringToBool("true"); // convert string to bool
	if (stob)
		std::cout << "stob is true!\n\n";
	else
		std::cout << "stob is false!\n\n";


	COLORREF Red = Luxury::StringToColor("red"); // convert string to colorref
	if (Red == RGB(255, 0, 0))
		std::cout << "Successfully converted string to color!\n\n";
	else
		std::cout << "Failed to convert string to color!\n\n";


	UNICODE_STRING usString = Luxury::ReturnUnicodeString(L"My Unicode String"); // create unicode string
	std::wcout << "Unicode String: " << usString.Buffer << "\n\n";

	std::string NoWhitespaces = Luxury::RemoveWhitespaces("s t r i n g"); // remove whitespaces
	std::cout << "Whitespaces removed from: " << NoWhitespaces << "\n\n";

	Sleep(3000);

	BOOL IsDead = Luxury::KillProcess(L"notepad.exe");

	std::cout << "Random float: ";
	Luxury::PrintFloat(69.69, 2);

	std::cout << "\n\nTesting Complete";
	Luxury::PrintPeriods(3, 500);
	getchar();
}*/