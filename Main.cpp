#include <iostream>
#include <Windows.h>
#include <vector>
#include <TlHelp32.h>

std::vector<PROCESSENTRY32> GetAllProcessesByNameW(std::wstring ProcessName) {
	std::vector<PROCESSENTRY32> ValidProcessesList;

	HANDLE ProcessListSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL IterationSuccess;
	PROCESSENTRY32 IterativeProcess;
	IterativeProcess.dwSize = sizeof(PROCESSENTRY32);
	for (IterationSuccess = Process32First(ProcessListSnapshot, &IterativeProcess);
		IterationSuccess;
		IterationSuccess = Process32Next(ProcessListSnapshot, &IterativeProcess)) {
		if (lstrcmpW(IterativeProcess.szExeFile, ProcessName.c_str()) == 0) {
			ValidProcessesList.push_back(IterativeProcess);
		}
	}
	return ValidProcessesList;
}
bool IsRunningUnderSandbox() {
	std::vector<PROCESSENTRY32> ProcessList = GetAllProcessesByNameW(L"SbieSvc.exe");
	//printf("[*] Found %d SbieSvc.exe processes.\n", ProcessList.size());
	if (ProcessList.size() == 0) {
		//printf("[!] Therefore I can't be in a Sandboxie+ sandbox.\n");
		return false;
	}
	bool CouldTerminate = false;
	for (PROCESSENTRY32 IterativeProcess : ProcessList) {
		HANDLE IterativeProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, IterativeProcess.th32ProcessID);
		if (IterativeProcessHandle == INVALID_HANDLE_VALUE) {
			//printf("[*] Couldn't open a handle to PID: %ld.\nGetLastError() returned %ld.\n", IterativeProcess.th32ProcessID, GetLastError());
			continue;
		}
		//printf("[*] Opened a valid handle to PID: %ld.\n", IterativeProcess.th32ProcessID);
		if (!TerminateProcess(IterativeProcessHandle, 0)) {
			//printf("[*] Couldn't terminate PID: %ld.\nGetLastError() returned %ld.\n", IterativeProcess.th32ProcessID, GetLastError());
			if (GetLastError() == 5) { // ACCESS_DENIED, usually Sandboxie+!
				return TRUE;
			}
			continue;
		}
		//printf("[*] Managed to terminate PID: %ld.\n", IterativeProcess.th32ProcessID);
	}
	return FALSE;
}

int main() {
	printf("Verdict: %s", IsRunningUnderSandbox() ? "SANDBOX!\n" : "CLEAN!\n");
	system("PAUSE");
}
