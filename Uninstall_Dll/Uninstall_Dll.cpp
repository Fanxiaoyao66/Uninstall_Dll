//Uninstall_Dll.exe
#include "windows.h"
#include "tlhelp32.h"
#include "tchar.h"

#define DEF_PROC_NAME (L"notepad.exe")
#define DEF_DLL_NAME (L"myhack.dll")

//获取进程ID
DWORD FindProcessID(LPCTSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	//HANDLE句柄指的是一个核心对象在某一个进程中的唯一索引，而不是指针。
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;				//用来存放快照进程信息的一个结构体

	//获取系统快照
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);		//如果函数成功，它将返回指定快照的打开句柄。

	//查找进程
	Process32First(hSnapShot, &pe);
	do
	{
		if (!_tcsicmp(szProcessName, (LPCTSTR)pe.szExeFile))		//szExeFile:进程的可执行文件的名称
		{
			dwPID = pe.th32ProcessID;			//进程标识符
			break;
		}
	}
	while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);			//要销毁快照，请使用 CloseHandle函数。

	return dwPID;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;		//TOKEN_PRIVILEGES结构包含有关访问令牌的一组权限的信息,第一个参数PrivilegeCount指定特权数组的个数(因为下一个参数是一个数组)
																					//第二个参数是一个LUID_AND_ATTRIBUTES（包括一个luid和对应的特权属性Attributes）结构体Privileges
	HANDLE hToken;
	LUID luid;		//描述适配器的本地标识符

	//OpenProcessToken函数用来打开与进程相关联的访问令牌(用来开启访问权限)。 
	//GetCurrentProcess获取当前进程的一个伪句柄,不需要closehandle函数关闭句柄。
	if (!(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)))
	{ 
		_tprintf(L"OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	//LookupPrivilegeValue函数查看系统权限的特权值，返回信息到一个LUID结构体里。
	if (!(LookupPrivilegeValue(NULL,  //第一个参数表示所要查看的系统，本地系统直接用NULL
		lpszPrivilege,			//第二个参数指定特权的名称
		&luid)))	//第三个参数用来接收所返回的指定特权名称的信息。
	{
		_tprintf(L"LookupPrivilegeValue Error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	//Enable the privilege or disable all privileges.启用或禁止指定访问令牌的特权
	if (!AdjustTokenPrivileges(hToken,//包含要修改特权的访问令牌的标识(句柄)
		FALSE,//标志这个函数是否禁用该令牌的所有特权,TRUE->NewState无效 FALSE->以NewState参数指针的信息为基础来修改特权.
		&tp,
		sizeof(TOKEN_PRIVILEGES),//指定下面这个参数指向缓冲区的大小
		(PTOKEN_PRIVILEGES)NULL,//填充一个TOKEN_PRIVILEGES结构体指针,包括该函数修改之前任何特权状态
		(PDWORD)NULL))//上面参数指向的缓冲区的所需大小
	{
		_tprintf(L"AdjustTokenPrivileges Error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		_tprintf(L"The Token does not have the specified privilege. \n");
		return FALSE;
	}
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hMoudule = NULL;
	MODULEENTRY32 me = { sizeof(me) };//模块条目 entry：条目
	LPTHREAD_START_ROUTINE pThreadProc;

	//dwPID=notepad进程ID
	//使用TH32CS_SNAPMODULE参数获取加载到notepad进程的DLL名称
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (_tcsicmp((LPCTSTR)me.szModule, szDllName) || _tcsicmp((LPCTSTR)me.szExePath, szDllName))
		{
			bFound = TRUE;
				break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf(L"OpenProcess(%d) Failed!![%d]\n", dwPID, GetLastError());
		return FALSE;
	}

	hMoudule = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMoudule, "FreeLibrary");

	hThread = CreateRemoteThread(hProcess,
		NULL,
		0,
		pThreadProc,
		me.modBaseAddr,
		0,
		NULL);
	WaitForSingleObject(hThread, INFINITE); //等待CreateRemoteThread函数执行完毕，否则将一直等待
	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
	DWORD dwPID = 0xFFFFFFFF;

	//获取进程ID
	dwPID = FindProcessID(DEF_PROC_NAME);
	if (dwPID == 0xFFFFFFF)
	{
		_tprintf(L"There is no %s process!\n", DEF_PROC_NAME);
		return 1;
	}

	_tprintf(L"PID of \"%s\" is %d\n", DEF_PROC_NAME, TRUE);

	//更改privilege
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
		return 1;


	//卸载Dll
	if (EjectDll(dwPID, DEF_PROC_NAME))
		_tprintf(L"EjectDll(%d,\"%s\") success!!!\n", dwPID, DEF_DLL_NAME);
	else
		_tprintf(L"EjectDll(%d,\"%s\") failed!!!\n", dwPID, DEF_DLL_NAME);

	return 0;
}

