//Uninstall_Dll.exe
#include "windows.h"
#include "tlhelp32.h"
#include "tchar.h"

#define DEF_PROC_NAME (L"notepad.exe")
#define DEF_DLL_NAME (L"myhack.dll")

//��ȡ����ID
DWORD FindProcessID(LPCTSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	//HANDLE���ָ����һ�����Ķ�����ĳһ�������е�Ψһ������������ָ�롣
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;				//������ſ��ս�����Ϣ��һ���ṹ��

	//��ȡϵͳ����
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);		//��������ɹ�����������ָ�����յĴ򿪾����

	//���ҽ���
	Process32First(hSnapShot, &pe);
	do
	{
		if (!_tcsicmp(szProcessName, (LPCTSTR)pe.szExeFile))		//szExeFile:���̵Ŀ�ִ���ļ�������
		{
			dwPID = pe.th32ProcessID;			//���̱�ʶ��
			break;
		}
	}
	while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);			//Ҫ���ٿ��գ���ʹ�� CloseHandle������

	return dwPID;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;		//TOKEN_PRIVILEGES�ṹ�����йط������Ƶ�һ��Ȩ�޵���Ϣ,��һ������PrivilegeCountָ����Ȩ����ĸ���(��Ϊ��һ��������һ������)
																					//�ڶ���������һ��LUID_AND_ATTRIBUTES������һ��luid�Ͷ�Ӧ����Ȩ����Attributes���ṹ��Privileges
	HANDLE hToken;
	LUID luid;		//�����������ı��ر�ʶ��

	//OpenProcessToken���������������������ķ�������(������������Ȩ��)�� 
	//GetCurrentProcess��ȡ��ǰ���̵�һ��α���,����Ҫclosehandle�����رվ����
	if (!(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)))
	{ 
		_tprintf(L"OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	//LookupPrivilegeValue�����鿴ϵͳȨ�޵���Ȩֵ��������Ϣ��һ��LUID�ṹ���
	if (!(LookupPrivilegeValue(NULL,  //��һ��������ʾ��Ҫ�鿴��ϵͳ������ϵͳֱ����NULL
		lpszPrivilege,			//�ڶ�������ָ����Ȩ������
		&luid)))	//�����������������������ص�ָ����Ȩ���Ƶ���Ϣ��
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

	//Enable the privilege or disable all privileges.���û��ָֹ���������Ƶ���Ȩ
	if (!AdjustTokenPrivileges(hToken,//����Ҫ�޸���Ȩ�ķ������Ƶı�ʶ(���)
		FALSE,//��־��������Ƿ���ø����Ƶ�������Ȩ,TRUE->NewState��Ч FALSE->��NewState����ָ�����ϢΪ�������޸���Ȩ.
		&tp,
		sizeof(TOKEN_PRIVILEGES),//ָ�������������ָ�򻺳����Ĵ�С
		(PTOKEN_PRIVILEGES)NULL,//���һ��TOKEN_PRIVILEGES�ṹ��ָ��,�����ú����޸�֮ǰ�κ���Ȩ״̬
		(PDWORD)NULL))//�������ָ��Ļ������������С
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
	MODULEENTRY32 me = { sizeof(me) };//ģ����Ŀ entry����Ŀ
	LPTHREAD_START_ROUTINE pThreadProc;

	//dwPID=notepad����ID
	//ʹ��TH32CS_SNAPMODULE������ȡ���ص�notepad���̵�DLL����
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
	WaitForSingleObject(hThread, INFINITE); //�ȴ�CreateRemoteThread����ִ����ϣ�����һֱ�ȴ�
	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
	DWORD dwPID = 0xFFFFFFFF;

	//��ȡ����ID
	dwPID = FindProcessID(DEF_PROC_NAME);
	if (dwPID == 0xFFFFFFF)
	{
		_tprintf(L"There is no %s process!\n", DEF_PROC_NAME);
		return 1;
	}

	_tprintf(L"PID of \"%s\" is %d\n", DEF_PROC_NAME, TRUE);

	//����privilege
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
		return 1;


	//ж��Dll
	if (EjectDll(dwPID, DEF_PROC_NAME))
		_tprintf(L"EjectDll(%d,\"%s\") success!!!\n", dwPID, DEF_DLL_NAME);
	else
		_tprintf(L"EjectDll(%d,\"%s\") failed!!!\n", dwPID, DEF_DLL_NAME);

	return 0;
}

