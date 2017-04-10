
#include "stdafx.h"
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <string.h>
#include <time.h>

HANDLE hEvent = NULL; // Для перехвата Ctrl+C.

// Прототип функции NtQuerySystemInformation().
NTSTATUS (_stdcall *pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, 
											   PVOID SystemInformation, 
											   ULONG SystemInformationLength, 
											   PULONG ReturnLength);
HMODULE hNtdll;

typedef struct _SYSTЕM_PROCЕSSЕS_INFO
{
    ULONG            NextEntryOffset;
    ULONG            NumberOfThreads;
    BYTE             _unknown1[24];
    LARGE_INTEGER    CreateTime;
    LARGE_INTEGER    UserTime;
    LARGE_INTEGER    KernelTime;
    UNICODE_STRING   ImageName;
    LONG             BasePriority;
    ULONG            UniqueProcessId;
    ULONG            InheritedFromUniqueProcessId;
    LONG             HandleCount;
    ULONG            SessionId;
    ULONG            _unknown2;
    // VM counters
    SIZE_T           PeakVirtualSize;
    SIZE_T           VirtualSize;
    ULONG            PageFaultCount;
    SIZE_T           PeakWorkingSetSize;
    SIZE_T           WorkingSetSize;
    SIZE_T           QuotaPeakPagedPoolUsage;
    SIZE_T           QuotaPagedPoolUsage;
    SIZE_T           QuotaPeakNonPagedPoolUsage;
    SIZE_T           QuotaNonPagedPoolUsage;
    SIZE_T           PagefileUsage;
    SIZE_T           PeakPagefileUsage;
    SIZE_T           PrivatePageCount;
#if _WIN32_WINNT >= 0x500 // Win2k и выше.
    // IO counters
    ULONGLONG        ReadOperationCount;
    ULONGLONG        WriteOperationCount;
    ULONGLONG        OtherOperationCount;
    ULONGLONG        ReadTransferCount;
    ULONGLONG        WriteTransferCount;
    ULONGLONG        OtherTransferCount;
#endif
} SYSTЕM_PROCЕSSЕS_INFO, *PSYSTЕM_PROCЕSSЕS_INFO;

// Получение информации о процессе по его PID.
BOOL QueryProcInfo(DWORD dwPID, PSYSTЕM_PROCЕSSЕS_INFO pProcInfo)
{
	NTSTATUS result;

	// Определение требуемого размера буфера.
	DWORD dwReturnLength = 0;
	result = pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwReturnLength);
	if (result != STATUS_INFO_LENGTH_MISMATCH) return FALSE;

	// Получение информации обо всех процессах.
	BYTE *pBuffer = new BYTE [dwReturnLength];
	result = pNtQuerySystemInformation(SystemProcessInformation, pBuffer, dwReturnLength, 
		&dwReturnLength);
	if (result != STATUS_SUCCESS) return FALSE;

	SYSTЕM_PROCЕSSЕS_INFO *spi;
	DWORD offset = 0;
	BOOL flag = FALSE;

	// Ищем нужный процесс по ID.
	do
	{
		spi = (SYSTЕM_PROCЕSSЕS_INFO*)(pBuffer + offset);

		if (spi->UniqueProcessId == dwPID)
		{
			memcpy(pProcInfo, spi, sizeof(SYSTЕM_PROCЕSSЕS_INFO));
			flag = TRUE;
			break;
		}

		offset += spi->NextEntryOffset;
	}
	while(spi->NextEntryOffset != 0);

	if (!flag) return FALSE;
	delete [] pBuffer;
	return TRUE;
}

// Получение информации о процессе по его PID (+ загрузка ЦП).
BOOL QueryProcInfoEx(DWORD dwPID, PSYSTЕM_PROCЕSSЕS_INFO pProcInfo, BYTE *pCpuUsage)
{
	BOOL result;
	SYSTЕM_PROCЕSSЕS_INFO spi1, spi2;

	// Подсчет загрузки за 0.1 сек.
	result = QueryProcInfo(dwPID, &spi1); if (!result) return FALSE;
	Sleep(100);
	result = QueryProcInfo(dwPID, &spi2); if (!result) return FALSE;

	DWORD dwDelUserTime, dwDelKernelTime, dwTotalUsage;

	dwDelUserTime   = (spi2.UserTime.LowPart - spi1.UserTime.LowPart) / 10000;
	dwDelKernelTime = (spi2.KernelTime.LowPart - spi1.KernelTime.LowPart) / 10000;
	dwTotalUsage    = dwDelUserTime + dwDelKernelTime;

	*pCpuUsage    = (BYTE)dwTotalUsage;
	if (dwTotalUsage > 100) *pCpuUsage = 100; // Из-за неточности работы Sleep() такое может быть.
	
	memcpy(pProcInfo, &spi2, sizeof(SYSTЕM_PROCЕSSЕS_INFO));

	return TRUE;
}

// Обработчик событий консоли.
BOOL WINAPI Handler(DWORD dwCtrlType)
{
	if (!hEvent) return FALSE;

	switch (dwCtrlType)
	{
		case CTRL_C_EVENT:
			SetEvent(hEvent);
		break;
		default:
		break;
	}

	return TRUE;
}

// Разность между отсчетами системного времени.
SYSTEMTIME DiffSystemTime(const SYSTEMTIME &st1, const SYSTEMTIME &st2)
{
    SYSTEMTIME     res;
    FILETIME       ft;
    ULARGE_INTEGER ui_buf;
    __int64        t1, t2, dt;

    SystemTimeToFileTime(&st1, &ft);
    ui_buf.LowPart  = ft.dwLowDateTime;
    ui_buf.HighPart = ft.dwHighDateTime;
    t1 = ui_buf.QuadPart;

    SystemTimeToFileTime(&st2, &ft);
    ui_buf.LowPart  = ft.dwLowDateTime;
    ui_buf.HighPart = ft.dwHighDateTime;
    t2 = ui_buf.QuadPart;

    dt = t2 - t1;

    ui_buf.QuadPart = dt;
    ft.dwLowDateTime  = ui_buf.LowPart;
    ft.dwHighDateTime = ui_buf.HighPart;
    FileTimeToSystemTime(&ft, &res);

    return res;
}

int _tmain(int argc, _TCHAR* argv[])
{
	setlocale(0, "");

	// Загружаем библиотеку и получаем адрес функции.
	hNtdll = LoadLibrary(L"ntdll.dll");
	if (!hNtdll) return 1;
	(FARPROC&)(pNtQuerySystemInformation) = GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) { FreeLibrary(hNtdll); return 1; }

	SYSTЕM_PROCЕSSЕS_INFO spi;
	BYTE                  nCpuUsage;
	DWORD                 dwPID;
	DWORD                 dwWait;

	dwPID = _wtoi(argv[1]);

	// Задаем обработчик для событий консоли.
	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!hEvent) { FreeLibrary(hNtdll); return 1; }
	if (!SetConsoleCtrlHandler(Handler, TRUE)) { FreeLibrary(hNtdll); return 1; }

	char szBuffer[100];
	sprintf(szBuffer, "%04d_stat.txt", dwPID);
	FILE *pf = fopen(szBuffer, "w");
	if (!pf) { FreeLibrary(hNtdll); return 1; }

	printf("Начат мониторинг процесса.\n");
	SYSTEMTIME st1, st2, st_dt;
	GetLocalTime(&st1);
	sprintf(szBuffer, "%02d:%02d:%02d,%d", st1.wHour, st1.wMinute, st1.wSecond, 
		st1.wMilliseconds);
	printf("Время начала: %s\n", szBuffer);
	time_t t1 = time(NULL);

	while(TRUE)
	{
		if (!QueryProcInfoEx(dwPID, &spi, &nCpuUsage)) break;
		fprintf(pf, "%d %d %d %d %d %d %llu %llu %llu %llu %llu %llu %llu %llu %d\n", 
			spi.VirtualSize,
			spi.WorkingSetSize,
			spi.QuotaPagedPoolUsage,
			spi.QuotaNonPagedPoolUsage,
			spi.PagefileUsage,
			spi.PrivatePageCount,
			spi.UserTime.QuadPart,
			spi.KernelTime.QuadPart,
			spi.ReadOperationCount,
			spi.WriteOperationCount,
			spi.OtherOperationCount,
			spi.ReadTransferCount,
			spi.WriteTransferCount,
			spi.OtherTransferCount,
			nCpuUsage);

		time_t t2 = time(NULL);
		time_t dt = t2 - t1;
		int min = dt / 60;
		int sec = dt - min * 60;
		sprintf(szBuffer, "Длительность мониторинга: %02d:%02d", min, sec);
		printf("\r%s", szBuffer);

		dwWait = WaitForSingleObject(hEvent, 100);
		if (dwWait == WAIT_OBJECT_0) break;
	}

	printf("\nМониторинг процесса успешно завершен.\n");
	GetLocalTime(&st2);
	sprintf(szBuffer, "%02d:%02d:%02d,%d", st2.wHour, st2.wMinute, st2.wSecond, 
		st2.wMilliseconds);
	printf("Время окончания: %s\n", szBuffer);

	st_dt = DiffSystemTime(st1, st2);
	sprintf(szBuffer, "%02d:%02d:%02d,%d", st_dt.wHour, st_dt.wMinute, st_dt.wSecond, 
		st_dt.wMilliseconds);
	printf("Длительность мониторинга (точно): %s\n", szBuffer);

	fclose(pf);
	FreeLibrary(hNtdll);
	CloseHandle(hEvent);
	SetConsoleCtrlHandler(Handler, FALSE);
	return 0;
}

