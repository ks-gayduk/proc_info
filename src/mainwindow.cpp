#include "mainwindow.h"
#include "ui_mainwindow.h"

// Объявление прототипов функций.
NTSTATUS (_stdcall *pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                               PVOID SystemInformation,
                                               ULONG SystemInformationLength,
                                               PULONG ReturnLength);

NTSTATUS (_stdcall *pRtlUnicodeStringToAnsiString)(PANSI_STRING DestinationString,
                                                   PUNICODE_STRING SourceString,
                                                   BOOLEAN AllocateDestinationString);

NTSTATUS (_stdcall *pRtlFreeAnsiString)(PANSI_STRING AnsiString);

NTSTATUS (_stdcall *pNtQueryInformationProcess)(HANDLE ProcessHandle,
                                                PROCESSINFOCLASS ProcessInformationClass,
                                                PVOID ProcessInformation,
                                                ULONG ProcessInformationLength,
                                                PULONG ReturnLength);


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Основной слой, отступы.
    ui->centralWidget->setLayout(ui->horizontalLayout);
    ui->centralWidget->setContentsMargins(5, 5, 5, 5);

    // Получение адресов необходимых WinAPI-функций.
    hNtdll = LoadLibrary(L"ntdll.dll");
    (FARPROC&)(pNtQuerySystemInformation)     = GetProcAddress(hNtdll, "NtQuerySystemInformation");
    (FARPROC&)(pRtlUnicodeStringToAnsiString) = GetProcAddress(hNtdll, "RtlUnicodeStringToAnsiString");
    (FARPROC&)(pRtlFreeAnsiString)            = GetProcAddress(hNtdll, "RtlFreeAnsiString");
    (FARPROC&)(pNtQueryInformationProcess)    = GetProcAddress(hNtdll, "NtQueryInformationProcess");

    // Настройка вкладки "Процессы".
    ui->tabProcList->setLayout(ui->verticalLayout);
    ui->tabProcList->setContentsMargins(5, 5, 5, 5);
    ui->twProcesses->verticalHeader()->setVisible(false);
    QStringList list; list << "PID" << "Image Name" << "Command Line";
    ui->twProcesses->setHorizontalHeaderLabels(list);
    ui->twProcesses->setColumnWidth(0, 75);
    ui->twProcesses->setColumnWidth(1, 220);
    ui->twProcesses->setColumnWidth(2, 390);
    ui->tabWidget->setTabText(0, "Processes");
    ui->twProcesses->setEditTriggers(QTableWidget::NoEditTriggers);

    // Настройка вкладки "Память".
    ui->tabMemory->setLayout(ui->verticalLayout_2);
    ui->tabMemory->setContentsMargins(5, 5, 5, 5);
    ui->chartVirtualSize->xAxis->setLabel("t, s");
    ui->chartVirtualSize->yAxis->setLabel("size, pages x10^3");
    ui->chartWorkingSetSize->xAxis->setLabel("t, s");
    ui->chartWorkingSetSize->yAxis->setLabel("size, pages x10^3");
    ui->chartPagedPool->xAxis->setLabel("t, s");
    ui->chartPagedPool->yAxis->setLabel("Size, KiB");
    ui->chartNonPagedPool->xAxis->setLabel("t, s");
    ui->chartNonPagedPool->yAxis->setLabel("Size, KiB");
    ui->chartPagefileUsage->xAxis->setLabel("t, s");
    ui->chartPagefileUsage->yAxis->setLabel("size, pages x10^3");
    ui->chartPrivatePageCount->xAxis->setLabel("t, s");
    ui->chartPrivatePageCount->yAxis->setLabel("size, pages x10^3");

    // Настройка вкладки "ЦП".
    ui->tabCPU->setLayout(ui->verticalLayout_3);
    ui->tabCPU->setContentsMargins(5, 5, 5, 5);
    ui->chartUserTime->xAxis->setLabel("t, s");
    ui->chartUserTime->yAxis->setLabel("usage, s");
    ui->chartKernelTime->xAxis->setLabel("t, s");
    ui->chartKernelTime->yAxis->setLabel("usage, s");
    ui->chartTotalTime->xAxis->setLabel("t, s");
    ui->chartTotalTime->yAxis->setLabel("usage, s");
    ui->chartCpuUsage->xAxis->setLabel("t, s");
    ui->chartCpuUsage->yAxis->setLabel("usage, %");

    // Настройка вкладки "Ввод-вывод".
    ui->tabIO->setLayout(ui->verticalLayout_4);
    ui->tabIO->setContentsMargins(5, 5, 5, 5);
    ui->chartROC->xAxis->setLabel("t, s");
    ui->chartROC->yAxis->setLabel("count");
    ui->chartWOC->xAxis->setLabel("t, s");
    ui->chartWOC->yAxis->setLabel("count");
    ui->chartOOC->xAxis->setLabel("t, s");
    ui->chartOOC->yAxis->setLabel("count");
    ui->chartRTC->xAxis->setLabel("t, s");
    ui->chartRTC->yAxis->setLabel("bytes");
    ui->chartWTC->xAxis->setLabel("t, s");
    ui->chartWTC->yAxis->setLabel("bytes");
    ui->chartOTC->xAxis->setLabel("t, s");
    ui->chartOTC->yAxis->setLabel("bytes");

    // Таймер для организации периодических измерений.
    timMetering = new QTimer();
    connect(timMetering, SIGNAL(timeout()), this, SLOT(measStep()));
    timMetering->setTimerType(Qt::PreciseTimer);

    // Построение списка процессов при запуске приложения.
    GetProcessList();

    // Строка состояния.
    ui->statusBar->addWidget(&lbT1);
    ui->statusBar->addWidget(&lbT2);
    ui->statusBar->addWidget(&lbDT);
    lbT1.setText("Starting at: 00:00:00,000");
    lbT2.setText("Stoping at: 00:00:00,000");
    lbDT.setText("Monitoring time: 00:00:00,000");
    lbT1.setMinimumWidth(150);
    lbT2.setMinimumWidth(150);
    lbDT.setMinimumWidth(180);
}

MainWindow::~MainWindow()
{
    timMetering->deleteLater();
    FreeLibrary(hNtdll);
    delete timMetering;
    delete ui;
}

// Получение информации о процессе по его PID.
BOOL MainWindow::QueryProcInfo(DWORD dwPID, PSYSTEM_PROCESSES_INFO pProcInfo)
{
    NTSTATUS result;

    // Определение требуемого размера буфера.
    DWORD dwReturnLength = 0;
    result = pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, 
	&dwReturnLength);
    if (result != STATUS_INFO_LENGTH_MISMATCH) return FALSE;

    // Получение информации обо всех процессах.
    BYTE *pBuffer = new BYTE [dwReturnLength];
    result = pNtQuerySystemInformation(SystemProcessInformation, pBuffer, 
	dwReturnLength, &dwReturnLength);
    if (result != STATUS_SUCCESS) { delete [] pBuffer; return FALSE; }

    SYSTEM_PROCESSES_INFO *spi;
    DWORD offset = 0;
    BOOL flag = FALSE;

    // Ищем нужный процесс по ID.
    do
    {
        spi = (SYSTEM_PROCESSES_INFO*)(pBuffer + offset);

        if (spi->UniqueProcessId == dwPID)
        {
            memcpy(pProcInfo, spi, sizeof(SYSTEM_PROCESSES_INFO));
            flag = TRUE;
            break;
        }

        offset += spi->NextEntryOffset;
    }
    while(spi->NextEntryOffset != 0);

    if (!flag) { delete [] pBuffer; return FALSE; }
    delete [] pBuffer;
    return TRUE;
}

// Получение информации о процессе по его PID (+ загрузка ЦП).
BOOL MainWindow::QueryProcInfoEx(DWORD dwPID, PSYSTEM_PROCESSES_INFO pProcInfo,
                                 BYTE *pCpuUsage)
{
    BOOL result;
    SYSTEM_PROCESSES_INFO spi1, spi2;

    // Подсчет загрузки за 0.1 сек.
    result = QueryProcInfo(dwPID, &spi1); if (!result) return FALSE;
    Sleep(100);
    result = QueryProcInfo(dwPID, &spi2); if (!result) return FALSE;

    DWORD dwDelUserTime, dwDelKernelTime, dwTotalUsage;

    dwDelUserTime   = (spi2.UserTime.LowPart -
                       spi1.UserTime.LowPart) / 10000;
    dwDelKernelTime = (spi2.KernelTime.LowPart -
                       spi1.KernelTime.LowPart) / 10000;
    dwTotalUsage    = dwDelUserTime + dwDelKernelTime;

    *pCpuUsage    = (BYTE)dwTotalUsage;
    if (dwTotalUsage > 100) *pCpuUsage = 100; // Из-за неточности работы Sleep()
                                              // такое может быть.

    memcpy(pProcInfo, &spi2, sizeof(SYSTEM_PROCESSES_INFO));

    return TRUE;
}

// Назначение привилегии текущему процессу.
DWORD MainWindow::SetPrivilege(LPCTSTR Privilege)
{
    // Получение маркера доступа текущего процесса.
    HANDLE hToken;
    BOOL   bResult;
    bResult = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
                               &hToken);
    if (!bResult) return GetLastError();

    // Формирование структуры-списка привилегий.
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount           = 1;                    // Количество привилегий.
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // Привилегии включены.

    bResult = LookupPrivilegeValue(NULL, Privilege, &tp.Privileges[0].Luid);
    if (!bResult) { CloseHandle(hToken); return GetLastError(); }

    // Назначение привилегий текущему процессу.
    bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, 0, 0);
    if (!bResult) { CloseHandle(hToken); return GetLastError(); }

    CloseHandle(hToken);
    return 0;
}

// Определение командной строки процесса по его PID.
DWORD MainWindow::GetCommandLineProcess(DWORD dwPID, char *szCommandLine)
{
    // Чтоб получить дескриптор процесса и доступ к его адресному пространству,
    // нужно обладать привилегией отладчика.
    if (SetPrivilege(SE_DEBUG_NAME)) return GetLastError();

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return GetLastError();

    // Получаем указатель на структуру PROCESS_BASIC_INFORMATION.
    NTSTATUS                  result;
    PROCESS_BASIC_INFORMATION pbi;
    DWORD                     dwReturnLength;
    result = pNtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                        &pbi, sizeof(pbi), &dwReturnLength);
    if (result != STATUS_SUCCESS) { CloseHandle(hProcess); return GetLastError(); }

    // Считываем указатель на структуру RTL_USER_PROCESS_PARAMETERS.
    PPEB  pPebAddress = pbi.PebBaseAddress;
    PVOID rtlUserProcParamsAddress;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(pPebAddress) + 0x10,
                           &rtlUserProcParamsAddress, sizeof(PVOID), NULL))
    {
        CloseHandle(hProcess);
        return GetLastError();
    }

    // Считываем указатель на юникод-строку.
    UNICODE_STRING usCommandLine;
    if (!ReadProcessMemory(hProcess, (PCHAR)rtlUserProcParamsAddress + 0x40,
                           &usCommandLine, sizeof(usCommandLine), NULL))
    {
        CloseHandle(hProcess);
        return GetLastError();
    }

    // Считываем саму командную строку в формате ЮНИКОД.
    WCHAR *wcCommandLineContents;
    wcCommandLineContents = (WCHAR *)malloc(usCommandLine.Length);
    if (!ReadProcessMemory(hProcess, usCommandLine.Buffer,
                           wcCommandLineContents, usCommandLine.Length, NULL))
    {
        free(wcCommandLineContents);
        CloseHandle(hProcess);
        return GetLastError();
    }

    // Конвертируем WCHAR* в char*.
    char szBuffer[1024];
    size_t len = wcstombs(szBuffer, wcCommandLineContents, usCommandLine.Length / 2);
    if (len > 0) szBuffer[len] = '\0';
    else
    {
        free(wcCommandLineContents);
        CloseHandle(hProcess);
        return -1;
    }

    strcpy(szCommandLine, szBuffer);
    free(wcCommandLineContents);
    CloseHandle(hProcess);
    return 0;
}

BOOL MainWindow::GetProcessList()
{
    NTSTATUS result;

    // Определение требуемого размера буфера.
    DWORD dwReturnLength = 0;
    result = pNtQuerySystemInformation(SystemProcessInformation, NULL,
                                       0, &dwReturnLength);
    if (result != STATUS_INFO_LENGTH_MISMATCH) return FALSE;

    // Получение информации обо всех процессах.
    BYTE *pBuffer = new BYTE [dwReturnLength];
    result = pNtQuerySystemInformation(SystemProcessInformation, pBuffer,
                                       dwReturnLength, &dwReturnLength);
    if (result != STATUS_SUCCESS) { delete [] pBuffer; return FALSE; }

    SYSTEM_PROCESSES_INFO *spi;
    DWORD offset = 0;

    // Очистка содержимого таблицы.
    ui->twProcesses->clearContents();
    ui->twProcesses->setRowCount(0);

    int idx = 0;
    proc_list.clear();
    PROCESS_MEMBER pm;

    do
    {
        spi = (SYSTEM_PROCESSES_INFO*)(pBuffer + offset);

        ui->twProcesses->setRowCount(ui->twProcesses->rowCount() + 1);
        ui->twProcesses->setRowHeight(idx, 22);

        // PID.
        ui->twProcesses->setItem(idx, 0, new 
		QTableWidgetItem(QString::number(spi->UniqueProcessId)));
        pm.PID = spi->UniqueProcessId;

        // Image Name.
        if (spi->UniqueProcessId)
        {
            ANSI_STRING ansi;
            pRtlUnicodeStringToAnsiString(&ansi, &spi->ImageName, TRUE);
            ui->twProcesses->setItem(idx, 1, new 
			QTableWidgetItem(QString::fromLatin1(ansi.Buffer)));
            pm.ImageName = QString::fromLatin1(ansi.Buffer);
            pRtlFreeAnsiString(&ansi);
        }
        else
        {
            ui->twProcesses->setItem(idx, 1, new QTableWidgetItem("idle.exe"));
            pm.ImageName = "idle.exe";
        }

        // CommandLine.
        char szBuffer[1024]; memset(szBuffer, 0, 1024);
        if (GetCommandLineProcess(spi->UniqueProcessId, szBuffer) == 0)
        {
            pm.CommandLine = QString(szBuffer);
        } else pm.CommandLine = "";
        ui->twProcesses->setItem(idx, 2, new QTableWidgetItem(pm.CommandLine));

        proc_list.append(pm);

        offset += spi->NextEntryOffset;
        idx++;
    }
    while(spi->NextEntryOffset != 0);

    ui->twProcesses->selectRow(0);
    ui->twProcesses->setFocus();
    ui->lbPID->setText("0");
    cur_pid = 0;

    delete [] pBuffer;
    return TRUE;
}

// Разность между отсчетами системного времени.
SYSTEMTIME MainWindow::DiffSystemTime(const SYSTEMTIME &st1,
                                      const SYSTEMTIME &st2)
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

// Снятие одного замера (обработчик таймера).
void MainWindow::measStep()
{
    SYSTEM_PROCESSES_INFO spi;
    BYTE                  nCpuUsage;
    DWORD                 dwPID = cur_pid;

    if (!QueryProcInfoEx(dwPID, &spi, &nCpuUsage)) return;
    fprintf(pFile, "%lu %lu %lu %lu %lu %lu %llu %llu %llu %llu %llu %llu %llu %llu %d\n",
            spi.VirtualSize, spi.WorkingSetSize, spi.QuotaPagedPoolUsage,
            spi.QuotaNonPagedPoolUsage, spi.PagefileUsage, spi.PrivatePageCount,
            spi.UserTime.QuadPart, spi.KernelTime.QuadPart, spi.ReadOperationCount,
            spi.WriteOperationCount, spi.OtherOperationCount, spi.ReadTransferCount,
            spi.WriteTransferCount, spi.OtherTransferCount, nCpuUsage);

    cur_time += mon_step;
    ui->progressBar->setValue((double)cur_time * 100 / mon_time);

    sample.append(spi);
    sample_cpu.append(nCpuUsage);

    if (fabs(mon_time - cur_time) < mon_step / 2)
    {
        timMetering->stop();
        ui->twProcesses->setEnabled(true);
        ui->sbMonTime->setEnabled(true);
        ui->sbMonStep->setEnabled(true);
        ui->pbUpdate->setEnabled(true);
        char szBuffer[100];
        GetLocalTime(&st2);
        sprintf(szBuffer, "Stoping at: %02d:%02d:%02d,%d", st2.wHour, st2.wMinute,
                st2.wSecond, st2.wMilliseconds);
        lbT2.setText(szBuffer);
        st_dt = DiffSystemTime(st1, st2);
        sprintf(szBuffer, "Monitoring time: %02d:%02d:%02d,%d", st_dt.wHour, st_dt.wMinute,
                st_dt.wSecond, st_dt.wMilliseconds);
        lbDT.setText(szBuffer);
        DisplayAndAnalysisData();
        fclose(pFile);
    }
}

void MainWindow::on_pbStart_clicked()
{
    sample.clear();
    sample_cpu.clear();
    ui->progressBar->setValue(0);
    mon_time = ui->sbMonTime->value() * 60 * 1000;
    mon_step = ui->sbMonStep->value();
    cur_time = 0;
    ui->twProcesses->setEnabled(false);
    ui->sbMonTime->setEnabled(false);
    ui->sbMonStep->setEnabled(false);
    ui->pbUpdate->setEnabled(false);
    char szBuffer[100];
    sprintf(szBuffer, "%05d_stat.txt", cur_pid);
    pFile = fopen(szBuffer, "w");
    GetLocalTime(&st1);
    sprintf(szBuffer, "Starting at: %02d:%02d:%02d,%d", st1.wHour, st1.wMinute,
            st1.wSecond, st1.wMilliseconds);
    lbT1.setText(szBuffer);
    lbT2.setText("Stoping at: 00:00:00,000");
    lbDT.setText("Monitoring time: 00:00:00,000");
    timMetering->start(mon_step);
}

void MainWindow::on_pbStop_clicked()
{
    char szBuffer[100];
    timMetering->stop();
    ui->progressBar->setValue(100);
    ui->twProcesses->setEnabled(true);
    ui->sbMonTime->setEnabled(true);
    ui->sbMonStep->setEnabled(true);
    ui->pbUpdate->setEnabled(true);
    GetLocalTime(&st2);
    sprintf(szBuffer, "Stoping at: %02d:%02d:%02d,%d", st2.wHour, st2.wMinute,
            st2.wSecond, st2.wMilliseconds);
    lbT2.setText(szBuffer);
    st_dt = DiffSystemTime(st1, st2);
    sprintf(szBuffer, "Monitoring time: %02d:%02d:%02d,%d", st_dt.wHour, st_dt.wMinute,
            st_dt.wSecond, st_dt.wMilliseconds);
    lbDT.setText(szBuffer);
    DisplayAndAnalysisData();
    fclose(pFile);
}

void MainWindow::on_twProcesses_itemSelectionChanged()
{
    int pid = proc_list.at(ui->twProcesses->currentRow()).PID;
    ui->lbPID->setText(QString::number(pid));
    cur_pid = pid;
}

void MainWindow::on_pbUpdate_clicked()
{
    GetProcessList();
    ui->progressBar->setValue(0);
    lbT1.setText("Starting at: 00:00:00,000");
    lbT2.setText("Stoping at: 00:00:00,000");
    lbDT.setText("Monitoring time: 00:00:00,000");
}

// Отображение и анализ данных.
void MainWindow::DisplayAndAnalysisData()
{
    // Реальное время мониторинга.
    double T = st_dt.wMilliseconds + st_dt.wSecond * 1000 +
            st_dt.wMinute * 60 *1000 + st_dt.wHour * 60 * 60 * 1000;
    T /= 1000; // s

    // Память, инициализация.
    minVirtualSize = maxVirtualSize = sample.at(0).VirtualSize / 4096;
    meanVirtualSize = 0;
    minWorkingSetSize = maxWorkingSetSize = sample.at(0).WorkingSetSize / 4096;
    meanWorkingSetSize = 0;
    minPagedPool = maxPagedPool = sample.at(0).QuotaPagedPoolUsage / 1024;
    meanPagedPool = 0;
    minNonPagedPool = maxNonPagedPool = sample.at(0).QuotaNonPagedPoolUsage / 1024;
    meanNonPagedPool = 0;
    minPagefileUsage = maxPagefileUsage = sample.at(0).PagefileUsage / 4096;
    meanPagefileUsage = 0;
    minPrivatePageCount = maxPrivatePageCount = sample.at(0).PrivatePageCount / 4096;
    meanPrivatePageCount = 0;

    // ЦП, инициализация.
    minCpuUsage = maxCpuUsage = sample_cpu.at(0);
    meanCpuUsage = 0;

    int n = sample.count();
    double dt = T / (n - 1), cur_t = 0;
    t.clear();

    // Очистка всех векторов.
    vs.clear(); wss.clear(); ppu.clear(); nppu.clear(); pu.clear(); ppc.clear();
    ut.clear(); kt.clear(); tt.clear(); cpu.clear(); roc.clear(); woc.clear();
    ooc.clear(); rtc.clear(); wtc.clear(); otc.clear();

    // Формирование векторов.
    for (int i = 0; i < n; i++)
    {
        double v;

        /**********************************************************/

        // VirtualSize
        v = sample.at(i).VirtualSize / 4096;
        if (minVirtualSize > v) minVirtualSize = v;
        if (maxVirtualSize < v) maxVirtualSize = v;
        meanVirtualSize += v / n;
        vs.append(v / 1000); // x10^3

        // WorkingSetSize
        v = sample.at(i).WorkingSetSize / 4096;
        if (minWorkingSetSize > v) minWorkingSetSize = v;
        if (maxWorkingSetSize < v) maxWorkingSetSize = v;
        meanWorkingSetSize += v / n;
        wss.append(v / 1000); // x10^3

        // PagedPool
        v = sample.at(i).QuotaPagedPoolUsage / 1024;
        if (minPagedPool > v) minPagedPool = v;
        if (maxPagedPool < v) maxPagedPool = v;
        meanPagedPool += v / n;
        ppu.append(v);

        // NonPagedPool
        v = sample.at(i).QuotaNonPagedPoolUsage / 1024;
        if (minNonPagedPool > v) minNonPagedPool = v;
        if (maxNonPagedPool < v) maxNonPagedPool = v;
        meanNonPagedPool += v / n;
        nppu.append(v);

        // PagefileUsage
        v = sample.at(i).PagefileUsage / 4096;
        if (minPagefileUsage > v) minPagefileUsage = v;
        if (maxPagefileUsage < v) maxPagefileUsage = v;
        meanPagefileUsage += v / n;
        pu.append(v / 1000); // x10^3

        // PrivatePageCount
        v = sample.at(i).PrivatePageCount / 4096;
        if (minPrivatePageCount > v) minPrivatePageCount = v;
        if (maxPrivatePageCount < v) maxPrivatePageCount = v;
        meanPrivatePageCount += v / n;
        ppc.append(v / 1000); // x10^3

        /**********************************************************/

        // UserTime
        v = sample.at(i).UserTime.QuadPart / 10000000;
        ut.append(v); // s

        // KernelTime
        v = sample.at(i).KernelTime.QuadPart / 10000000;
        kt.append(v); // s

        // TotalTime
        v = ut.at(i) + kt.at(i);
        tt.append(v); // s

        // CpuUsage
        v = sample_cpu.at(i);
        if (minCpuUsage > v) minCpuUsage = v;
        if (maxCpuUsage < v) maxCpuUsage = v;
        meanCpuUsage += v / n;
        cpu.append(v); // %

        /**********************************************************/

        // ROC
        v = sample.at(i).ReadOperationCount;
        roc.append(v);

        // WOC
        v = sample.at(i).WriteOperationCount;
        woc.append(v);

        // OOC
        v = sample.at(i).OtherOperationCount;
        ooc.append(v);

        // RTC
        v = sample.at(i).ReadTransferCount;
        rtc.append(v);

        // WTC
        v = sample.at(i).WriteTransferCount;
        wtc.append(v);

        // OTC
        v = sample.at(i).OtherTransferCount;
        otc.append(v);

        // t
        t.append(cur_t);
        cur_t += dt;
    }

    /**********************************************************/

    // UserTime
    begUserTime = sample.at(0).UserTime.QuadPart / 10000000;
    endUserTime = sample.at(sample.count() - 1).UserTime.QuadPart / 10000000;
    dtUserTime  = endUserTime - begUserTime;

    // KernelTime
    begKernelTime = sample.at(0).KernelTime.QuadPart / 10000000;
    endKernelTime = sample.at(sample.count() - 1).KernelTime.QuadPart / 10000000;
    dtKernelTime  = endKernelTime - begKernelTime;

    // TotalTime
    begTotalTime = tt.at(0);
    endTotalTime = tt.at(tt.count() - 1);
    dtTotalTime  = endTotalTime - begTotalTime;

    /**********************************************************/

    // ROC
    begROC = roc.at(0);
    endROC = roc.at(roc.count() - 1);
    dtROC  = endROC - begROC;
    opsROC = dtROC / T;

    // WOC
    begWOC = woc.at(0);
    endWOC = woc.at(roc.count() - 1);
    dtWOC  = endWOC - begWOC;
    opsWOC = dtWOC / T;

    // OOC
    begOOC = ooc.at(0);
    endOOC = ooc.at(roc.count() - 1);
    dtOOC  = endOOC - begOOC;
    opsOOC = dtOOC / T;

    // RTC
    begRTC = rtc.at(0);
    endRTC = rtc.at(roc.count() - 1);
    dtRTC  = endRTC - begRTC;
    bpsRTC = dtRTC / T;

    // WTC
    begWTC = wtc.at(0);
    endWTC = wtc.at(roc.count() - 1);
    dtWTC  = endWTC - begWTC;
    bpsWTC = dtWTC / T;

    // OTC
    begOTC = otc.at(0);
    endOTC = otc.at(roc.count() - 1);
    dtOTC  = endOTC - begOTC;
    bpsOTC = dtOTC / T;

    double l, h, delta;

/***********************************************************************/

    // VirtualSize
    l = minVirtualSize / 1000;
    h = maxVirtualSize / 1000;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartVirtualSize->xAxis->setRange(0, T);
    ui->chartVirtualSize->yAxis->setRange(l, h);

    ui->chartVirtualSize->clearGraphs();
    ui->chartVirtualSize->addGraph();
    ui->chartVirtualSize->graph(0)->setData(t, vs);
    ui->chartVirtualSize->replot();

    // WorkingSetSize
    l = minWorkingSetSize / 1000;
    h = maxWorkingSetSize / 1000;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartWorkingSetSize->xAxis->setRange(0, T);
    ui->chartWorkingSetSize->yAxis->setRange(l, h);

    ui->chartWorkingSetSize->clearGraphs();
    ui->chartWorkingSetSize->addGraph();
    ui->chartWorkingSetSize->graph(0)->setData(t, wss);
    ui->chartWorkingSetSize->replot();

    // PagedPool
    l = minPagedPool;
    h = maxPagedPool;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartPagedPool->xAxis->setRange(0, T);
    ui->chartPagedPool->yAxis->setRange(l, h);

    ui->chartPagedPool->clearGraphs();
    ui->chartPagedPool->addGraph();
    ui->chartPagedPool->graph(0)->setData(t, ppu);
    ui->chartPagedPool->replot();

    // NonPagedPool
    l = minNonPagedPool;
    h = maxNonPagedPool;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartNonPagedPool->xAxis->setRange(0, T);
    ui->chartNonPagedPool->yAxis->setRange(l, h);

    ui->chartNonPagedPool->clearGraphs();
    ui->chartNonPagedPool->addGraph();
    ui->chartNonPagedPool->graph(0)->setData(t, nppu);
    ui->chartNonPagedPool->replot();

    // PagefileUsage
    l = minPagefileUsage / 1000;
    h = maxPagefileUsage / 1000;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartPagefileUsage->xAxis->setRange(0, T);
    ui->chartPagefileUsage->yAxis->setRange(l, h);

    ui->chartPagefileUsage->clearGraphs();
    ui->chartPagefileUsage->addGraph();
    ui->chartPagefileUsage->graph(0)->setData(t, pu);
    ui->chartPagefileUsage->replot();

    // PrivatePageCount
    l = minPrivatePageCount / 1000;
    h = maxPrivatePageCount / 1000;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartPrivatePageCount->xAxis->setRange(0, T);
    ui->chartPrivatePageCount->yAxis->setRange(l, h);

    ui->chartPrivatePageCount->clearGraphs();
    ui->chartPrivatePageCount->addGraph();
    ui->chartPrivatePageCount->graph(0)->setData(t, ppc);
    ui->chartPrivatePageCount->replot();

    // Отображение сводной информации.
    ui->teMemory->clear();
    char szBuffer[256];
    sprintf(szBuffer, "min(VirtualSize)      = %6d pages,  max(VirtualSize)      = %6d pages,  mean(VirtualSize)      = %6d pages",
            (int)round(minVirtualSize), (int)round(maxVirtualSize), (int)round(meanVirtualSize));
    ui->teMemory->append(QString(szBuffer));
    sprintf(szBuffer, "min(WorkingSetSize)   = %6d pages,  max(WorkingSetSize)   = %6d pages,  mean(WorkingSetSize)   = %6d pages",
            (int)round(minWorkingSetSize), (int)round(maxWorkingSetSize), (int)round(meanWorkingSetSize));
    ui->teMemory->append(QString(szBuffer));
    sprintf(szBuffer, "min(PagedPool)        = %6d KiB,    max(PagedPool)        = %6d KiB,    mean(PagedPool)        = %6d KiB",
            (int)round(minPagedPool), (int)round(maxPagedPool), (int)round(meanPagedPool));
    ui->teMemory->append(QString(szBuffer));
    sprintf(szBuffer, "min(NonPagedPool)     = %6d KiB,    max(NonPagedPool)     = %6d KiB,    mean(NonPagedPool)     = %6d KiB",
            (int)round(minNonPagedPool), (int)round(maxNonPagedPool), (int)round(meanNonPagedPool));
    ui->teMemory->append(QString(szBuffer));
    sprintf(szBuffer, "min(PagefileUsage)    = %6d pages,  max(PagefileUsage)    = %6d pages,  mean(PagefileUsage)    = %6d pages",
            (int)round(minPagefileUsage), (int)round(maxPagefileUsage), (int)round(meanPagefileUsage));
    ui->teMemory->append(QString(szBuffer));
    sprintf(szBuffer, "min(PrivatePageCount) = %6d pages,  max(PrivatePageCount) = %6d pages,  mean(PrivatePageCount) = %6d pages",
            (int)round(minPrivatePageCount), (int)round(maxPrivatePageCount), (int)round(meanPrivatePageCount));
    ui->teMemory->append(QString(szBuffer));

    // Метка-заголовок на вкладке "Память".
    int pid = proc_list.at(ui->twProcesses->currentRow()).PID;
    sprintf(szBuffer, "Memory usage by process %s (PID %d)",
            proc_list.at(ui->twProcesses->currentRow()).ImageName.toLatin1().data(), pid);
    ui->lbMemUsage->setText(szBuffer);

/***********************************************************************/

    // UserTime
    l = begUserTime;
    h = endUserTime;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartUserTime->xAxis->setRange(0, T);
    ui->chartUserTime->yAxis->setRange(l, h);

    ui->chartUserTime->clearGraphs();
    ui->chartUserTime->addGraph();
    ui->chartUserTime->graph(0)->setData(t, ut);
    ui->chartUserTime->replot();

    // KernelTime
    l = begKernelTime;
    h = endKernelTime;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartKernelTime->xAxis->setRange(0, T);
    ui->chartKernelTime->yAxis->setRange(l, h);

    ui->chartKernelTime->clearGraphs();
    ui->chartKernelTime->addGraph();
    ui->chartKernelTime->graph(0)->setData(t, kt);
    ui->chartKernelTime->replot();

    // TotalTime
    l = begTotalTime;
    h = endTotalTime;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartTotalTime->xAxis->setRange(0, T);
    ui->chartTotalTime->yAxis->setRange(l, h);

    ui->chartTotalTime->clearGraphs();
    ui->chartTotalTime->addGraph();
    ui->chartTotalTime->graph(0)->setData(t, tt);
    ui->chartTotalTime->replot();

    // CpuUsage
    ui->chartCpuUsage->xAxis->setRange(0, T);
    ui->chartCpuUsage->yAxis->setRange(0, 100);

    ui->chartCpuUsage->clearGraphs();
    ui->chartCpuUsage->addGraph();
    ui->chartCpuUsage->graph(0)->setData(t, cpu);
    ui->chartCpuUsage->replot();

    // Отображение сводной информации.
    ui->teCPU->clear();
    sprintf(szBuffer, "beg(UserTime)    = %9.3f s,  end(UserTime)    = %9.3f s,  diff(UserTime)    = %9.3f s",
            begUserTime, endUserTime, dtUserTime);
    ui->teCPU->append(QString(szBuffer));
    sprintf(szBuffer, "beg(KernelTime)  = %9.3f s,  end(KernelTime)  = %9.3f s,  diff(KernelTime)  = %9.3f s",
            begKernelTime, endKernelTime, dtKernelTime);
    ui->teCPU->append(QString(szBuffer));
    sprintf(szBuffer, "beg(TotalTime)   = %9.3f s,  end(TotalTime)   = %9.3f s,  diff(TotalTime)   = %9.3f s",
            begTotalTime, endTotalTime, dtTotalTime);
    ui->teCPU->append(QString(szBuffer));
    sprintf(szBuffer, "min(CpuUsage)    = %9d %%,  max(CpuUsage)    = %9d %%,  mean(CpuUsage)    = %9d %%",
            (int)round(minCpuUsage), (int)round(maxCpuUsage), (int)round(meanCpuUsage));
    ui->teCPU->append(QString(szBuffer));

    // Метка-заголовок на вкладке "ЦП".
    sprintf(szBuffer, "CPU usage by process %s (PID %d)",
            proc_list.at(ui->twProcesses->currentRow()).ImageName.toLatin1().data(), pid);
    ui->lbCpuUsage->setText(szBuffer);

/***********************************************************************/

    // ROC
    l = begROC;
    h = endROC;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartROC->xAxis->setRange(0, T);
    ui->chartROC->yAxis->setRange(l, h);

    ui->chartROC->clearGraphs();
    ui->chartROC->addGraph();
    ui->chartROC->graph(0)->setData(t, roc);
    ui->chartROC->replot();

    // WOC
    l = begWOC;
    h = endWOC;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartWOC->xAxis->setRange(0, T);
    ui->chartWOC->yAxis->setRange(l, h);

    ui->chartWOC->clearGraphs();
    ui->chartWOC->addGraph();
    ui->chartWOC->graph(0)->setData(t, woc);
    ui->chartWOC->replot();

    // OOC
    l = begOOC;
    h = endOOC;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartOOC->xAxis->setRange(0, T);
    ui->chartOOC->yAxis->setRange(l, h);

    ui->chartOOC->clearGraphs();
    ui->chartOOC->addGraph();
    ui->chartOOC->graph(0)->setData(t, ooc);
    ui->chartOOC->replot();

    // RTC
    l = begRTC;
    h = endRTC;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartRTC->xAxis->setRange(0, T);
    ui->chartRTC->yAxis->setRange(l, h);

    ui->chartRTC->clearGraphs();
    ui->chartRTC->addGraph();
    ui->chartRTC->graph(0)->setData(t, rtc);
    ui->chartRTC->replot();

    // WTC
    l = begWTC;
    h = endWTC;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartWTC->xAxis->setRange(0, T);
    ui->chartWTC->yAxis->setRange(l, h);

    ui->chartWTC->clearGraphs();
    ui->chartWTC->addGraph();
    ui->chartWTC->graph(0)->setData(t, wtc);
    ui->chartWTC->replot();

    // OTC
    l = begOTC;
    h = endOTC;
    delta = h - l;
    if (delta != 0)
    {
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    else
    {
        delta = h * 0.1;
        l = l - delta * 0.1 < 0 ? 0 : l - delta * 0.1;
        h = h + delta * 0.1;
    }
    ui->chartOTC->xAxis->setRange(0, T);
    ui->chartOTC->yAxis->setRange(l, h);

    ui->chartOTC->clearGraphs();
    ui->chartOTC->addGraph();
    ui->chartOTC->graph(0)->setData(t, otc);
    ui->chartOTC->replot();

    // Отображение сводной информации.
    ui->teIO->clear();

    sprintf(szBuffer, "beg(ROC)  = %10d,        end(ROC)  = %10d,        diff(ROC)  = %10d,        Operation Per Second  = %10d",
            (int)begROC, (int)endROC, (int)dtROC, (int)opsROC);
    ui->teIO->append(QString(szBuffer));
    sprintf(szBuffer, "beg(WOC)  = %10d,        end(WOC)  = %10d,        diff(WOC)  = %10d,        Operation Per Second  = %10d",
            (int)begWOC, (int)endWOC, (int)dtWOC, (int)opsWOC);
    ui->teIO->append(QString(szBuffer));
    sprintf(szBuffer, "beg(OOC)  = %10d,        end(OOC)  = %10d,        diff(OOC)  = %10d,        Operation Per Second  = %10d",
            (int)begOOC, (int)endOOC, (int)dtOOC, (int)opsOOC);
    ui->teIO->append(QString(szBuffer));

    sprintf(szBuffer, "beg(RTC)  = %10u bytes,  end(RTC)  = %10u bytes,  diff(RTC)  = %10u bytes,  Bytes Per Second      = %10u",
            (unsigned int)begRTC, (unsigned int)endRTC, (unsigned int)dtRTC, (unsigned int)bpsRTC);
    ui->teIO->append(QString(szBuffer));
    sprintf(szBuffer, "beg(WTC)  = %10u bytes,  end(WTC)  = %10u bytes,  diff(WTC)  = %10u bytes,  Bytes Per Second      = %10u",
            (unsigned int)begWTC, (unsigned int)endWTC, (unsigned int)dtWTC, (unsigned int)bpsWTC);
    ui->teIO->append(QString(szBuffer));
    sprintf(szBuffer, "beg(OTC)  = %10u bytes,  end(OTC)  = %10u bytes,  diff(OTC)  = %10u bytes,  Bytes Per Second      = %10u",
            (unsigned int)begOTC, (unsigned int)endOTC, (unsigned int)dtOTC, (unsigned int)bpsOTC);
    ui->teIO->append(QString(szBuffer));

    // Метка-заголовок на вкладке "Ввод-вывод".
    sprintf(szBuffer, "IO operations process %s (PID %d)",
            proc_list.at(ui->twProcesses->currentRow()).ImageName.toLatin1().data(), pid);
    ui->lbIO->setText(szBuffer);
}
