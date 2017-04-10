#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QDebug>
#include <QVBoxLayout>
#include <QTableWidgetItem>
#include <QList>
#include <QTime>
#include <QLabel>

#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <string.h>
#include <time.h>
#include <winternl.h>

typedef struct _SYSTEM_PROCESSES_INFO
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
} SYSTEM_PROCESSES_INFO, *PSYSTEM_PROCESSES_INFO;

typedef struct _PROCESS_MEMBER
{
    DWORD   PID;
    QString ImageName;
    QString CommandLine;
} PROCESS_MEMBER, *PPROCESS_MEMBER;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    // Получение информации о процессе по его PID.
    BOOL QueryProcInfo(DWORD dwPID, PSYSTEM_PROCESSES_INFO pProcInfo);
    // Получение информации о процессе по его PID (+ загрузка ЦП).
    BOOL QueryProcInfoEx(DWORD dwPID, PSYSTEM_PROCESSES_INFO pProcInfo, BYTE *pCpuUsage);
    // Назначение привилегии текущему процессу.
    DWORD SetPrivilege(LPCTSTR Privilege);
    // Определение командной строки процесса по его PID.
    DWORD GetCommandLineProcess(DWORD dwPID, char *szCommandLine);
    // Разность между отсчетами системного времени.
    SYSTEMTIME DiffSystemTime(const SYSTEMTIME &st1, const SYSTEMTIME &st2);
    // Получение списка запущенных процессов.
    BOOL GetProcessList();
    // Отображение и анализ данных.
    void DisplayAndAnalysisData();

private slots:
    void on_pbStart_clicked();                  // Начало мониторинга.
    void on_pbStop_clicked();                   // Окончание мониторинга.
    void on_twProcesses_itemSelectionChanged(); // Выбор процесса.
    void on_pbUpdate_clicked();                 // Обновление списка процессов.
    void measStep();                            // Обработчик таймера.

private:
    Ui::MainWindow *ui;

    HMODULE                       hNtdll;
    QTimer                       *timMetering;
    QList<PROCESS_MEMBER>         proc_list;
    int                           cur_pid;
    QList<SYSTEM_PROCESSES_INFO>  sample;
    QList<int>                    sample_cpu;
    int                           mon_time;
    int                           mon_step;
    int                           cur_time;
    FILE                         *pFile;
    SYSTEMTIME                    st1, st2, st_dt;
    QLabel                        lbT1, lbT2, lbDT;

    double minVirtualSize, maxVirtualSize, meanVirtualSize;
    double minWorkingSetSize, maxWorkingSetSize, meanWorkingSetSize;
    double minPagedPool, maxPagedPool, meanPagedPool;
    double minNonPagedPool, maxNonPagedPool, meanNonPagedPool;
    double minPagefileUsage, maxPagefileUsage, meanPagefileUsage;
    double minPrivatePageCount, maxPrivatePageCount, meanPrivatePageCount;

    double begUserTime, endUserTime, dtUserTime;
    double begKernelTime, endKernelTime, dtKernelTime;
    double begTotalTime, endTotalTime, dtTotalTime;
    double minCpuUsage, maxCpuUsage, meanCpuUsage;

    double begROC, endROC, dtROC, opsROC;
    double begWOC, endWOC, dtWOC, opsWOC;
    double begOOC, endOOC, dtOOC, opsOOC;
    double begRTC, endRTC, dtRTC, bpsRTC;
    double begWTC, endWTC, dtWTC, bpsWTC;
    double begOTC, endOTC, dtOTC, bpsOTC;

    QVector<double> t;
    QVector<double> vs, wss, ppu, nppu, pu, ppc, ut, kt, tt, cpu,
    roc, woc, ooc, rtc, wtc, otc;
};

#endif // MAINWINDOW_H
