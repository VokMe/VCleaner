#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Psapi.lib")
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>
#include <cstdlib>
#include <shellapi.h>
#include <shlobj.h>
#include <tchar.h>
#include <direct.h>
#include <Psapi.h>

using namespace std;

class VCleaner {
private:
    HANDLE hConsole;
    unsigned long long totalFreed = 0;
    vector<string> tempPaths = {
        "C:\\Windows\\Temp",
        "C:\\Windows\\Prefetch",
        "%temp%",
        "%tmp%"
    };

    vector<string> browserPaths = {
        "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache",
        "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache",
        "\\AppData\\Local\\Mozilla\\Firefox\\Profiles"
    };

    vector<string> additionalPaths = {
        "C:\\Windows\\SoftwareDistribution\\Download",  // Windows Update cache
        "C:\\Windows\\Downloaded Program Files",        // ActiveX and Java cache
        "C:\\ProgramData\\Microsoft\\Windows\\WER",     // Windows Error Reports
        "%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer", // Windows thumbnail cache
        "%LOCALAPPDATA%\\Microsoft\\Windows\\INetCache" // Internet Explorer cache
    };

    string expandEnvStrings(const string& path) {
        char expanded[MAX_PATH];
        ExpandEnvironmentStringsA(path.c_str(), expanded, MAX_PATH);
        return string(expanded);
    }

    unsigned long long deleteFiles(const string& path) {
        unsigned long long freedSpace = 0;
        WIN32_FIND_DATAW ffd;
        wstring searchPath = wstring(path.begin(), path.end()) + L"\\*";
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0) {
                    wstring fullPath = wstring(path.begin(), path.end()) + L"\\" + ffd.cFileName;
                    if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        freedSpace += deleteFiles(string(fullPath.begin(), fullPath.end()));
                        RemoveDirectoryW(fullPath.c_str());
                    }
                    else {
                        LARGE_INTEGER fileSize;
                        fileSize.LowPart = ffd.nFileSizeLow;
                        fileSize.HighPart = ffd.nFileSizeHigh;
                        freedSpace += fileSize.QuadPart;
                        DeleteFileW(fullPath.c_str());
                    }
                }
            } while (FindNextFileW(hFind, &ffd) != 0);
            FindClose(hFind);
        }
        return freedSpace;
    }

public:
    VCleaner() {
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    }

    void setColor(int color) {
        SetConsoleTextAttribute(hConsole, color);
    }

    void cleanTempFiles() {
        setColor(11);
        cout << "\nCleaning temporary files..." << endl;
        setColor(7);
        for (const auto& path : tempPaths) {
            string expandedPath = expandEnvStrings(path);
            cout << "Cleaning: ";
            setColor(14);
            cout << expandedPath << endl;
            setColor(7);
            totalFreed += deleteFiles(expandedPath);
        }
    }

    void cleanBrowserCache() {
        cout << "\nCleaning browser cache..." << endl;
        string userProfile = expandEnvStrings("%USERPROFILE%");

        for (const auto& browserPath : browserPaths) {
            string fullPath = userProfile + browserPath;
            cout << "Cleaning: " << fullPath << endl;
            totalFreed += deleteFiles(fullPath);
        }
    }

    void emptyRecycleBin() {
        cout << "\nEmptying Recycle Bin..." << endl;
        SHEmptyRecycleBinA(NULL, NULL, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
    }

    void cleanDownloads() {
        cout << "\nCleaning old files from Downloads..." << endl;
        string downloadsPath = expandEnvStrings("%USERPROFILE%\\Downloads");
        totalFreed += deleteFiles(downloadsPath);
    }

    void showResults() {
        setColor(10);
        cout << "\n=== VCleaner Results ===" << endl;
        cout << "Space freed: " << (totalFreed / 1024.0 / 1024.0) << " MB" << endl;
        setColor(7);
    }

    void runDiskCleanup() {
        cout << "\nLaunching Windows Disk Cleanup utility..." << endl;
        system("cleanmgr /sagerun:1");
    }

    void disableWindowsDefender() {
        setColor(12);
        cout << "\nWarning: Disabling Windows Defender - This operation is irreversible!" << endl;
        setColor(7);
        cout << "Attempting to disable Windows Defender..." << endl;
        system("powershell -Command \"Start-Process powershell -Verb RunAs -ArgumentList \\\"-Command Set-MpPreference -DisableRealtimeMonitoring $true; "
            "Set-MpPreference -DisableIOAVProtection $true; "
            "New-ItemProperty -Path \\\"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\\" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force; "
            "Remove-Service -Name WinDefend -Force\\\"\"");

        setColor(14);
        cout << "Windows Defender disable attempt completed." << endl;
        setColor(7);
    }

    void cleanWindowsUpdateCache() {
        setColor(11);
        cout << "\nCleaning Windows Update Cache..." << endl;
        setColor(7);
        system("net stop wuauserv");
        string updatePath = "C:\\Windows\\SoftwareDistribution";
        totalFreed += deleteFiles(updatePath);
        system("net start wuauserv");
    }

    void cleanSystemRestorePoints() {
        setColor(11);
        cout << "\nCleaning old System Restore points..." << endl;
        setColor(7);

        system("vssadmin delete shadows /all /quiet");
    }

    void optimizeServices() {
        setColor(11);
        cout << "\nOptimizing Windows Services..." << endl;
        setColor(7);
        vector<string> srvcDi = {
            "DiagTrack",          // Connected User Experiences and Telemetry
            "dmwappushservice",   // WAP Push Message Routing Service
            "SysMain",           // Superfetch
            "WSearch"            // Windows Search
        };

        for (const auto& service : srvcDi) {
            string cmd = "sc stop " + service + " & sc config " + service + " start=disabled";
            system(cmd.c_str());
            cout << "Disabled service: " << service << endl;
        }
    }

    void cleanAdditionalFiles() {
        setColor(11);
        cout << "\nCleaning additional system files..." << endl;
        setColor(7);

        for (const auto& path : additionalPaths) {
            string expandedPath = expandEnvStrings(path);
            cout << "Cleaning: ";
            setColor(14);
            cout << expandedPath << endl;
            setColor(7);
            totalFreed += deleteFiles(expandedPath);
        }
    }

    void optimizeRegistry() {
        setColor(11);
        cout << "\nOptimizing Registry..." << endl;
        setColor(7);
        string backupCmd = "reg export HKLM C:\\Windows\\Temp\\registry_backup.reg /y";
        system(backupCmd.c_str());
        vector<string> regCommands = {
            "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /va /f",
            "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\" /va /f",
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\*\" /va /f"
        };

        for (const auto& cmd : regCommands) {
            system(cmd.c_str());
        }
    }

    void clearEventLogs() {
        setColor(11);
        cout << "\nClearing Windows Event Logs..." << endl;
        setColor(7);

        vector<string> eventLogs = {
            "System", "Application", "Security", "Setup"
        };

        for (const auto& log : eventLogs) {
            string cmd = "wevtutil cl " + log;
            system(cmd.c_str());
            cout << "Cleared " << log << " log" << endl;
        }
    }

    void optimizeNetwork() {
        setColor(11);
        cout << "\nOptimizing network settings..." << endl;
        setColor(7);
        system("netsh int ip reset");
        system("netsh winsock reset");
        system("ipconfig /flushdns");
        vector<string> netCommands = {
            "netsh int tcp set global autotuninglevel=normal",
            "netsh int tcp set global chimney=enabled",
            "netsh int tcp set global dca=enabled",
            "netsh int tcp set global netdma=enabled"
        };

        for (const auto& cmd : netCommands) {
            system(cmd.c_str());
        }
    }

    void defragmentDrives() {
        setColor(11);
        cout << "\nStarting drive defragmentation..." << endl;
        setColor(7);
        char drives[MAX_PATH];
        if (GetLogicalDriveStringsA(MAX_PATH, drives)) {
            char* drive = drives;
            while (*drive) {
                if (GetDriveTypeA(drive) == DRIVE_FIXED) {
                    string driveLetter(1, drive[0]);
                    cout << "Defragmenting drive " << driveLetter << ":" << endl;
                    string cmd = "defrag " + driveLetter + ": /U /V";
                    system(cmd.c_str());
                }
                drive += strlen(drive) + 1;
            }
        }
    }

    void optimizeStartup() {
        setColor(11);
        cout << "\nOptimizing startup programs..." << endl;
        setColor(7);
        vector<string> regCommands = {
            "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /va /f",
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /va /f",
            "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\" /va /f",
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\" /va /f"
        };

        for (const auto& cmd : regCommands) {
            system(cmd.c_str());
        }
    }

    void cleanPowerConfig() {
        setColor(11);
        cout << "\nOptimizing power settings..." << endl;
        setColor(7);
        system("powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
        system("powercfg -h off");
        system("powercfg -change -monitor-timeout-ac 0");
        system("powercfg -change -standby-timeout-ac 0");
    }

    void disableVisualEffects() {
        setColor(11);
        cout << "\nDisabling unnecessary visual effects..." << endl;
        setColor(7);
        vector<string> regCommands = {
            "reg add \"HKCU\\Control Panel\\Desktop\\WindowMetrics\" /v MinAnimate /t REG_SZ /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v TaskbarAnimations /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\" /v EnableTransparency /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\" /v VisualFXSetting /t REG_DWORD /d 2 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\\AnimateMinMax\" /v DefaultApplied /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\\ComboBoxAnimation\" /v DefaultApplied /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\\ControlAnimations\" /v DefaultApplied /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\\MenuAnimation\" /v DefaultApplied /t REG_DWORD /d 0 /f",
            "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects\\TaskbarAnimation\" /v DefaultApplied /t REG_DWORD /d 0 /f"
        };

        for (const auto& cmd : regCommands) {
            system(cmd.c_str());
        }
    }

    void optimizePageFile() {
        setColor(11);
        cout << "\nOptimizing virtual memory settings..." << endl;
        setColor(7);
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        DWORDLONG totalPhysMem = memInfo.ullTotalPhys;

        // Calculate optimal page file size (1.5x RAM for low-end systems)
        DWORDLONG pageFileSize = (totalPhysMem * 1.5) / 1024 / 1024; // Convert to MB

        string cmd = "wmic computersystem where name=\"%computername%\" set AutomaticManagedPagefile=False";
        system(cmd.c_str());

        cmd = "wmic pagefileset where name=\"C:\\\\pagefile.sys\" set InitialSize=" + to_string((DWORD)pageFileSize) +
            ",MaximumSize=" + to_string((DWORD)pageFileSize);
        system(cmd.c_str());
    }

    void disableBackgroundServices() {
        setColor(11);
        cout << "\nDisabling unnecessary background services..." << endl;
        setColor(7);

        vector<string> srvcDisable = {
            "TapiSrv",           // Telephony
            "Browser",           // Computer Browser
            "WerSvc",           // Windows Error Reporting
            "WSearch",          // Windows Search
            "SysMain",          // Superfetch
            "MapsBroker",       // Downloaded Maps Manager
            "lfsvc",            // Geolocation Service
            "DiagTrack",        // Connected User Experiences and Telemetry
            "DPS",              // Diagnostic Policy Service
            "RemoteRegistry",   // Remote Registry
            "ShellHWDetection", // Shell Hardware Detection
            "PcaSvc",           // Program Compatibility Assistant
            "WMPNetworkSvc",    // Windows Media Player Network Sharing
            "WbioSrvc",         // Windows Biometric Service
            "FontCache"         // Windows Font Cache Service
        };

        for (const auto& service : srvcDisable) {
            string cmd = "sc stop " + service + " & sc config " + service + " start=disabled";
            system(cmd.c_str());
            cout << "Disabled service: " << service << endl;
        }
    }

    void optimizeCPU() {
        setColor(11);
        cout << "\nOptimizing CPU settings..." << endl;
        setColor(7);

        system("powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
        system("powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100");
        system("powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100");
        system("powercfg -setactive scheme_current");
    }

    void cleanSystemWorkingSet() {
        setColor(11);
        cout << "\nCleaning system working set memory..." << endl;
        setColor(7);

        HANDLE hProcess = GetCurrentProcess();
        SetProcessWorkingSetSize(hProcess, -1, -1);
        EmptyWorkingSet(hProcess);
    }

    void disableWindowsSearch() {
        setColor(11);
        cout << "\nDisabling Windows Search Indexing..." << endl;
        setColor(7);

        system("sc stop \"WSearch\" && sc config \"WSearch\" start=disabled");
        system("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\" /v AllowCortana /t REG_DWORD /d 0 /f");
    }

    void optimizeGameMode() {
        setColor(11);
        cout << "\nOptimizing Windows Game Mode..." << endl;
        setColor(7);

        vector<string> gameOptimizations = {
            "reg add \"HKCU\\Software\\Microsoft\\GameBar\" /v AllowAutoGameMode /t REG_DWORD /d 1 /f",
            "reg add \"HKCU\\Software\\Microsoft\\GameBar\" /v AutoGameModeEnabled /t REG_DWORD /d 1 /f",
            "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\" /v AllowGameDVR /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\" /v SystemResponsiveness /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"GPU Priority\" /t REG_DWORD /d 8 /f",
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games\" /v \"Priority\" /t REG_DWORD /d 6 /f"
        };

        for (const auto& cmd : gameOptimizations) {
            system(cmd.c_str());
        }
    }

    void disableSuperfetch() {
        setColor(11);
        cout << "\nDisabling Superfetch/SysMain..." << endl;
        setColor(7);

        system("sc stop \"SysMain\" && sc config \"SysMain\" start=disabled");
        system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v EnableSuperfetch /t REG_DWORD /d 0 /f");
    }

    void optimizeMemoryUsage() {
        setColor(11);
        cout << "\nOptimizing memory usage..." << endl;
        setColor(7);

        vector<string> memoryOptimizations = {
            "powershell -Command \"Disable-MMAgent -mc\"",
            "powershell -Command \"Disable-MMAgent -pc\"",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v LargeSystemCache /t REG_DWORD /d 0 /f",
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v DisablePagingExecutive /t REG_DWORD /d 1 /f"
        };

        for (const auto& cmd : memoryOptimizations) {
            system(cmd.c_str());
        }
    }
};

int main() {
    SetConsoleOutputCP(CP_UTF8);
    VCleaner cleaner;

    cleaner.setColor(11);
    cout << "=== VCleaner ===" << endl;
    cleaner.setColor(7);

    if (!IsUserAnAdmin()) {
        cleaner.setColor(12);
        cout << "Administrator rights required!" << endl;
        cout << "Please run the program as administrator." << endl;
        cleaner.setColor(7);
        system("pause");
        return 1;
    }

    string input;
    while (true) {
        cleaner.setColor(11);
        cout << "\nSelect operations (enter numbers separated by spaces):" << endl;
        cleaner.setColor(7);
        cout << "1. Clean temporary files" << endl;
        cout << "2. Clean browser cache" << endl;
        cout << "3. Empty Recycle Bin" << endl;
        cout << "4. Clean Downloads folder" << endl;
        cout << "5. Run Windows Disk Cleanup" << endl;
        cleaner.setColor(12);
        cout << "6. Disable Windows Defender (Irreversible!)" << endl;
        cleaner.setColor(7);
        cout << "7. Clean Windows Update Cache" << endl;
        cout << "8. Clean System Restore Points" << endl;
        cout << "9. Optimize Windows Services" << endl;
        cout << "10. Clean Additional System Files" << endl;
        cout << "11. Optimize Registry" << endl;
        cout << "12. Clear Event Logs" << endl;
        cout << "13. Optimize Network Settings" << endl;
        cout << "14. Defragment Drives" << endl;
        cout << "15. Optimize Startup Programs" << endl;
        cout << "16. Optimize Power Settings" << endl;
        cout << "17. Disable Visual Effects" << endl;
        cout << "18. Optimize Virtual Memory" << endl;
        cout << "19. Disable Background Services" << endl;
        cout << "20. Optimize CPU Settings" << endl;
        cout << "21. Clean System Working Set" << endl;
        cout << "22. Disable Windows Search" << endl;
        cout << "23. Optimize Game Mode" << endl;
        cout << "24. Disable Superfetch" << endl;
        cout << "25. Optimize Memory Usage" << endl;
        cleaner.setColor(10);
        cout << "26. Perform all operations" << endl;
        cleaner.setColor(14);
        cout << "Your choices (e.g., 1 3 4): ";
        cleaner.setColor(7);

        getline(cin, input);

        if (input.find("26") != string::npos) {
            cleaner.cleanTempFiles();
            cleaner.cleanBrowserCache();
            cleaner.emptyRecycleBin();
            cleaner.cleanDownloads();
            cleaner.runDiskCleanup();
            cleaner.cleanWindowsUpdateCache();
            cleaner.cleanSystemRestorePoints();
            cleaner.optimizeServices();
            cleaner.cleanAdditionalFiles();
            cleaner.optimizeRegistry();
            cleaner.clearEventLogs();
            cleaner.optimizeNetwork();
            cleaner.defragmentDrives();
            cleaner.optimizeStartup();
            cleaner.cleanPowerConfig();
            cleaner.disableVisualEffects();
            cleaner.optimizePageFile();
            cleaner.disableBackgroundServices();
            cleaner.optimizeCPU();
            cleaner.cleanSystemWorkingSet();
            cleaner.disableWindowsSearch();
            cleaner.optimizeGameMode();
            cleaner.disableSuperfetch();
            cleaner.optimizeMemoryUsage();
            cleaner.showResults();
        }
        else {
            if (input.find('1') != string::npos) cleaner.cleanTempFiles();
            if (input.find('2') != string::npos) cleaner.cleanBrowserCache();
            if (input.find('3') != string::npos) cleaner.emptyRecycleBin();
            if (input.find('4') != string::npos) cleaner.cleanDownloads();
            if (input.find('5') != string::npos) cleaner.runDiskCleanup();
            if (input.find('6') != string::npos) cleaner.disableWindowsDefender();
            if (input.find('7') != string::npos) cleaner.cleanWindowsUpdateCache();
            if (input.find('8') != string::npos) cleaner.cleanSystemRestorePoints();
            if (input.find('9') != string::npos) cleaner.optimizeServices();
            if (input.find("10") != string::npos) cleaner.cleanAdditionalFiles();
            if (input.find("11") != string::npos) cleaner.optimizeRegistry();
            if (input.find("12") != string::npos) cleaner.clearEventLogs();
            if (input.find("13") != string::npos) cleaner.optimizeNetwork();
            if (input.find("14") != string::npos) cleaner.defragmentDrives();
            if (input.find("15") != string::npos) cleaner.optimizeStartup();
            if (input.find("16") != string::npos) cleaner.cleanPowerConfig();
            if (input.find("17") != string::npos) cleaner.disableVisualEffects();
            if (input.find("18") != string::npos) cleaner.optimizePageFile();
            if (input.find("19") != string::npos) cleaner.disableBackgroundServices();
            if (input.find("20") != string::npos) cleaner.optimizeCPU();
            if (input.find("21") != string::npos) cleaner.cleanSystemWorkingSet();
            if (input.find("22") != string::npos) cleaner.disableWindowsSearch();
            if (input.find("23") != string::npos) cleaner.optimizeGameMode();
            if (input.find("24") != string::npos) cleaner.disableSuperfetch();
            if (input.find("25") != string::npos) cleaner.optimizeMemoryUsage();
            cleaner.showResults();
        }
    }

    return 0;
}
