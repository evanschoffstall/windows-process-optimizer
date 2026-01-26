#Requires AutoHotkey v2.0
#SingleInstance Force

; =============================================================================
; CONFIGURATION
; =============================================================================

; Global settings object containing all configuration options
global CONFIG := {
    ; Operating Mode
    mode: "whitelist",                      ; "blacklist" = only throttle listed targets, "whitelist" = throttle all except listed
    ; Skip Conditions
    skipWindowsApps: true,                 ; Skip UWP/Microsoft Store apps
    skipForegroundProcess: true,            ; Don't throttle the currently active window's process
    skipForegroundProcessTree: true,        ; Don't throttle parent/child processes of foreground app
    skipExceptionProcessTree: true,         ; Don't throttle parent/child processes of exception apps
    ; Default Settings (applied to all processes unless overridden)
    defaults: {
        enabled: true,                      ; Whether to throttle by default
        ; Priority Settings
        useIdlePriority: true,              ; Use idle priority class (slowest) instead of below normal
        useBackgroundMode: true,            ; Enable Windows background mode for better foreground responsiveness
        ; Memory Management
        useMemoryTrimming: true,            ; Enable working set memory trimming
        memoryThresholdMB: 10,              ; Only trim memory if process uses more than this many MB
        useAggressiveMemory: true,          ; Use multiple trim passes for better memory reduction
        memoryTrimPasses: 3,                ; Number of trim passes when aggressive mode is enabled
        ; CPU Management
        useCpuAffinity: true,               ; Restrict processes to specific CPU cores
        cpuAffinityMask: 0x03,              ; Bitmask for CPU cores (0x03 = cores 0 and 1)
        useCpuRateLimit: true,              ; Enable CPU usage rate limiting via job objects
        cpuRateLimitPercent: 5,             ; Maximum CPU usage percent per process
        ; I/O Priority
        useIoPriority: true,                ; Lower I/O priority for disk/network operations
        ; Extreme Throttling (disabled by default - use with caution)
        useSuspendCycles: false,            ; Periodically suspend/resume to severely limit execution
        suspendDurationMs: 100,             ; How long to keep process suspended per cycle
        resumeDurationMs: 50,               ; How long to allow process to run between suspends
        usePagePriority: false,             ; Lower memory page priority (reduces cache priority)
        pagePriority: 1,                    ; Page priority level (1=very low, 5=normal)
        useSingleCore: false,               ; Force process to single CPU core (overrides cpuAffinityMask)
        singleCoreIndex: 0,                 ; Which core to use when useSingleCore is true (0-based)
        useWorkingSetLimit: false,          ; Limit maximum working set size
        workingSetLimitMB: 10,              ; Maximum working set in MB
        useSchedulingClass: false,          ; Set thread scheduling class to lowest
        schedulingClass: 0                  ; Scheduling class (0=lowest, 9=highest)
    },
    ; Target List (for blacklist mode) - processes to throttle
    ; Each entry can be a string (process name) or an object with name/names and custom settings
    ; Use "name" for single process or "names" array for multiple processes with same settings
    targets: [
        "Taskmgr.exe",
        "bdservicehost.exe",
        "downloader.exe",
        "testinitsigs.exe", {
            names: ["svchost.exe", "AdobeColabSync.exe", "WmiPrvSE.exe", "CCleaner_service.exe"],
            enabled: true,
            useIdlePriority: true,
            useBackgroundMode: true,
            useAggressiveMemory: true,
            memoryTrimPasses: 10,
            memoryThresholdMB: 1,
            useCpuAffinity: true,
            useSingleCore: true,
            singleCoreIndex: 0,
            useCpuRateLimit: true,
            cpuRateLimitPercent: 1,
            useIoPriority: true,
            useSuspendCycles: true,
            suspendDurationMs: 2000,
            resumeDurationMs: 20,
            usePagePriority: true,
            pagePriority: 1,
            useWorkingSetLimit: true,
            workingSetLimitMB: 5,
            useSchedulingClass: true,
            schedulingClass: 0
        }
    ],
    ; Exception List (for whitelist mode) - processes to never throttle
    exceptions: [
        "Flow.Launcher.exe",
        "explorer.exe",
        "everything.exe",
        "yasb.exe"
    ]
}

; -----------------------------------------------------------------------------
; GetProcessSettings - Retrieves settings for a specific process
; Merges default settings with any process-specific overrides from targets list
; Parameters:
;   processName - Name of the process to get settings for (optional)
; Returns: Map containing all applicable settings
; -----------------------------------------------------------------------------
GetProcessSettings(processName := "") {
    global CONFIG
    settings := Map()

    ; Start with defaults
    for key, value in CONFIG.defaults.OwnProps()
        settings[key] := value

    ; If process name provided, check for overrides in target list
    if processName {
        for target in CONFIG.targets {
            if (Type(target) = "String") {
                if (StrLower(target) = StrLower(processName))
                    break  ; No overrides for simple string entries
            } else if (Type(target) = "Object") {
                ; Check if process matches this target (supports both "name" and "names")
                isMatch := false
                if target.HasOwnProp("name") && (StrLower(target.name) = StrLower(processName))
                    isMatch := true
                else if target.HasOwnProp("names") {
                    for targetName in target.names {
                        if (StrLower(targetName) = StrLower(processName)) {
                            isMatch := true
                            break
                        }
                    }
                }
                if isMatch {
                    ; Apply overrides
                    for key, value in target.OwnProps() {
                        if (key != "name" && key != "names")
                            settings[key] := value
                    }
                    break
                }
            }
        }
    }

    return settings
}

; =============================================================================
; CONSTANTS & GLOBALS
; =============================================================================

; Process access rights
PROCESS_QUERY_LIMITED_INFORMATION := 0x1000
PROCESS_QUERY_INFORMATION := 0x0400
PROCESS_SET_INFORMATION := 0x0200
PROCESS_SET_QUOTA := 0x0100
PROCESS_VM_READ := 0x0010
PROCESS_SUSPEND_RESUME := 0x0800

; Priority class constants
IDLE_PRIORITY_CLASS := 0x0040
BELOW_NORMAL_PRIORITY_CLASS := 0x4000
PROCESS_MODE_BACKGROUND_BEGIN := 0x00100000
PROCESS_MODE_BACKGROUND_END := 0x00200000

; Structure sizes and offsets
PROCESSENTRY32_SIZE := 304
PROCESS_BASIC_INFO_SIZE := 48
PROCESS_MEMORY_COUNTERS_SIZE := 72
PE32_PID_OFFSET := 8
PE32_PPID_OFFSET_X86 := 20
PE32_PPID_OFFSET_X64 := 28
PBI_PARENT_OFFSET_X86 := 20
PBI_PARENT_OFFSET_X64 := 40

; Timing constants
SCAN_INTERVAL_MS := 15000
CPU_RATE_CHECK_INTERVAL := 100

; Other constants
MAX_PATH_CHARS := 260

; State tracking maps
handled := Map()                ; Processes currently being throttled
suspendCycleTimers := Map()     ; Active suspend cycle timers by PID
cpuRateLimitTimers := Map()     ; Active CPU rate limit timers by PID
cpuUsageTracking := Map()       ; CPU usage tracking data by PID

; Runtime state
currentScriptPID := DllCall("Kernel32\GetCurrentProcessId", "UInt")
currentForegroundPID := 0
foregroundHookHandle := 0
pendingForegroundChange := false

; =============================================================================
; INITIALIZATION
; =============================================================================

; Set up cleanup handler and start monitoring
OnExit(RestoreAllProcesses)
A_IconTip := "Windows Process Optimizer`nInitializing..."
ScanAndApplyAll()
SetupProcessWatcher()
SetupForegroundWatcher()
SetTimer(ScanAndApplyAll, SCAN_INTERVAL_MS)

; =============================================================================
; MAIN SCAN LOGIC
; =============================================================================

; -----------------------------------------------------------------------------
; ScanAndApplyAll - Main scan function that iterates all running processes
; Applies throttling to eligible processes based on configuration
; -----------------------------------------------------------------------------
ScanAndApplyAll() {
    global handled, currentScriptPID, CONFIG
    foregroundPID := CONFIG.skipForegroundProcess ? GetForegroundProcessId() : 0
    foregroundTreePIDs := BuildTreeMap(foregroundPID, CONFIG.skipForegroundProcessTree)
    exceptionTreePIDs := BuildExceptionTreeMap()
    skipCounts := { uwp: 0, exception: 0 }

    snapshot := DllCall("Kernel32\CreateToolhelp32Snapshot", "UInt", 0x2, "UInt", 0, "Ptr")
    if (snapshot = -1)
        return

    try {
        pe32 := Buffer(PROCESSENTRY32_SIZE, 0)
        NumPut("UInt", pe32.Size, pe32, 0)

        if DllCall("Kernel32\Process32First", "Ptr", snapshot, "Ptr", pe32) {
            loop {
                pid := NumGet(pe32, PE32_PID_OFFSET, "UInt")
                if (!ShouldSkipProcess(pid, foregroundPID, foregroundTreePIDs, exceptionTreePIDs, &skipCounts))
                    ProcessBackgroundApp(pid)
                if !DllCall("Kernel32\Process32Next", "Ptr", snapshot, "Ptr", pe32)
                    break
            }
        }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", snapshot)
    }
    UpdateTrayTooltip(skipCounts.uwp, skipCounts.exception)
}

; -----------------------------------------------------------------------------
; BuildTreeMap - Creates a map of PIDs in a process tree
; Parameters:
;   pid     - Root process ID
;   enabled - Whether tree building is enabled
; Returns: Map with PIDs as keys
; -----------------------------------------------------------------------------
BuildTreeMap(pid, enabled) {
    treeMap := Map()
    if (enabled && pid) {
        for _, p in GetProcessTreePIDs(pid)
            treeMap[p] := true
    }
    return treeMap
}

; -----------------------------------------------------------------------------
; BuildExceptionTreeMap - Builds a map of all PIDs related to exception processes
; Includes parent and child processes of any excepted process
; Returns: Map with PIDs as keys
; -----------------------------------------------------------------------------
BuildExceptionTreeMap() {
    global CONFIG
    exceptionTreePIDs := Map()
    if !CONFIG.skipExceptionProcessTree
        return exceptionTreePIDs

    snapshot := DllCall("Kernel32\CreateToolhelp32Snapshot", "UInt", 0x2, "UInt", 0, "Ptr")
    if (snapshot = -1)
        return exceptionTreePIDs

    try {
        pe32 := Buffer(PROCESSENTRY32_SIZE, 0)
        NumPut("UInt", pe32.Size, pe32, 0)
        if DllCall("Kernel32\Process32First", "Ptr", snapshot, "Ptr", pe32) {
            loop {
                pid := NumGet(pe32, PE32_PID_OFFSET, "UInt")
                processName := GetProcessName(pid)
                if processName {
                    for exeName in CONFIG.exceptions {
                        if (StrLower(processName) = StrLower(exeName)) {
                            for _, treePid in GetProcessTreePIDs(pid)
                                exceptionTreePIDs[treePid] := true
                            break
                        }
                    }
                }
                if !DllCall("Kernel32\Process32Next", "Ptr", snapshot, "Ptr", pe32)
                    break
            }
        }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", snapshot)
    }
    return exceptionTreePIDs
}

; -----------------------------------------------------------------------------
; ShouldSkipProcess - Determines if a process should be excluded from throttling
; Parameters:
;   pid                - Process ID to check
;   foregroundPID      - Current foreground process ID
;   foregroundTreePIDs - Map of foreground process tree PIDs
;   exceptionTreePIDs  - Map of exception process tree PIDs
;   skipCounts         - Reference to skip counter object
; Returns: true if process should be skipped, false otherwise
; -----------------------------------------------------------------------------
ShouldSkipProcess(pid, foregroundPID, foregroundTreePIDs, exceptionTreePIDs, &skipCounts) {
    global handled, currentScriptPID, CONFIG

    if (CONFIG.mode = "blacklist") {
        if (!IsTargetApp(pid))
            return true
    } else {
        if (IsException(pid)) {
            skipCounts.exception++
            RestoreIfHandled(pid)
            return true
        }
        if (CONFIG.skipExceptionProcessTree && exceptionTreePIDs.Has(pid)) {
            RestoreIfHandled(pid)
            return true
        }
    }

    if (pid = currentScriptPID)
        return true

    if (CONFIG.skipWindowsApps && IsWindowsApp(pid)) {
        skipCounts.uwp++
        return true
    }

    if (CONFIG.skipForegroundProcess && foregroundPID && pid = foregroundPID) {
        RestoreIfHandled(pid)
        return true
    }

    if (CONFIG.skipForegroundProcessTree && foregroundTreePIDs.Has(pid)) {
        RestoreIfHandled(pid)
        return true
    }

    return false
}

; -----------------------------------------------------------------------------
; RestoreIfHandled - Restores a process to original state if currently throttled
; Parameters:
;   pid - Process ID to restore
; -----------------------------------------------------------------------------
RestoreIfHandled(pid) {
    global handled
    if handled.Has(pid) {
        info := handled[pid]
        RestoreProcess(pid, info.priority, info.HasOwnProp("originalAffinity") ? info.originalAffinity : 0)
        handled.Delete(pid)
    }
}

; -----------------------------------------------------------------------------
; ProcessBackgroundApp - Applies throttling to a background process
; Parameters:
;   pid - Process ID to throttle
; -----------------------------------------------------------------------------
ProcessBackgroundApp(pid) {
    global handled
    if !handled.Has(pid) {
        processName := GetProcessName(pid)
        settings := GetProcessSettings(processName)

        if !settings["enabled"]
            return

        originalPriority := GetProcessPriority(pid)
        result := ApplyEfficiencyLikeMode(pid, settings)
        if (originalPriority && result.success) {
            memTrimmed := settings["useMemoryTrimming"] ? TrimProcessMemory(pid, settings["memoryThresholdMB"],
                settings["useAggressiveMemory"], settings["memoryTrimPasses"]) : false
            handled[pid] := { priority: originalPriority, throttled: true, memoryTrimmed: memTrimmed,
                originalAffinity: result.originalAffinity, processName: processName }
        }
    } else if handled.Has(pid) {
        info := handled[pid]
        settings := GetProcessSettings(info.HasOwnProp("processName") ? info.processName : "")
        if settings["useMemoryTrimming"]
            TrimProcessMemory(pid, settings["memoryThresholdMB"], settings["useAggressiveMemory"], settings[
                "memoryTrimPasses"])
    }
}

; -----------------------------------------------------------------------------
; UpdateTrayTooltip - Updates the system tray icon tooltip with current status
; Parameters:
;   uwpCount       - Number of skipped UWP apps
;   exceptionCount - Number of skipped exception processes
; -----------------------------------------------------------------------------
UpdateTrayTooltip(uwpCount := 0, exceptionCount := 0) {
    global handled, CONFIG
    foregroundPID := GetForegroundProcessId()
    if !foregroundPID {
        A_IconTip := "Windows Process Optimizer`nNo foreground window"
        return
    }
    foregroundName := GetProcessName(foregroundPID)
    if !foregroundName
        foregroundName := "Unknown"
    throttledCount := handled.Count
    treeSize := CONFIG.skipForegroundProcessTree ? GetProcessTreePIDs(foregroundPID).Length : (CONFIG.skipForegroundProcess ?
        1 : 0)
    totalSkipped := uwpCount + treeSize + exceptionCount
    tooltip := "Windows Process Optimizer`nMode: " . (CONFIG.mode = "blacklist" ? "Blacklist (Target Only)" :
        "Whitelist (All Except)")
    if CONFIG.skipForegroundProcess
        tooltip .= "`nForeground: " . foregroundName . " (PID: " . foregroundPID . ")"
    tooltip .= "`nThrottled: " . throttledCount . "`nSkipped: " . totalSkipped
    A_IconTip := tooltip
}

; -----------------------------------------------------------------------------
; SetupProcessWatcher - Sets up WMI event subscription for new process creation
; -----------------------------------------------------------------------------
SetupProcessWatcher() {
    query := "SELECT ProcessId FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    sink := ComObject("WbemScripting.SWbemSink")
    ComObjConnect(sink, "OnProcessCreated_")
    wmi := ComObjGet("winmgmts:\\.\root\CIMV2")
    wmi.ExecNotificationQueryAsync(sink, query)
}

; -----------------------------------------------------------------------------
; SetupForegroundWatcher - Sets up hook for foreground window change events
; -----------------------------------------------------------------------------
SetupForegroundWatcher() {
    global foregroundHookHandle, currentForegroundPID
    callback := CallbackCreate(OnForegroundWindowChanged, "F", 7)
    foregroundHookHandle := DllCall("User32\SetWinEventHook", "UInt", 0x0003, "UInt", 0x0003, "Ptr", 0, "Ptr", callback,
        "UInt", 0, "UInt", 0, "UInt", 0x0002, "Ptr")
    currentForegroundPID := GetForegroundProcessId()
}

; -----------------------------------------------------------------------------
; OnForegroundWindowChanged - Callback for foreground window change events
; Schedules deferred processing to avoid rapid switching overhead
; -----------------------------------------------------------------------------
OnForegroundWindowChanged(hWinEventHook, event, hwnd, idObject, idChild, idEventThread, dwmsEventTime) {
    global currentForegroundPID, CONFIG, pendingForegroundChange
    if !CONFIG.skipForegroundProcess
        return
    newPID := 0
    if hwnd
        DllCall("User32\GetWindowThreadProcessId", "Ptr", hwnd, "UInt*", &newPID)
    if !newPID || newPID = currentForegroundPID
        return
    currentForegroundPID := newPID
    pendingForegroundChange := true
    SetTimer(ProcessForegroundChange, -50)
}

; -----------------------------------------------------------------------------
; ProcessForegroundChange - Handles foreground window change
; Restores new foreground process and throttles previous foreground process
; -----------------------------------------------------------------------------
ProcessForegroundChange() {
    global pendingForegroundChange, currentForegroundPID, handled, CONFIG
    static lastProcessedPID := 0
    if !pendingForegroundChange
        return
    pendingForegroundChange := false
    if (currentForegroundPID = lastProcessedPID)
        return
    newPID := currentForegroundPID
    oldPID := lastProcessedPID
    lastProcessedPID := newPID
    if oldPID && oldPID != newPID
        ApplyToProcessList(CONFIG.skipForegroundProcessTree ? GetProcessTreePIDs(oldPID) : [oldPID])
    if newPID
        RestoreProcessList(CONFIG.skipForegroundProcessTree ? GetProcessTreePIDs(newPID) : [newPID])
    UpdateTrayTooltip()
}

; -----------------------------------------------------------------------------
; ApplyToProcessList - Applies throttling to a list of processes
; Parameters:
;   pidList - Array of process IDs to throttle
; -----------------------------------------------------------------------------
ApplyToProcessList(pidList) {
    global handled, currentScriptPID, CONFIG
    for _, targetPID in pidList {
        if (targetPID = currentScriptPID || (CONFIG.skipWindowsApps && IsWindowsApp(targetPID)))
            continue
        if (CONFIG.mode = "blacklist" && !IsTargetApp(targetPID))
            continue
        if (CONFIG.mode = "whitelist" && IsException(targetPID))
            continue
        if !handled.Has(targetPID) {
            processName := GetProcessName(targetPID)
            settings := GetProcessSettings(processName)

            if !settings["enabled"]
                continue

            originalPriority := GetProcessPriority(targetPID)
            result := ApplyEfficiencyLikeMode(targetPID, settings)
            if (originalPriority && result.success) {
                memTrimmed := settings["useMemoryTrimming"] ? TrimProcessMemory(targetPID, settings["memoryThresholdMB"
                    ],
                    settings["useAggressiveMemory"], settings["memoryTrimPasses"]) : false
                handled[targetPID] := { priority: originalPriority, throttled: true, memoryTrimmed: memTrimmed,
                    originalAffinity: result.originalAffinity, processName: processName }
            }
        }
    }
}

; -----------------------------------------------------------------------------
; RestoreProcessList - Restores a list of processes to original state
; Parameters:
;   pidList - Array of process IDs to restore
; -----------------------------------------------------------------------------
RestoreProcessList(pidList) {
    for _, targetPID in pidList
        RestoreIfHandled(targetPID)
}

; -----------------------------------------------------------------------------
; OnProcessCreated_OnObjectReady - WMI callback for new process creation events
; Applies throttling to newly created processes if eligible
; -----------------------------------------------------------------------------
OnProcessCreated_OnObjectReady(objWbemObject, objWbemAsyncContext) {
    global currentScriptPID, CONFIG, handled
    try {
        pid := objWbemObject.TargetInstance.ProcessId
        if (pid = currentScriptPID || (CONFIG.skipWindowsApps && IsWindowsApp(pid)) || (CONFIG.skipForegroundProcess &&
            pid =
            GetForegroundProcessId()) || handled.Has(pid))
            return
        if (CONFIG.mode = "blacklist" && !IsTargetApp(pid))
            return
        if (CONFIG.mode = "whitelist" && IsException(pid))
            return

        processName := GetProcessName(pid)
        settings := GetProcessSettings(processName)

        if !settings["enabled"]
            return

        originalPriority := GetProcessPriority(pid)
        if !originalPriority
            return

        result := ApplyEfficiencyLikeMode(pid, settings)
        if !result.success {
            Sleep(50)
            result := ApplyEfficiencyLikeMode(pid, settings)
        }
        if result.success {
            memTrimmed := settings["useMemoryTrimming"] ? TrimProcessMemory(pid, settings["memoryThresholdMB"],
                settings["useAggressiveMemory"], settings["memoryTrimPasses"]) : false
            handled[pid] := { priority: originalPriority, throttled: true, memoryTrimmed: memTrimmed,
                originalAffinity: result.originalAffinity, processName: processName }
        }
    }
}

; -----------------------------------------------------------------------------
; IsWindowsApp - Checks if a process is a UWP/Microsoft Store app
; Parameters:
;   pid - Process ID to check
; Returns: true if UWP app, false otherwise
; -----------------------------------------------------------------------------
IsWindowsApp(pid) {
    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt", pid,
        "Ptr")
    if !hProc
        return false
    try {
        packageLength := 0
        result := DllCall("Kernel32\GetPackageFullName", "Ptr", hProc, "UInt*", &packageLength, "Ptr", 0, "Int")
        return (result = 122)
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

; -----------------------------------------------------------------------------
; GetProcessName - Retrieves the executable name for a process
; Parameters:
;   pid - Process ID
; Returns: Executable filename or empty string on failure
; -----------------------------------------------------------------------------
GetProcessName(pid) {
    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt", pid,
        "Ptr")
    if !hProc
        return ""
    try {
        nameBuffer := Buffer(MAX_PATH_CHARS * 2, 0)
        nameSize := MAX_PATH_CHARS
        if DllCall("Kernel32\QueryFullProcessImageName", "Ptr", hProc, "UInt", 0, "Ptr", nameBuffer.Ptr, "UInt*", &
            nameSize) {
            fullPath := StrGet(nameBuffer.Ptr, "UTF-16")
            SplitPath(fullPath, &fileName)
            return fileName
        }
        return ""
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

; -----------------------------------------------------------------------------
; GetForegroundProcessId - Gets the PID of the current foreground window's process
; Returns: Process ID or 0 if no foreground window
; -----------------------------------------------------------------------------
GetForegroundProcessId() {
    hWnd := DllCall("User32\GetForegroundWindow", "Ptr")
    if !hWnd
        return 0
    pid := 0
    DllCall("User32\GetWindowThreadProcessId", "Ptr", hWnd, "UInt*", &pid)
    return pid
}

; -----------------------------------------------------------------------------
; GetParentProcessId - Gets the parent process ID for a given process
; Parameters:
;   pid - Process ID
; Returns: Parent process ID or 0 on failure
; -----------------------------------------------------------------------------
GetParentProcessId(pid) {
    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt", pid,
        "Ptr")
    if !hProc
        return 0
    try {
        pbi := Buffer(PROCESS_BASIC_INFO_SIZE, 0)
        returnLength := 0
        result := DllCall("Ntdll\NtQueryInformationProcess", "Ptr", hProc, "Int", 0, "Ptr", pbi.Ptr, "UInt", pbi.Size,
            "UInt*", &returnLength)
        if (result = 0) {
            offset := (A_PtrSize = 8) ? PBI_PARENT_OFFSET_X64 : PBI_PARENT_OFFSET_X86
            return NumGet(pbi, offset, "UPtr")
        }
        return 0
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

; -----------------------------------------------------------------------------
; IsException - Checks if a process is in the exception list
; Parameters:
;   pid - Process ID to check
; Returns: true if excepted, false otherwise
; -----------------------------------------------------------------------------
IsException(pid) {
    global CONFIG
    processName := GetProcessName(pid)
    if !processName
        return false
    for exeName in CONFIG.exceptions {
        if (StrLower(processName) = StrLower(exeName))
            return true
    }
    return false
}

; -----------------------------------------------------------------------------
; IsTargetApp - Checks if a process is in the target list (for blacklist mode)
; Supports both simple string entries and object entries with name/names
; Parameters:
;   pid - Process ID to check
; Returns: true if targeted, false otherwise
; -----------------------------------------------------------------------------
IsTargetApp(pid) {
    global CONFIG
    processName := GetProcessName(pid)
    if !processName
        return false
    for target in CONFIG.targets {
        if (Type(target) = "String") {
            if (StrLower(processName) = StrLower(target))
                return true
        } else if (Type(target) = "Object") {
            if target.HasOwnProp("name") && (StrLower(processName) = StrLower(target.name))
                return true
            if target.HasOwnProp("names") {
                for targetName in target.names {
                    if (StrLower(processName) = StrLower(targetName))
                        return true
                }
            }
        }
    }
    return false
}

; -----------------------------------------------------------------------------
; GetProcessPriority - Gets the current priority class of a process
; Parameters:
;   pid - Process ID
; Returns: Priority class value or 0 on failure
; -----------------------------------------------------------------------------
GetProcessPriority(pid) {
    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt", pid,
        "Ptr")
    if !hProc
        return 0
    try {
        return DllCall("Kernel32\GetPriorityClass", "Ptr", hProc, "UInt")
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

; -----------------------------------------------------------------------------
; GetProcessTreePIDs - Gets all PIDs in a process tree (parent, children, same name)
; Parameters:
;   rootPid - Root process ID to build tree from
; Returns: Array of all related process IDs
; -----------------------------------------------------------------------------
GetProcessTreePIDs(rootPid) {
    treePIDs := [rootPid]
    rootName := GetProcessName(rootPid)
    parentPID := GetParentProcessId(rootPid)
    if (parentPID && parentPID != rootPid) {
        hParent := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt",
            parentPID, "Ptr")
        if (hParent) {
            DllCall("Kernel32\CloseHandle", "Ptr", hParent)
            treePIDs.Push(parentPID)
        }
    }
    snapshot := DllCall("Kernel32\CreateToolhelp32Snapshot", "UInt", 0x2, "UInt", 0, "Ptr")
    if (snapshot = -1)
        return treePIDs
    try {
        pidMap := Map()
        pe32 := Buffer(PROCESSENTRY32_SIZE, 0)
        NumPut("UInt", pe32.Size, pe32, 0)
        if DllCall("Kernel32\Process32First", "Ptr", snapshot, "Ptr", pe32) {
            loop {
                pid := NumGet(pe32, PE32_PID_OFFSET, "UInt")
                ppid := NumGet(pe32, (A_PtrSize = 8) ? PE32_PPID_OFFSET_X64 : PE32_PPID_OFFSET_X86, "UInt")
                pidMap[pid] := ppid
                if (pid != rootPid && rootName) {
                    procName := GetProcessName(pid)
                    if (procName && procName = rootName && !ArrayHas(treePIDs, pid))
                        treePIDs.Push(pid)
                }
                if !DllCall("Kernel32\Process32Next", "Ptr", snapshot, "Ptr", pe32)
                    break
            }
        }
        prevCount := 0
        while (treePIDs.Length != prevCount) {
            prevCount := treePIDs.Length
            for pid, ppid in pidMap {
                if (ArrayHas(treePIDs, ppid) && pid != ppid && !ArrayHas(treePIDs, pid))
                    treePIDs.Push(pid)
            }
        }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", snapshot)
    }
    return treePIDs
}

; -----------------------------------------------------------------------------
; ArrayHas - Checks if an array contains a value
; Parameters:
;   arr   - Array to search
;   value - Value to find
; Returns: true if found, false otherwise
; -----------------------------------------------------------------------------
ArrayHas(arr, value) {
    for item in arr {
        if (item = value)
            return true
    }
    return false
}

; -----------------------------------------------------------------------------
; RestoreAllProcesses - Cleanup function called on script exit
; Restores all throttled processes to their original state
; -----------------------------------------------------------------------------
RestoreAllProcesses(*) {
    global handled, foregroundHookHandle, suspendCycleTimers, cpuRateLimitTimers, cpuUsageTracking

    ; Stop foreground window hook
    if foregroundHookHandle {
        DllCall("User32\UnhookWinEvent", "Ptr", foregroundHookHandle)
        foregroundHookHandle := 0
    }

    ; Stop all suspend cycle timers
    for pid, timerFunc in suspendCycleTimers.Clone() {
        SetTimer(timerFunc, 0)
    }
    suspendCycleTimers.Clear()

    ; Stop all CPU rate limit timers
    for pid, timerFunc in cpuRateLimitTimers.Clone() {
        SetTimer(timerFunc, 0)
    }
    cpuRateLimitTimers.Clear()
    cpuUsageTracking.Clear()

    ; Restore all handled processes
    for pid, info in handled {
        RestoreProcess(pid, info.priority, info.HasOwnProp("originalAffinity") ? info.originalAffinity : 0)
    }
    handled.Clear()
}

; -----------------------------------------------------------------------------
; RestoreProcess - Restores a single process to its original state
; Parameters:
;   pid              - Process ID to restore
;   originalPriority - Original priority class to restore
;   originalAffinity - Original CPU affinity mask to restore (optional)
; Returns: true on success, false on failure
; -----------------------------------------------------------------------------
RestoreProcess(pid, originalPriority, originalAffinity := 0) {
    global handled, CONFIG, PROCESS_SUSPEND_RESUME

    ; Stop active throttling mechanisms (these also resume the process)
    StopSuspendCycle(pid)
    StopCpuRateLimiter(pid)

    ; Ensure process is fully resumed (resume multiple times for nested suspensions)
    hResume := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_SUSPEND_RESUME, "Int", false, "UInt", pid, "Ptr")
    if hResume {
        loop 5
            DllCall("Ntdll\NtResumeProcess", "Ptr", hResume)
        DllCall("Kernel32\CloseHandle", "Ptr", hResume)
    }

    access := PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return false
    try {
        ; Retrieve settings used for this process
        processName := ""
        if handled.Has(pid) && handled[pid].HasOwnProp("processName")
            processName := handled[pid].processName
        settings := GetProcessSettings(processName)

        if settings["useBackgroundMode"]
            DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", PROCESS_MODE_BACKGROUND_END)
        DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", originalPriority)
        ppt := Buffer(12, 0)
        NumPut("UInt", 1, ppt, 0), NumPut("UInt", 0x3, ppt, 4), NumPut("UInt", 0x0, ppt, 8)
        DllCall("Kernel32\SetProcessInformation", "Ptr", hProc, "Int", 4, "Ptr", ppt.Ptr, "UInt", ppt.Size, "Int")
        if settings["useIoPriority"] {
            ioPriority := Buffer(4, 0)
            NumPut("UInt", 2, ioPriority, 0)
            DllCall("Ntdll\NtSetInformationProcess", "Ptr", hProc, "Int", 33, "Ptr", ioPriority.Ptr, "UInt", 4)
        }
        ; Restore page priority to normal (5 = normal priority)
        if settings["usePagePriority"] {
            pagePriority := Buffer(4, 0)
            NumPut("UInt", 5, pagePriority, 0)
            DllCall("Ntdll\NtSetInformationProcess", "Ptr", hProc, "Int", 39, "Ptr", pagePriority.Ptr, "UInt", 4)
        }
        ; Restore CPU affinity
        if (settings["useCpuAffinity"] && originalAffinity)
            DllCall("Kernel32\SetProcessAffinityMask", "Ptr", hProc, "UPtr", originalAffinity)

        ; Remove working set limits
        if settings["useWorkingSetLimit"]
            DllCall("Kernel32\SetProcessWorkingSetSizeEx", "Ptr", hProc, "Ptr", -1, "Ptr", -1, "UInt", 0)
        return true
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

; -----------------------------------------------------------------------------
; GetProcessMemoryMB - Gets the working set memory usage of a process in MB
; Parameters:
;   pid - Process ID
; Returns: Memory usage in megabytes or 0 on failure
; -----------------------------------------------------------------------------
GetProcessMemoryMB(pid) {
    access := PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return 0
    try {
        pmc := Buffer(PROCESS_MEMORY_COUNTERS_SIZE, 0)
        NumPut("UInt", pmc.Size, pmc, 0)
        if DllCall("Psapi\GetProcessMemoryInfo", "Ptr", hProc, "Ptr", pmc.Ptr, "UInt", pmc.Size) {
            workingSetSize := NumGet(pmc, 12, "UPtr")
            return Round(workingSetSize / (1024 * 1024))
        }
        return 0
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

; -----------------------------------------------------------------------------
; TrimProcessMemory - Reduces the working set memory of a process
; Parameters:
;   pid         - Process ID
;   thresholdMB - Only trim if memory exceeds this value (default: 100)
;   aggressive  - Use multiple trim passes (default: true)
;   passes      - Number of trim passes for aggressive mode (default: 3)
; Returns: true if trimmed, false otherwise
; -----------------------------------------------------------------------------
TrimProcessMemory(pid, thresholdMB := 100, aggressive := true, passes := 3) {
    memoryMB := GetProcessMemoryMB(pid)
    if (memoryMB < thresholdMB)
        return false
    access := PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return false
    try {
        if aggressive {
            DllCall("Kernel32\SetProcessWorkingSetSize", "Ptr", hProc, "Ptr", -1, "Ptr", -1)
            result := false
            loop passes {
                if DllCall("Psapi\EmptyWorkingSet", "Ptr", hProc, "Int")
                    result := true
                if (A_Index < passes)
                    Sleep(10)
            }
            return result
        } else
            return !!DllCall("Psapi\EmptyWorkingSet", "Ptr", hProc, "Int")
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

; -----------------------------------------------------------------------------
; ApplyEfficiencyLikeMode - Applies all throttling settings to a process
; Sets priority, QoS, I/O priority, CPU affinity, memory limits, and more
; Parameters:
;   pid      - Process ID to throttle
;   settings - Map of settings to apply
; Returns: Object with success status and original affinity mask
; -----------------------------------------------------------------------------
ApplyEfficiencyLikeMode(pid, settings) {
    global suspendCycleTimers
    access := PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION |
        PROCESS_SET_QUOTA
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return { success: false, originalAffinity: 0 }
    originalAffinity := 0
    try {
        if settings["useBackgroundMode"]
            DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", PROCESS_MODE_BACKGROUND_BEGIN)
        else {
            priority := settings["useIdlePriority"] ? IDLE_PRIORITY_CLASS : BELOW_NORMAL_PRIORITY_CLASS
            DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", priority)
        }
        ppt := Buffer(12, 0)
        NumPut("UInt", 1, ppt, 0), NumPut("UInt", 0x3, ppt, 4), NumPut("UInt", 0x3, ppt, 8)
        ok := DllCall("Kernel32\SetProcessInformation", "Ptr", hProc, "Int", 4, "Ptr", ppt.Ptr, "UInt", ppt.Size, "Int"
        )
        if ok {
            ecoQoS := Buffer(12, 0)
            NumPut("UInt", 1, ecoQoS, 0), NumPut("UInt", 0x3, ecoQoS, 4), NumPut("UInt", 0x3, ecoQoS, 8)
            DllCall("Kernel32\SetProcessInformation", "Ptr", hProc, "Int", 4, "Ptr", ecoQoS.Ptr, "UInt", ecoQoS.Size,
                "Int")
        }
        if settings["useIoPriority"] {
            ioPriority := Buffer(4, 0)
            NumPut("UInt", 0, ioPriority, 0)
            DllCall("Ntdll\NtSetInformationProcess", "Ptr", hProc, "Int", 33, "Ptr", ioPriority.Ptr, "UInt", 4)
        }
        ; Set page priority (memory manager priority)
        if settings["usePagePriority"] {
            pagePriority := Buffer(4, 0)
            NumPut("UInt", settings["pagePriority"], pagePriority, 0)
            DllCall("Ntdll\NtSetInformationProcess", "Ptr", hProc, "Int", 39, "Ptr", pagePriority.Ptr, "UInt", 4)
        }
        ; Set CPU affinity (single core setting overrides affinity mask)
        if settings["useCpuAffinity"] {
            systemAffinity := 0
            if DllCall("Kernel32\GetProcessAffinityMask", "Ptr", hProc, "UPtr*", &originalAffinity, "UPtr*", &
                systemAffinity) {
                affinityMask := settings["cpuAffinityMask"]
                if settings["useSingleCore"]
                    affinityMask := 1 << settings["singleCoreIndex"]
                DllCall("Kernel32\SetProcessAffinityMask", "Ptr", hProc, "UPtr", affinityMask)
            }
        }
        ; Set working set limits (0x6 = QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_ENABLE)
        if settings["useWorkingSetLimit"] {
            minWS := 1024 * 1024
            maxWS := settings["workingSetLimitMB"] * 1024 * 1024
            DllCall("Kernel32\SetProcessWorkingSetSizeEx", "Ptr", hProc, "Ptr", minWS, "Ptr", maxWS, "UInt", 0x6)
        }

        ; Start CPU rate limiting via active monitoring
        if settings["useCpuRateLimit"] {
            StartCpuRateLimiter(pid, settings["cpuRateLimitPercent"])
        }
        ; Start suspend/resume cycles
        if settings["useSuspendCycles"] {
            suspendDuration := settings["suspendDurationMs"]
            resumeDuration := settings["resumeDurationMs"]
            cycleInterval := suspendDuration + resumeDuration
            boundFunc := SuspendCycleCallback.Bind(pid, suspendDuration, resumeDuration)
            SetTimer(boundFunc, cycleInterval)
            suspendCycleTimers[pid] := boundFunc
        }
        return { success: !!ok, originalAffinity: originalAffinity }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

; -----------------------------------------------------------------------------
; SuspendCycleCallback - Timer callback for suspend/resume cycling
; Parameters:
;   pid       - Process ID to suspend
;   suspendMs - Duration to keep process suspended
;   resumeMs  - Duration to allow process to run (unused, handled by interval)
; -----------------------------------------------------------------------------
SuspendCycleCallback(pid, suspendMs, resumeMs) {
    global PROCESS_SUSPEND_RESUME, handled

    ; Verify process is still being managed
    if !handled.Has(pid) {
        StopSuspendCycle(pid)
        return
    }
    ; Suspend the process and schedule resume
    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_SUSPEND_RESUME, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return
    DllCall("Ntdll\NtSuspendProcess", "Ptr", hProc)
    DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    SetTimer(ResumeProcessCallback.Bind(pid), -suspendMs)
}

; -----------------------------------------------------------------------------
; ResumeProcessCallback - Timer callback to resume a suspended process
; Parameters:
;   pid - Process ID to resume
; -----------------------------------------------------------------------------
ResumeProcessCallback(pid) {
    global PROCESS_SUSPEND_RESUME
    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_SUSPEND_RESUME, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return
    DllCall("Ntdll\NtResumeProcess", "Ptr", hProc)
    DllCall("Kernel32\CloseHandle", "Ptr", hProc)
}

; -----------------------------------------------------------------------------
; StopSuspendCycle - Stops the suspend/resume cycle for a process
; Parameters:
;   pid - Process ID to stop cycling
; -----------------------------------------------------------------------------
StopSuspendCycle(pid) {
    global suspendCycleTimers
    if suspendCycleTimers.Has(pid) {
        SetTimer(suspendCycleTimers[pid], 0)
        suspendCycleTimers.Delete(pid)
        ResumeProcessCallback(pid)
    }
}

; =============================================================================
; CPU RATE LIMITER
; Active monitoring with suspend/resume to enforce CPU usage limits
; =============================================================================

; -----------------------------------------------------------------------------
; StartCpuRateLimiter - Starts CPU rate limiting for a process
; Parameters:
;   pid           - Process ID to limit
;   targetPercent - Maximum CPU usage percentage allowed
; -----------------------------------------------------------------------------
StartCpuRateLimiter(pid, targetPercent) {
    global cpuRateLimitTimers, cpuUsageTracking, CPU_RATE_CHECK_INTERVAL

    ; Initialize tracking state for this process
    cpuUsageTracking[pid] := {
        targetPercent: targetPercent,
        lastKernelTime: 0,
        lastUserTime: 0,
        lastCheckTime: A_TickCount,
        isSuspended: false,
        suspendUntil: 0
    }

    ; Get initial CPU times and start monitoring timer
    UpdateProcessCpuTimes(pid)
    boundFunc := CpuRateLimitCallback.Bind(pid)
    SetTimer(boundFunc, CPU_RATE_CHECK_INTERVAL)
    cpuRateLimitTimers[pid] := boundFunc
}

; -----------------------------------------------------------------------------
; StopCpuRateLimiter - Stops CPU rate limiting for a process
; Parameters:
;   pid - Process ID to stop limiting
; -----------------------------------------------------------------------------
StopCpuRateLimiter(pid) {
    global cpuRateLimitTimers, cpuUsageTracking, PROCESS_SUSPEND_RESUME

    ; Stop the monitoring timer
    if cpuRateLimitTimers.Has(pid) {
        SetTimer(cpuRateLimitTimers[pid], 0)
        cpuRateLimitTimers.Delete(pid)
    }

    ; Clean up tracking and ensure process is resumed
    if cpuUsageTracking.Has(pid) {
        if cpuUsageTracking[pid].isSuspended {
            hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_SUSPEND_RESUME, "Int", false, "UInt", pid, "Ptr")
            if hProc {
                DllCall("Ntdll\NtResumeProcess", "Ptr", hProc)
                DllCall("Kernel32\CloseHandle", "Ptr", hProc)
            }
        }
        cpuUsageTracking.Delete(pid)
    }
}

; -----------------------------------------------------------------------------
; UpdateProcessCpuTimes - Updates stored CPU time values for a process
; Parameters:
;   pid - Process ID to update
; Returns: true on success, false on failure
; -----------------------------------------------------------------------------
UpdateProcessCpuTimes(pid) {
    global cpuUsageTracking, PROCESS_QUERY_LIMITED_INFORMATION

    if !cpuUsageTracking.Has(pid)
        return false

    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt", pid,
        "Ptr")
    if !hProc
        return false

    try {
        creationTime := Buffer(8, 0)
        exitTime := Buffer(8, 0)
        kernelTime := Buffer(8, 0)
        userTime := Buffer(8, 0)

        if DllCall("Kernel32\GetProcessTimes", "Ptr", hProc, "Ptr", creationTime.Ptr, "Ptr", exitTime.Ptr, "Ptr",
            kernelTime.Ptr, "Ptr", userTime.Ptr, "Int") {
            cpuUsageTracking[pid].lastKernelTime := NumGet(kernelTime, 0, "Int64")
            cpuUsageTracking[pid].lastUserTime := NumGet(userTime, 0, "Int64")
            cpuUsageTracking[pid].lastCheckTime := A_TickCount
            return true
        }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
    return false
}

; -----------------------------------------------------------------------------
; GetProcessCpuPercent - Calculates current CPU usage percentage for a process
; Uses delta between current and previous measurements
; Parameters:
;   pid - Process ID to measure
; Returns: CPU usage percentage (0-100+)
; -----------------------------------------------------------------------------
GetProcessCpuPercent(pid) {
    global cpuUsageTracking, PROCESS_QUERY_LIMITED_INFORMATION

    if !cpuUsageTracking.Has(pid)
        return 0

    tracking := cpuUsageTracking[pid]
    prevKernel := tracking.lastKernelTime
    prevUser := tracking.lastUserTime
    prevTime := tracking.lastCheckTime

    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt", pid,
        "Ptr")
    if !hProc
        return 0

    try {
        creationTime := Buffer(8, 0)
        exitTime := Buffer(8, 0)
        kernelTime := Buffer(8, 0)
        userTime := Buffer(8, 0)

        if DllCall("Kernel32\GetProcessTimes", "Ptr", hProc, "Ptr", creationTime.Ptr, "Ptr", exitTime.Ptr, "Ptr",
            kernelTime.Ptr, "Ptr", userTime.Ptr, "Int") {
            currentKernel := NumGet(kernelTime, 0, "Int64")
            currentUser := NumGet(userTime, 0, "Int64")
            currentTime := A_TickCount

            ; Update stored values for next calculation
            cpuUsageTracking[pid].lastKernelTime := currentKernel
            cpuUsageTracking[pid].lastUserTime := currentUser
            cpuUsageTracking[pid].lastCheckTime := currentTime

            ; Calculate elapsed time and CPU time delta (times are in 100ns intervals)
            elapsedMs := currentTime - prevTime
            if elapsedMs <= 0
                return 0

            cpuTimeDelta := (currentKernel - prevKernel) + (currentUser - prevUser)
            cpuTimeMs := cpuTimeDelta / 10000

            ; Get processor count for accurate percentage calculation
            numProcessors := DllCall("Kernel32\GetActiveProcessorCount", "UShort", 0xFFFF, "UInt")
            if numProcessors < 1
                numProcessors := 1

            ; Calculate percentage: (CPU time / wall time / processors) * 100
            cpuPercent := (cpuTimeMs / elapsedMs / numProcessors) * 100
            return cpuPercent
        }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
    return 0
}

; -----------------------------------------------------------------------------
; CpuRateLimitCallback - Timer callback for CPU rate limit enforcement
; Monitors CPU usage and suspends process when over limit
; Parameters:
;   pid - Process ID to monitor
; -----------------------------------------------------------------------------
CpuRateLimitCallback(pid) {
    global cpuUsageTracking, handled, PROCESS_SUSPEND_RESUME

    ; Verify process is still being managed
    if !handled.Has(pid) || !cpuUsageTracking.Has(pid) {
        StopCpuRateLimiter(pid)
        return
    }

    tracking := cpuUsageTracking[pid]

    ; Check if suspended process should be resumed
    if tracking.isSuspended {
        if A_TickCount >= tracking.suspendUntil {
            hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_SUSPEND_RESUME, "Int", false, "UInt", pid, "Ptr")
            if hProc {
                DllCall("Ntdll\NtResumeProcess", "Ptr", hProc)
                DllCall("Kernel32\CloseHandle", "Ptr", hProc)
            }
            cpuUsageTracking[pid].isSuspended := false
            UpdateProcessCpuTimes(pid)
        }
        return
    }

    ; Check CPU usage and suspend if over limit
    cpuPercent := GetProcessCpuPercent(pid)

    if cpuPercent > tracking.targetPercent {
        hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_SUSPEND_RESUME, "Int", false, "UInt", pid, "Ptr")
        if hProc {
            DllCall("Ntdll\NtSuspendProcess", "Ptr", hProc)
            DllCall("Kernel32\CloseHandle", "Ptr", hProc)

            ; Calculate suspension duration based on overage (50-500ms)
            overageRatio := cpuPercent / Max(tracking.targetPercent, 1)
            suspendMs := Min(Max(50 * overageRatio, 50), 500)

            cpuUsageTracking[pid].isSuspended := true
            cpuUsageTracking[pid].suspendUntil := A_TickCount + suspendMs
        }
    }
}
