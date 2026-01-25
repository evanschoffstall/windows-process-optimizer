#Requires AutoHotkey v2.0
#SingleInstance Force

; ====================================================================================
; CONFIGURATION
; ====================================================================================

; Priority Settings
useIdlePriority := false       ; true = IDLE, false = BELOW NORMAL

; Memory Management
useMemoryTrimming := true      ; true = trim working set to reduce RAM usage
memoryThresholdMB := 10        ; only trim processes using more than this amount of RAM (in MB)
useAggressiveMemory := true    ; true = use ultra-aggressive memory reduction (working set limits + multi-pass trim)
memoryTrimPasses := 3          ; number of times to call EmptyWorkingSet (more passes = more aggressive)

; Advanced CPU Reduction
useIoPriority := true          ; true = set I/O priority to Very Low (reduces disk/network interference)
useCpuAffinity := true         ; true = restrict to specific CPU cores (limits CPU access)
cpuAffinityMask := 0x03        ; bitmask for allowed cores (0x03 = cores 0-1, 0x0F = cores 0-3)
useCpuRateLimit := true        ; true = hard cap CPU usage percentage (most aggressive)
cpuRateLimitPercent := 5       ; max CPU usage percent (1-100) when rate limiting enabled
useBackgroundMode := true      ; true = enable PROCESS_MODE_BACKGROUND_BEGIN (tells Windows process is background)

; Mode Selection
useBlacklistMode := true      ; true = target ONLY apps in targetNames list, false = target ALL apps except exceptions

; Blacklist Mode - Target specific apps
targetNames := ["CCleaner_service.exe", "svchost.exe", "WmiPrvSE.exe", "bdservicehost.exe",
    "downloader.exe", "testinitsigs.exe", "AdobeColabSync.exe"]  ; apps to target when useBlacklistMode = true

; Whitelist Mode - Skip Rules (used when useBlacklistMode = false)
exceptions := ["Flow.Launcher.exe", "explorer.exe", "everything.exe", "yasb.exe"]  ; list of exe names to exclude from efficiency mode
skipWindowsApps := false       ; true = exclude Windows Apps/UWP processes from efficiency mode
skipForegroundProcess := true  ; true = exclude process with active foreground window from efficiency mode
skipForegroundProcessTree := true  ; true = also exclude all child processes of foreground app
skipExceptionProcessTree := true  ; true = also exclude all child processes of exception apps

; ====================================================================================
; CONSTANTS
; ====================================================================================

; Process Access Rights
PROCESS_QUERY_LIMITED_INFORMATION := 0x1000
PROCESS_QUERY_INFORMATION := 0x0400
PROCESS_SET_INFORMATION := 0x0200
PROCESS_SET_QUOTA := 0x0100
PROCESS_VM_READ := 0x0010

; Priority Classes
IDLE_PRIORITY_CLASS := 0x0040
BELOW_NORMAL_PRIORITY_CLASS := 0x4000
PROCESS_MODE_BACKGROUND_BEGIN := 0x00100000
PROCESS_MODE_BACKGROUND_END := 0x00200000

; Structure Sizes
PROCESSENTRY32_SIZE := 304
PROCESS_BASIC_INFO_SIZE := 48
PROCESS_MEMORY_COUNTERS_SIZE := 72

; PROCESSENTRY32 Offsets
PE32_PID_OFFSET := 8
PE32_PPID_OFFSET_X86 := 20
PE32_PPID_OFFSET_X64 := 28

; PROCESS_BASIC_INFORMATION Offsets
PBI_PARENT_OFFSET_X86 := 20
PBI_PARENT_OFFSET_X64 := 40

; Other Constants
SCAN_INTERVAL_MS := 15000
MAX_PATH_CHARS := 260

; ====================================================================================
; GLOBAL STATE
; ====================================================================================

handled := Map()  ; PID -> {priority, throttled, memoryTrimmed, jobHandle, originalAffinity}
currentScriptPID := DllCall("Kernel32\GetCurrentProcessId", "UInt")
currentForegroundPID := 0  ; Track current foreground process
foregroundHookHandle := 0  ; Handle to the foreground window event hook
pendingForegroundChange := false  ; Flag to indicate pending foreground change

; ====================================================================================
; INITIALIZATION
; ====================================================================================

OnExit(RestoreAllProcesses)
A_IconTip := "Keep ALL Apps Efficient\nInitializing..."

ScanAndApplyAll()
SetupProcessWatcher()
SetupForegroundWatcher()
SetTimer(ScanAndApplyAll, SCAN_INTERVAL_MS)

; ====================================================================================
; MAIN SCAN LOGIC
; ====================================================================================

/**
 * Scans all running processes and applies efficiency mode to background processes
 * Skips foreground apps, their process trees, UWP apps, and exceptions
 */
ScanAndApplyAll() {
    global handled, currentScriptPID

    foregroundPID := skipForegroundProcess ? GetForegroundProcessId() : 0
    foregroundTreePIDs := BuildForegroundTreeMap(foregroundPID)
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

                if (ShouldSkipProcess(pid, foregroundPID, foregroundTreePIDs, exceptionTreePIDs, &skipCounts)) {
                    if !DllCall("Kernel32\Process32Next", "Ptr", snapshot, "Ptr", pe32)
                        break
                    continue
                }

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

/**
 * Builds a map of all PIDs in the foreground process tree
 */
BuildForegroundTreeMap(foregroundPID) {
    foregroundTreePIDs := Map()

    if (skipForegroundProcessTree && foregroundPID) {
        treePIDs := GetProcessTreePIDs(foregroundPID)
        for _, pid in treePIDs
            foregroundTreePIDs[pid] := true
    }

    return foregroundTreePIDs
}

/**
 * Builds a map of all PIDs in exception process trees
 */
BuildExceptionTreeMap() {
    global exceptions, skipExceptionProcessTree
    exceptionTreePIDs := Map()

    if !skipExceptionProcessTree
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

                ; Check if this process is an exception
                processName := GetProcessName(pid)
                if processName {
                    for exeName in exceptions {
                        if (StrLower(processName) = StrLower(exeName)) {
                            ; Found an exception, add its entire tree
                            treePIDs := GetProcessTreePIDs(pid)
                            for _, treePid in treePIDs
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

/**
 * Determines if a process should be skipped based on rules
 * Returns true if process should be skipped, false otherwise
 * Modifies skipCounts by reference to track skip reasons
 */
ShouldSkipProcess(pid, foregroundPID, foregroundTreePIDs, exceptionTreePIDs, &skipCounts) {
    global handled, currentScriptPID, skipExceptionProcessTree, useBlacklistMode

    ; Skip this script itself
    if (pid = currentScriptPID)
        return true

    ; BLACKLIST MODE: Only process apps in targetNames, skip everything else
    if (useBlacklistMode) {
        if (!IsTargetApp(pid)) {
            return true  ; Skip if not in target list
        }
        ; If in target list, continue with foreground checks below
    }

    ; Skip UWP apps (applies to both modes)
    if (skipWindowsApps && IsWindowsApp(pid)) {
        skipCounts.uwp++
        return true
    }

    ; Skip and restore foreground process
    if (skipForegroundProcess && foregroundPID && pid = foregroundPID) {
        RestoreIfHandled(pid)
        return true
    }

    ; Skip and restore processes in foreground tree
    if (skipForegroundProcessTree && foregroundTreePIDs.Has(pid)) {
        RestoreIfHandled(pid)
        return true
    }

    ; WHITELIST MODE ONLY: Skip exceptions
    if (!useBlacklistMode) {
        if (IsException(pid)) {
            skipCounts.exception++
            RestoreIfHandled(pid)
            return true
        }

        ; Skip exception process trees
        if (skipExceptionProcessTree && exceptionTreePIDs.Has(pid)) {
            RestoreIfHandled(pid)
            return true
        }
    }

    return false
}

/**
 * Restores a process if it was previously handled
 */
RestoreIfHandled(pid) {
    global handled

    if handled.Has(pid) {
        info := handled[pid]
        RestoreProcess(pid, info.priority,
            info.HasOwnProp("jobHandle") ? info.jobHandle : 0,
            info.HasOwnProp("originalAffinity") ? info.originalAffinity : 0)
        handled.Delete(pid)
    }
}

/**
 * Applies efficiency mode to a background process
 */
ProcessBackgroundApp(pid) {
    global handled, useIdlePriority, useMemoryTrimming, memoryThresholdMB,
        useAggressiveMemory, memoryTrimPasses

    if !handled.Has(pid) {
        originalPriority := GetProcessPriority(pid)
        result := ApplyEfficiencyLikeMode(pid, useIdlePriority)

        if (originalPriority && result.success) {
            memTrimmed := useMemoryTrimming ?
                TrimProcessMemory(pid, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses) : false

            handled[pid] := {
                priority: originalPriority,
                throttled: true,
                memoryTrimmed: memTrimmed,
                jobHandle: result.jobHandle,
                originalAffinity: result.originalAffinity
            }
        }
    } else if (useMemoryTrimming && handled.Has(pid)) {
        ; Periodically trim memory for already-handled processes
        TrimProcessMemory(pid, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses)
    }
}

; ====================================================================================
; TRAY TOOLTIP
; ====================================================================================

/**
 * Updates the system tray tooltip with current status
 */
UpdateTrayTooltip(uwpCount := 0, exceptionCount := 0) {
    global handled, skipForegroundProcess, skipForegroundProcessTree

    foregroundPID := GetForegroundProcessId()
    if !foregroundPID {
        A_IconTip := "Keep ALL Apps Efficient\nNo foreground window"
        return
    }

    foregroundName := GetProcessName(foregroundPID)
    if !foregroundName
        foregroundName := "Unknown"

    throttledCount := handled.Count
    treeSize := CalculateTreeSize(foregroundPID)
    totalSkipped := uwpCount + treeSize + exceptionCount

    tooltip := "Keep ALL Apps Efficient"
    tooltip .= "`nMode: " . (useBlacklistMode ? "Blacklist (Target Only)" : "Whitelist (All Except)")
    if skipForegroundProcess
        tooltip .= "`nForeground: " . foregroundName . " (PID: " . foregroundPID . ")"

    tooltip .= "`nThrottled: " . throttledCount
    tooltip .= "`nSkipped: " . totalSkipped

    A_IconTip := tooltip
}

/**
 * Calculates the size of the process tree for the given PID
 */
CalculateTreeSize(pid) {
    if skipForegroundProcessTree {
        treePIDs := GetProcessTreePIDs(pid)
        return treePIDs.Length
    } else if skipForegroundProcess {
        return 1
    }
    return 0
}

; ====================================================================================
; PROCESS WATCHER
; ====================================================================================

/**
 * Sets up WMI watcher to monitor newly created processes
 */
SetupProcessWatcher() {
    query := "SELECT ProcessId FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    sink := ComObject("WbemScripting.SWbemSink")
    ComObjConnect(sink, "OnProcessCreated_")
    wmi := ComObjGet("winmgmts:\\.\root\CIMV2")
    wmi.ExecNotificationQueryAsync(sink, query)
}

; ====================================================================================
; FOREGROUND WINDOW WATCHER
; ====================================================================================

/**
 * Sets up real-time foreground window change detection using Windows Event Hooks
 */
SetupForegroundWatcher() {
    global foregroundHookHandle, currentForegroundPID

    ; EVENT_SYSTEM_FOREGROUND = 0x0003
    ; WINEVENT_OUTOFCONTEXT = 0x0000 (callback in our process context)
    ; WINEVENT_SKIPOWNPROCESS = 0x0002 (skip events from this process)

    ; Create callback function
    callback := CallbackCreate(OnForegroundWindowChanged, "F", 7)

    ; SetWinEventHook(eventMin, eventMax, hmodWinEventProc, callback, idProcess, idThread, dwFlags)
    foregroundHookHandle := DllCall("User32\SetWinEventHook",
        "UInt", 0x0003,     ; EVENT_SYSTEM_FOREGROUND
        "UInt", 0x0003,     ; EVENT_SYSTEM_FOREGROUND
        "Ptr", 0,           ; hmodWinEventProc (0 for callback in our process)
        "Ptr", callback,    ; lpfnWinEventProc
        "UInt", 0,          ; idProcess (0 = all processes)
        "UInt", 0,          ; idThread (0 = all threads)
        "UInt", 0x0002,     ; dwFlags (WINEVENT_SKIPOWNPROCESS)
        "Ptr")

    ; Initialize current foreground
    currentForegroundPID := GetForegroundProcessId()
}

/**
 * Callback function called when foreground window changes
 * Lightweight - only updates PID and schedules deferred work
 * Parameters: hWinEventHook, event, hwnd, idObject, idChild, idEventThread, dwmsEventTime
 */
OnForegroundWindowChanged(hWinEventHook, event, hwnd, idObject, idChild, idEventThread, dwmsEventTime) {
    global currentForegroundPID, skipForegroundProcess, pendingForegroundChange

    if !skipForegroundProcess
        return

    ; Get PID of new foreground window (fast operation)
    newPID := 0
    if hwnd
        DllCall("User32\GetWindowThreadProcessId", "Ptr", hwnd, "UInt*", &newPID)

    if !newPID || newPID = currentForegroundPID
        return

    ; Update tracking (lightweight)
    currentForegroundPID := newPID
    pendingForegroundChange := true

    ; Defer heavy work (tree building, process restoration, efficiency mode application)
    ; Use -50ms for one-shot timer that runs after callback completes
    SetTimer(ProcessForegroundChange, -50)
}

/**
 * Deferred foreground change processor - runs heavy operations outside callback
 * This keeps the event hook callback fast and reduces CPU overhead
 */
ProcessForegroundChange() {
    global pendingForegroundChange, currentForegroundPID, handled
    static lastProcessedPID := 0

    if !pendingForegroundChange
        return

    pendingForegroundChange := false

    ; Avoid reprocessing same PID
    if (currentForegroundPID = lastProcessedPID)
        return

    newPID := currentForegroundPID
    oldPID := lastProcessedPID
    lastProcessedPID := newPID

    ; Apply efficiency mode to old foreground (now background)
    if oldPID && oldPID != newPID {
        ApplyToFormerForeground(oldPID)
    }

    ; Restore new foreground process
    if newPID {
        RestoreForegroundProcess(newPID)
    }

    ; Update tray tooltip
    UpdateTrayTooltip()
}

/**
 * Applies efficiency mode to a process that was just moved to background
 */
ApplyToFormerForeground(pid) {
    global skipForegroundProcessTree, handled, useIdlePriority
    global useMemoryTrimming, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses

    ; Get PIDs to apply efficiency mode to
    pidsToHandle := [pid]
    if skipForegroundProcessTree {
        treePIDs := GetProcessTreePIDs(pid)
        pidsToHandle := treePIDs
    }

    ; Apply efficiency mode to each PID
    for _, targetPID in pidsToHandle {
        if ShouldSkipProcessForEfficiency(targetPID)
            continue

        if !handled.Has(targetPID) {
            originalPriority := GetProcessPriority(targetPID)
            result := ApplyEfficiencyLikeMode(targetPID, useIdlePriority)

            if (originalPriority && result.success) {
                memTrimmed := useMemoryTrimming ?
                    TrimProcessMemory(targetPID, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses) : false

                handled[targetPID] := {
                    priority: originalPriority,
                    throttled: true,
                    memoryTrimmed: memTrimmed,
                    jobHandle: result.jobHandle,
                    originalAffinity: result.originalAffinity
                }
            }
        }
    }
}

/**
 * Restores a process that just became foreground
 */
RestoreForegroundProcess(pid) {
    global skipForegroundProcessTree

    ; Get PIDs to restore
    pidsToRestore := [pid]
    if skipForegroundProcessTree {
        treePIDs := GetProcessTreePIDs(pid)
        pidsToRestore := treePIDs
    }

    ; Restore each PID
    for _, targetPID in pidsToRestore {
        RestoreIfHandled(targetPID)
    }
}

/**
 * Checks if a process should be skipped when applying efficiency mode
 */
ShouldSkipProcessForEfficiency(pid) {
    global currentScriptPID

    if (pid = currentScriptPID)
        return true
    if (skipWindowsApps && IsWindowsApp(pid))
        return true
    if (IsException(pid))
        return true

    return false
}

/**
 * Callback when a new process is created
 */
OnProcessCreated_OnObjectReady(objWbemObject, objWbemAsyncContext) {
    global handled, useIdlePriority, useMemoryTrimming, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses,
        currentScriptPID, skipForegroundProcess, skipWindowsApps

    try {
        pid := objWbemObject.TargetInstance.ProcessId

        if (ShouldSkipNewProcess(pid))
            return

        ApplyToNewProcess(pid)
    }
}

/**
 * Determines if a newly created process should be skipped
 */
ShouldSkipNewProcess(pid) {
    global currentScriptPID, skipWindowsApps, skipForegroundProcess

    if (pid = currentScriptPID)
        return true
    if (skipWindowsApps && IsWindowsApp(pid))
        return true
    if (skipForegroundProcess && pid = GetForegroundProcessId())
        return true
    if (IsException(pid))
        return true

    return false
}

/**
 * Applies efficiency mode to a newly created process with retry logic
 */
ApplyToNewProcess(pid) {
    global handled, useIdlePriority, useMemoryTrimming, memoryThresholdMB,
        useAggressiveMemory, memoryTrimPasses

    if handled.Has(pid)
        return

    originalPriority := GetProcessPriority(pid)
    if !originalPriority
        return

    result := ApplyEfficiencyLikeMode(pid, useIdlePriority)
    if !result.success {
        Sleep(50)
        result := ApplyEfficiencyLikeMode(pid, useIdlePriority)
    }

    if result.success {
        memTrimmed := useMemoryTrimming ?
            TrimProcessMemory(pid, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses) : false

        handled[pid] := {
            priority: originalPriority,
            throttled: true,
            memoryTrimmed: memTrimmed,
            jobHandle: result.jobHandle,
            originalAffinity: result.originalAffinity
        }
    }
}

; ====================================================================================
; PROCESS IDENTIFICATION
; ====================================================================================

/**
 * Checks if a process is a Windows UWP/Packaged app
 */
IsWindowsApp(pid) {
    hProc := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt", pid,
        "Ptr")
    if !hProc
        return false

    try {
        packageLength := 0
        result := DllCall("Kernel32\GetPackageFullName", "Ptr", hProc, "UInt*", &packageLength, "Ptr", 0, "Int")
        ; ERROR_INSUFFICIENT_BUFFER (122) = has package name (UWP App)
        ; APPMODEL_ERROR_NO_PACKAGE (15700) = not packaged (Background process)
        return (result = 122)
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

/**
 * Gets the executable name of a process
 */
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

/**
 * Gets the PID of the process owning the foreground window
 */
GetForegroundProcessId() {
    hWnd := DllCall("User32\GetForegroundWindow", "Ptr")
    if !hWnd
        return 0

    pid := 0
    DllCall("User32\GetWindowThreadProcessId", "Ptr", hWnd, "UInt*", &pid)
    return pid
}

/**
 * Gets the parent process ID using NtQueryInformationProcess
 */
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

/**
 * Checks if a process name matches any in the exceptions list
 */
IsException(pid) {
    global exceptions

    processName := GetProcessName(pid)
    if !processName
        return false

    for exeName in exceptions {
        if (StrLower(processName) = StrLower(exeName))
            return true
    }
    return false
}

/**
 * Checks if a process name matches any in the targetNames list (for blacklist mode)
 */
IsTargetApp(pid) {
    global targetNames

    processName := GetProcessName(pid)
    if !processName
        return false

    for targetName in targetNames {
        if (StrLower(processName) = StrLower(targetName))
            return true
    }
    return false
}

/**
 * Gets the current priority class of a process
 */
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

; ====================================================================================
; PROCESS TREE ANALYSIS
; ====================================================================================

/**
 * Gets all PIDs in a process tree:
 * - Root process
 * - Parent process (if exists)
 * - All child/descendant processes
 * - All processes with the same executable name (for multi-process apps like Firefox)
 */
GetProcessTreePIDs(rootPid) {
    treePIDs := [rootPid]
    rootName := GetProcessName(rootPid)

    AddParentToTree(&treePIDs, rootPid)

    snapshot := DllCall("Kernel32\CreateToolhelp32Snapshot", "UInt", 0x2, "UInt", 0, "Ptr")
    if (snapshot = -1)
        return treePIDs

    try {
        pidMap := BuildPIDMap(snapshot, &treePIDs, rootPid, rootName)
        AddChildrenToTree(&treePIDs, pidMap)
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", snapshot)
    }

    return treePIDs
}

/**
 * Adds parent process to tree if it exists
 */
AddParentToTree(&treePIDs, rootPid) {
    parentPID := GetParentProcessId(rootPid)
    if (!parentPID || parentPID = rootPid)
        return

    hParent := DllCall("Kernel32\OpenProcess", "UInt", PROCESS_QUERY_LIMITED_INFORMATION, "Int", false, "UInt",
        parentPID, "Ptr")
    if (hParent) {
        DllCall("Kernel32\CloseHandle", "Ptr", hParent)
        treePIDs.Push(parentPID)
    }
}

/**
 * Builds a map of PID -> Parent PID for all processes
 * Also adds same-name processes to tree
 */
BuildPIDMap(snapshot, &treePIDs, rootPid, rootName) {
    pe32 := Buffer(PROCESSENTRY32_SIZE, 0)
    NumPut("UInt", pe32.Size, pe32, 0)
    pidMap := Map()

    if !DllCall("Kernel32\Process32First", "Ptr", snapshot, "Ptr", pe32)
        return pidMap

    loop {
        pid := NumGet(pe32, PE32_PID_OFFSET, "UInt")
        ppid := NumGet(pe32, (A_PtrSize = 8) ? PE32_PPID_OFFSET_X64 : PE32_PPID_OFFSET_X86, "UInt")
        pidMap[pid] := ppid

        ; Add all processes with same name
        if (pid != rootPid && rootName) {
            procName := GetProcessName(pid)
            if (procName && procName = rootName && !IsInArray(treePIDs, pid))
                treePIDs.Push(pid)
        }

        if !DllCall("Kernel32\Process32Next", "Ptr", snapshot, "Ptr", pe32)
            break
    }

    return pidMap
}

/**
 * Adds all child processes from pidMap to tree
 */
AddChildrenToTree(&treePIDs, pidMap) {
    prevCount := 0

    while (treePIDs.Length != prevCount) {
        prevCount := treePIDs.Length

        for pid, ppid in pidMap {
            if (IsParentInTree(ppid, treePIDs) && pid != ppid && !IsInArray(treePIDs, pid))
                treePIDs.Push(pid)
        }
    }
}

/**
 * Checks if a PID is in the tree
 */
IsParentInTree(ppid, treePIDs) {
    for treePid in treePIDs {
        if (ppid = treePid)
            return true
    }
    return false
}

/**
 * Checks if a PID exists in an array
 */
IsInArray(arr, value) {
    for item in arr {
        if (item = value)
            return true
    }
    return false
}

; ====================================================================================
; PROCESS RESTORATION
; ====================================================================================

/**
 * Restores all handled processes on script exit
 */
RestoreAllProcesses(*) {
    global handled, foregroundHookHandle

    ; Unhook the foreground window event hook
    if foregroundHookHandle {
        DllCall("User32\UnhookWinEvent", "Ptr", foregroundHookHandle)
        foregroundHookHandle := 0
    }

    for pid, info in handled {
        RestoreProcess(pid, info.priority,
            info.HasOwnProp("jobHandle") ? info.jobHandle : 0,
            info.HasOwnProp("originalAffinity") ? info.originalAffinity : 0)
    }
}

/**
 * Restores a process to its original state
 */
RestoreProcess(pid, originalPriority, jobHandle := 0, originalAffinity := 0) {
    global useIoPriority, useCpuAffinity, useCpuRateLimit, useBackgroundMode

    access := PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return false

    try {
        ; End background mode
        if useBackgroundMode
            DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", PROCESS_MODE_BACKGROUND_END)

        RestorePriority(hProc, originalPriority)
        DisablePowerThrottling(hProc)

        if useIoPriority
            RestoreIOPriority(hProc)

        if (useCpuAffinity && originalAffinity)
            DllCall("Kernel32\SetProcessAffinityMask", "Ptr", hProc, "UPtr", originalAffinity)

        if (useCpuRateLimit && jobHandle)
            DllCall("Kernel32\CloseHandle", "Ptr", jobHandle)

        return true
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

/**
 * Restores process to original priority
 */
RestorePriority(hProc, originalPriority) {
    DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", originalPriority)
}

/**
 * Disables power throttling for a process
 */
DisablePowerThrottling(hProc) {
    ppt := Buffer(12, 0)
    NumPut("UInt", 1, ppt, 0)     ; Version
    NumPut("UInt", 0x3, ppt, 4)   ; ControlMask
    NumPut("UInt", 0x0, ppt, 8)   ; StateMask (disable = 0)

    DllCall("Kernel32\SetProcessInformation", "Ptr", hProc, "Int", 4, "Ptr", ppt.Ptr, "UInt", ppt.Size, "Int")
}

/**
 * Restores I/O priority to normal
 */
RestoreIOPriority(hProc) {
    ioPriority := Buffer(4, 0)
    NumPut("UInt", 2, ioPriority, 0)  ; IoPriorityNormal = 2
    DllCall("Ntdll\NtSetInformationProcess", "Ptr", hProc, "Int", 33, "Ptr", ioPriority.Ptr, "UInt", 4)
}

; ====================================================================================
; MEMORY MANAGEMENT
; ====================================================================================

/**
 * Gets process memory usage in MB
 */
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

/**
 * Trims process memory if it exceeds threshold
 */
TrimProcessMemory(pid, thresholdMB := 100, aggressive := true, passes := 3) {
    memoryMB := GetProcessMemoryMB(pid)
    if (memoryMB < thresholdMB)
        return false

    access := PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return false

    try {
        if aggressive
            return TrimAggressively(hProc, passes)
        else
            return !!DllCall("Psapi\EmptyWorkingSet", "Ptr", hProc, "Int")
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

/**
 * Performs aggressive memory trimming with multiple passes
 */
TrimAggressively(hProc, passes) {
    DllCall("Kernel32\SetProcessWorkingSetSize", "Ptr", hProc, "Ptr", -1, "Ptr", -1)

    result := false
    loop passes {
        if DllCall("Psapi\EmptyWorkingSet", "Ptr", hProc, "Int")
            result := true
        if (A_Index < passes)
            Sleep(10)
    }

    return result
}

; ====================================================================================
; EFFICIENCY MODE APPLICATION
; ====================================================================================

/**
 * Applies Windows 11 Efficiency Mode to a process
 * Returns {success, jobHandle, originalAffinity}
 */
ApplyEfficiencyLikeMode(pid, idlePriority := false) {
    global useIoPriority, useCpuAffinity, cpuAffinityMask, useCpuRateLimit, cpuRateLimitPercent, useBackgroundMode

    access := PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return { success: false, jobHandle: 0, originalAffinity: 0 }

    jobHandle := 0
    originalAffinity := 0

    try {
        ; Enable background mode (tells Windows this is a background process)
        ; Background mode automatically lowers priority, so skip manual priority setting
        if useBackgroundMode {
            DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", PROCESS_MODE_BACKGROUND_BEGIN)
        } else {
            ; Lower priority manually
            priority := idlePriority ? IDLE_PRIORITY_CLASS : BELOW_NORMAL_PRIORITY_CLASS
            DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", priority)
        }

        ; Enable power throttling and EcoQoS
        ok := EnablePowerThrottling(hProc)

        ; Set I/O priority to very low
        if useIoPriority
            SetLowIOPriority(hProc)

        ; Restrict CPU affinity
        if useCpuAffinity
            originalAffinity := SetCPUAffinity(hProc, cpuAffinityMask)

        ; Apply CPU rate limit via job object
        if useCpuRateLimit
            jobHandle := ApplyCPURateLimit(pid, hProc, cpuRateLimitPercent)

        return { success: !!ok, jobHandle: jobHandle, originalAffinity: originalAffinity }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

/**
 * Enables Windows 11 power throttling and EcoQoS
 */
EnablePowerThrottling(hProc) {
    ppt := Buffer(12, 0)
    NumPut("UInt", 1, ppt, 0)     ; Version
    NumPut("UInt", 0x3, ppt, 4)   ; ControlMask
    NumPut("UInt", 0x3, ppt, 8)   ; StateMask

    ok := DllCall("Kernel32\SetProcessInformation", "Ptr", hProc, "Int", 4, "Ptr", ppt.Ptr, "UInt", ppt.Size, "Int")

    if ok {
        ecoQoS := Buffer(12, 0)
        NumPut("UInt", 1, ecoQoS, 0)
        NumPut("UInt", 0x3, ecoQoS, 4)
        NumPut("UInt", 0x3, ecoQoS, 8)
        DllCall("Kernel32\SetProcessInformation", "Ptr", hProc, "Int", 4, "Ptr", ecoQoS.Ptr, "UInt", ecoQoS.Size, "Int"
        )
    }

    return ok
}

/**
 * Sets I/O priority to very low
 */
SetLowIOPriority(hProc) {
    ioPriority := Buffer(4, 0)
    NumPut("UInt", 0, ioPriority, 0)  ; IoPriorityVeryLow = 0
    DllCall("Ntdll\NtSetInformationProcess", "Ptr", hProc, "Int", 33, "Ptr", ioPriority.Ptr, "UInt", 4)
}

/**
 * Restricts CPU affinity and returns original affinity
 */
SetCPUAffinity(hProc, affinityMask) {
    originalAffinity := 0
    systemAffinity := 0

    if DllCall("Kernel32\GetProcessAffinityMask", "Ptr", hProc, "UPtr*", &originalAffinity, "UPtr*", &systemAffinity)
        DllCall("Kernel32\SetProcessAffinityMask", "Ptr", hProc, "UPtr", affinityMask)

    return originalAffinity
}

/**
 * Applies CPU rate limiting via job object
 */
ApplyCPURateLimit(pid, hProc, rateLimitPercent) {
    jobHandle := DllCall("Kernel32\CreateJobObject", "Ptr", 0, "Ptr", 0, "Ptr")
    if !jobHandle
        return 0

    DllCall("Kernel32\AssignProcessToJobObject", "Ptr", jobHandle, "Ptr", hProc)

    cpuRateInfo := Buffer(16, 0)
    NumPut("UInt", 0x5, cpuRateInfo, 0)  ; ENABLE | HARD_CAP
    NumPut("UInt", rateLimitPercent * 100, cpuRateInfo, 4)  ; Rate in hundredths of percent

    DllCall("Kernel32\SetInformationJobObject", "Ptr", jobHandle, "Int", 15, "Ptr", cpuRateInfo.Ptr, "UInt",
        cpuRateInfo.Size)

    return jobHandle
}
