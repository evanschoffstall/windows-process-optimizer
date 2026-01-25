#Requires AutoHotkey v2.0
#SingleInstance Force

; ====================================================================================
; CONFIGURATION
; ====================================================================================

; Priority Settings
useIdlePriority := false                    ; Use idle priority class (slowest) instead of below normal
useBackgroundMode := true                   ; Enable Windows background mode for better foreground responsiveness

; Memory Management
useMemoryTrimming := true                   ; Enable working set memory trimming
memoryThresholdMB := 10                     ; Only trim memory if process uses more than this many MB
useAggressiveMemory := true                 ; Use multiple trim passes for better memory reduction
memoryTrimPasses := 3                       ; Number of trim passes when aggressive mode is enabled

; CPU Management
useCpuAffinity := true                      ; Restrict processes to specific CPU cores
cpuAffinityMask := 0x03                     ; Bitmask for CPU cores (0x03 = cores 0 and 1)
useCpuRateLimit := true                     ; Enable CPU usage rate limiting via job objects
cpuRateLimitPercent := 5                    ; Maximum CPU usage percent per process

; I/O Priority
useIoPriority := true                       ; Lower I/O priority for disk/network operations

; Mode Settings
useBlacklistMode := true                    ; true = only target specific processes, false = target all except exceptions

; Process Lists
targetNames := ["CCleaner_service.exe", "svchost.exe", "WmiPrvSE.exe", "bdservicehost.exe", "downloader.exe",
    "testinitsigs.exe", "AdobeColabSync.exe"]  ; Processes to throttle when in blacklist mode
exceptions := ["Flow.Launcher.exe", "explorer.exe", "everything.exe", "yasb.exe"]  ; Processes to never throttle when in whitelist mode

; Skip Conditions
skipWindowsApps := false                    ; Skip UWP/Microsoft Store apps
skipForegroundProcess := true               ; Don't throttle the currently active window's process
skipForegroundProcessTree := true           ; Don't throttle parent/child processes of foreground app
skipExceptionProcessTree := true            ; Don't throttle parent/child processes of exception apps

; ====================================================================================
; CONSTANTS & GLOBALS
; ====================================================================================

PROCESS_QUERY_LIMITED_INFORMATION := 0x1000
PROCESS_QUERY_INFORMATION := 0x0400
PROCESS_SET_INFORMATION := 0x0200
PROCESS_SET_QUOTA := 0x0100
PROCESS_VM_READ := 0x0010
IDLE_PRIORITY_CLASS := 0x0040
BELOW_NORMAL_PRIORITY_CLASS := 0x4000
PROCESS_MODE_BACKGROUND_BEGIN := 0x00100000
PROCESS_MODE_BACKGROUND_END := 0x00200000
PROCESSENTRY32_SIZE := 304
PROCESS_BASIC_INFO_SIZE := 48
PROCESS_MEMORY_COUNTERS_SIZE := 72
PE32_PID_OFFSET := 8
PE32_PPID_OFFSET_X86 := 20
PE32_PPID_OFFSET_X64 := 28
PBI_PARENT_OFFSET_X86 := 20
PBI_PARENT_OFFSET_X64 := 40
SCAN_INTERVAL_MS := 15000
MAX_PATH_CHARS := 260

handled := Map()
currentScriptPID := DllCall("Kernel32\GetCurrentProcessId", "UInt")
currentForegroundPID := 0
foregroundHookHandle := 0
pendingForegroundChange := false

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

ScanAndApplyAll() {
    global handled, currentScriptPID
    foregroundPID := skipForegroundProcess ? GetForegroundProcessId() : 0
    foregroundTreePIDs := BuildTreeMap(foregroundPID, skipForegroundProcessTree)
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

BuildTreeMap(pid, enabled) {
    treeMap := Map()
    if (enabled && pid) {
        for _, p in GetProcessTreePIDs(pid)
            treeMap[p] := true
    }
    return treeMap
}

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
                processName := GetProcessName(pid)
                if processName {
                    for exeName in exceptions {
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

ShouldSkipProcess(pid, foregroundPID, foregroundTreePIDs, exceptionTreePIDs, &skipCounts) {
    global handled, currentScriptPID, useBlacklistMode

    if (useBlacklistMode) {
        if (!IsTargetApp(pid))
            return true
    } else {
        if (IsException(pid)) {
            skipCounts.exception++
            RestoreIfHandled(pid)
            return true
        }
        if (skipExceptionProcessTree && exceptionTreePIDs.Has(pid)) {
            RestoreIfHandled(pid)
            return true
        }
    }

    if (pid = currentScriptPID)
        return true

    if (skipWindowsApps && IsWindowsApp(pid)) {
        skipCounts.uwp++
        return true
    }

    if (skipForegroundProcess && foregroundPID && pid = foregroundPID) {
        RestoreIfHandled(pid)
        return true
    }

    if (skipForegroundProcessTree && foregroundTreePIDs.Has(pid)) {
        RestoreIfHandled(pid)
        return true
    }

    return false
}

RestoreIfHandled(pid) {
    global handled
    if handled.Has(pid) {
        info := handled[pid]
        RestoreProcess(pid, info.priority, info.HasOwnProp("jobHandle") ? info.jobHandle : 0, info.HasOwnProp(
            "originalAffinity") ? info.originalAffinity : 0)
        handled.Delete(pid)
    }
}

ProcessBackgroundApp(pid) {
    global handled, useIdlePriority, useMemoryTrimming, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses
    if !handled.Has(pid) {
        originalPriority := GetProcessPriority(pid)
        result := ApplyEfficiencyLikeMode(pid, useIdlePriority)
        if (originalPriority && result.success) {
            memTrimmed := useMemoryTrimming ? TrimProcessMemory(pid, memoryThresholdMB, useAggressiveMemory,
                memoryTrimPasses) : false
            handled[pid] := { priority: originalPriority, throttled: true, memoryTrimmed: memTrimmed, jobHandle: result
                .jobHandle, originalAffinity: result.originalAffinity }
        }
    } else if (useMemoryTrimming && handled.Has(pid))
        TrimProcessMemory(pid, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses)
}

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
    treeSize := skipForegroundProcessTree ? GetProcessTreePIDs(foregroundPID).Length : (skipForegroundProcess ? 1 : 0)
    totalSkipped := uwpCount + treeSize + exceptionCount
    tooltip := "Keep ALL Apps Efficient`nMode: " . (useBlacklistMode ? "Blacklist (Target Only)" :
        "Whitelist (All Except)")
    if skipForegroundProcess
        tooltip .= "`nForeground: " . foregroundName . " (PID: " . foregroundPID . ")"
    tooltip .= "`nThrottled: " . throttledCount . "`nSkipped: " . totalSkipped
    A_IconTip := tooltip
}

SetupProcessWatcher() {
    query := "SELECT ProcessId FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
    sink := ComObject("WbemScripting.SWbemSink")
    ComObjConnect(sink, "OnProcessCreated_")
    wmi := ComObjGet("winmgmts:\\.\root\CIMV2")
    wmi.ExecNotificationQueryAsync(sink, query)
}

SetupForegroundWatcher() {
    global foregroundHookHandle, currentForegroundPID
    callback := CallbackCreate(OnForegroundWindowChanged, "F", 7)
    foregroundHookHandle := DllCall("User32\SetWinEventHook", "UInt", 0x0003, "UInt", 0x0003, "Ptr", 0, "Ptr", callback,
        "UInt", 0, "UInt", 0, "UInt", 0x0002, "Ptr")
    currentForegroundPID := GetForegroundProcessId()
}

OnForegroundWindowChanged(hWinEventHook, event, hwnd, idObject, idChild, idEventThread, dwmsEventTime) {
    global currentForegroundPID, skipForegroundProcess, pendingForegroundChange
    if !skipForegroundProcess
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

ProcessForegroundChange() {
    global pendingForegroundChange, currentForegroundPID, handled
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
        ApplyToProcessList(skipForegroundProcessTree ? GetProcessTreePIDs(oldPID) : [oldPID])
    if newPID
        RestoreProcessList(skipForegroundProcessTree ? GetProcessTreePIDs(newPID) : [newPID])
    UpdateTrayTooltip()
}

ApplyToProcessList(pidList) {
    global handled, useIdlePriority, useMemoryTrimming, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses,
        currentScriptPID, useBlacklistMode
    for _, targetPID in pidList {
        if (targetPID = currentScriptPID || (skipWindowsApps && IsWindowsApp(targetPID)))
            continue
        if (useBlacklistMode && !IsTargetApp(targetPID))
            continue
        if (!useBlacklistMode && IsException(targetPID))
            continue
        if !handled.Has(targetPID) {
            originalPriority := GetProcessPriority(targetPID)
            result := ApplyEfficiencyLikeMode(targetPID, useIdlePriority)
            if (originalPriority && result.success) {
                memTrimmed := useMemoryTrimming ? TrimProcessMemory(targetPID, memoryThresholdMB, useAggressiveMemory,
                    memoryTrimPasses) : false
                handled[targetPID] := { priority: originalPriority, throttled: true, memoryTrimmed: memTrimmed,
                    jobHandle: result.jobHandle, originalAffinity: result.originalAffinity }
            }
        }
    }
}

RestoreProcessList(pidList) {
    for _, targetPID in pidList
        RestoreIfHandled(targetPID)
}

OnProcessCreated_OnObjectReady(objWbemObject, objWbemAsyncContext) {
    global currentScriptPID, skipWindowsApps, skipForegroundProcess, handled, useIdlePriority, useBlacklistMode
    global useMemoryTrimming, memoryThresholdMB, useAggressiveMemory, memoryTrimPasses
    try {
        pid := objWbemObject.TargetInstance.ProcessId
        if (pid = currentScriptPID || (skipWindowsApps && IsWindowsApp(pid)) || (skipForegroundProcess && pid =
            GetForegroundProcessId()) || handled.Has(pid))
            return
        if (useBlacklistMode && !IsTargetApp(pid))
            return
        if (!useBlacklistMode && IsException(pid))
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
            memTrimmed := useMemoryTrimming ? TrimProcessMemory(pid, memoryThresholdMB, useAggressiveMemory,
                memoryTrimPasses) : false
            handled[pid] := { priority: originalPriority, throttled: true, memoryTrimmed: memTrimmed, jobHandle: result
                .jobHandle, originalAffinity: result.originalAffinity }
        }
    }
}

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

GetForegroundProcessId() {
    hWnd := DllCall("User32\GetForegroundWindow", "Ptr")
    if !hWnd
        return 0
    pid := 0
    DllCall("User32\GetWindowThreadProcessId", "Ptr", hWnd, "UInt*", &pid)
    return pid
}

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

ArrayHas(arr, value) {
    for item in arr {
        if (item = value)
            return true
    }
    return false
}

RestoreAllProcesses(*) {
    global handled, foregroundHookHandle
    if foregroundHookHandle {
        DllCall("User32\UnhookWinEvent", "Ptr", foregroundHookHandle)
        foregroundHookHandle := 0
    }
    for pid, info in handled {
        RestoreProcess(pid, info.priority, info.HasOwnProp("jobHandle") ? info.jobHandle : 0, info.HasOwnProp(
            "originalAffinity") ? info.originalAffinity : 0)
    }
}

RestoreProcess(pid, originalPriority, jobHandle := 0, originalAffinity := 0) {
    global useIoPriority, useCpuAffinity, useCpuRateLimit, useBackgroundMode
    access := PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return false
    try {
        if useBackgroundMode
            DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", PROCESS_MODE_BACKGROUND_END)
        DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", originalPriority)
        ppt := Buffer(12, 0)
        NumPut("UInt", 1, ppt, 0), NumPut("UInt", 0x3, ppt, 4), NumPut("UInt", 0x0, ppt, 8)
        DllCall("Kernel32\SetProcessInformation", "Ptr", hProc, "Int", 4, "Ptr", ppt.Ptr, "UInt", ppt.Size, "Int")
        if useIoPriority {
            ioPriority := Buffer(4, 0)
            NumPut("UInt", 2, ioPriority, 0)
            DllCall("Ntdll\NtSetInformationProcess", "Ptr", hProc, "Int", 33, "Ptr", ioPriority.Ptr, "UInt", 4)
        }
        if (useCpuAffinity && originalAffinity)
            DllCall("Kernel32\SetProcessAffinityMask", "Ptr", hProc, "UPtr", originalAffinity)
        if (useCpuRateLimit && jobHandle)
            DllCall("Kernel32\CloseHandle", "Ptr", jobHandle)
        return true
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}

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

ApplyEfficiencyLikeMode(pid, idlePriority := false) {
    global useIoPriority, useCpuAffinity, cpuAffinityMask, useCpuRateLimit, cpuRateLimitPercent, useBackgroundMode
    access := PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION
    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return { success: false, jobHandle: 0, originalAffinity: 0 }
    jobHandle := 0, originalAffinity := 0
    try {
        if useBackgroundMode
            DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", PROCESS_MODE_BACKGROUND_BEGIN)
        else {
            priority := idlePriority ? IDLE_PRIORITY_CLASS : BELOW_NORMAL_PRIORITY_CLASS
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
        if useIoPriority {
            ioPriority := Buffer(4, 0)
            NumPut("UInt", 0, ioPriority, 0)
            DllCall("Ntdll\NtSetInformationProcess", "Ptr", hProc, "Int", 33, "Ptr", ioPriority.Ptr, "UInt", 4)
        }
        if useCpuAffinity {
            systemAffinity := 0
            if DllCall("Kernel32\GetProcessAffinityMask", "Ptr", hProc, "UPtr*", &originalAffinity, "UPtr*", &
                systemAffinity)
                DllCall("Kernel32\SetProcessAffinityMask", "Ptr", hProc, "UPtr", cpuAffinityMask)
        }
        if useCpuRateLimit {
            jobHandle := DllCall("Kernel32\CreateJobObject", "Ptr", 0, "Ptr", 0, "Ptr")
            if jobHandle {
                DllCall("Kernel32\AssignProcessToJobObject", "Ptr", jobHandle, "Ptr", hProc)
                cpuRateInfo := Buffer(16, 0)
                NumPut("UInt", 0x5, cpuRateInfo, 0), NumPut("UInt", cpuRateLimitPercent * 100, cpuRateInfo, 4)
                DllCall("Kernel32\SetInformationJobObject", "Ptr", jobHandle, "Int", 15, "Ptr", cpuRateInfo.Ptr, "UInt",
                    cpuRateInfo.Size)
            }
        }
        return { success: !!ok, jobHandle: jobHandle, originalAffinity: originalAffinity }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}
