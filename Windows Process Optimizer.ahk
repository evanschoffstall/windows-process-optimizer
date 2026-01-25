#Requires AutoHotkey v2.0
#SingleInstance Force

targetNames := ["Flow.Launcher.exe", "CCleaner_service.exe", "svchost.exe", "WmiPrvSE.exe", "bdservicehost.exe"]
useIdlePriority := false       ; true = IDLE, false = BELOW NORMAL

handled := Map()               ; PID -> true
targetSet := Map()             ; Convert array to map for O(1) lookup
for name in targetNames
    targetSet[name] := true

; Apply to existing processes
ScanAndApplyAll()

; Set up multiple WMI watchers - one per process for maximum performance
for targetName in targetNames
    SetupProcessWatcher(targetName)

; Fallback timer (every 30s) for reliability in case WMI misses something
SetTimer(ScanAndApplyAll, 30000)

ScanAndApplyAll() {
    global targetNames, handled, useIdlePriority

    snapshot := DllCall("Kernel32\CreateToolhelp32Snapshot", "UInt", 0x2, "UInt", 0, "Ptr")
    if (snapshot = -1)
        return

    try {
        pe32 := Buffer(304, 0)
        NumPut("UInt", pe32.Size, pe32, 0)

        if DllCall("Kernel32\Process32First", "Ptr", snapshot, "Ptr", pe32) {
            loop {
                exeName := StrGet(pe32.Ptr + 44, 260, "CP0")
                if targetSet.Has(exeName) {
                    pid := NumGet(pe32, 8, "UInt")
                    if !handled.Has(pid) {
                        if ApplyEfficiencyLikeMode(pid, useIdlePriority)
                            handled[pid] := true
                    }
                }

                if !DllCall("Kernel32\Process32Next", "Ptr", snapshot, "Ptr", pe32)
                    break
            }
        }
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", snapshot)
    }
}

SetupProcessWatcher(processName) {
    global handled, useIdlePriority

    query :=
        "SELECT ProcessId FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '" processName "'"

    sink := ComObject("WbemScripting.SWbemSink")
    ComObjConnect(sink, "OnProcessCreated_")

    wmi := ComObjGet("winmgmts:\\.\root\CIMV2")
    wmi.ExecNotificationQueryAsync(sink, query)
}

OnProcessCreated_OnObjectReady(objWbemObject, objWbemAsyncContext) {
    global handled, useIdlePriority

    try {
        pid := objWbemObject.TargetInstance.ProcessId

        if !handled.Has(pid) {
            ; Try immediately, then retry once if it fails (process might not be fully initialized)
            if !ApplyEfficiencyLikeMode(pid, useIdlePriority) {
                Sleep(50)
                if ApplyEfficiencyLikeMode(pid, useIdlePriority)
                    handled[pid] := true
            } else {
                handled[pid] := true
            }
        }
    }
}

ApplyEfficiencyLikeMode(pid, idlePriority := false) {
    ; Access rights
    PROCESS_SET_INFORMATION := 0x0200
    PROCESS_QUERY_LIMITED_INFORMATION := 0x1000
    access := PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION

    hProc := DllCall("Kernel32\OpenProcess", "UInt", access, "Int", false, "UInt", pid, "Ptr")
    if !hProc
        return false

    try {
        ; 1) Lower priority
        IDLE_PRIORITY_CLASS := 0x0040
        BELOW_NORMAL_PRIORITY_CLASS := 0x4000
        pr := idlePriority ? IDLE_PRIORITY_CLASS : BELOW_NORMAL_PRIORITY_CLASS
        DllCall("Kernel32\SetPriorityClass", "Ptr", hProc, "UInt", pr)

        ; 2) Enable power throttling (execution speed) = close to Efficiency Mode
        ; PROCESS_POWER_THROTTLING_STATE:
        ;   ULONG Version;
        ;   ULONG ControlMask;
        ;   ULONG StateMask;
        ;
        ; Version = 1
        ; ControlMask bit 0x1 = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        ; StateMask   bit 0x1 enables it
        ppt := Buffer(12, 0)
        NumPut("UInt", 1, ppt, 0)  ; Version
        NumPut("UInt", 0x1, ppt, 4)  ; ControlMask
        NumPut("UInt", 0x1, ppt, 8)  ; StateMask

        ; PROCESS_INFORMATION_CLASS: ProcessPowerThrottling = 4
        ok := DllCall("Kernel32\SetProcessInformation"
            , "Ptr", hProc
            , "Int", 4
            , "Ptr", ppt.Ptr
            , "UInt", ppt.Size
            , "Int")

        return !!ok
    } finally {
        DllCall("Kernel32\CloseHandle", "Ptr", hProc)
    }
}
