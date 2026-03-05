<div align="center">

<br/>

<h1>Windows Process Optimizer</h1>

<p><em>Your CPU. Your rules. Zero background waste.</em></p>

<p>
  <a href="https://www.autohotkey.com"><img src="https://img.shields.io/badge/AutoHotkey-v2.0-334455?style=for-the-badge&logo=autohotkey&logoColor=white" alt="AutoHotkey v2.0" /></a>
  <a href="https://www.microsoft.com/windows"><img src="https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows 10/11" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge" alt="MIT License" /></a>
</p>

<p>An AutoHotkey v2 script that automatically throttles background processes<br/>to free up CPU, memory, and I/O for whatever you're actually using right now.</p>

<br/>

</div>

---

## What is Windows Process Optimizer?

Windows Process Optimizer is a **background automation script** that continuously monitors your running processes and applies aggressive resource constraints to anything you're not actively using. The moment you switch to a new window, the old process gets throttled and your new foreground app gets its resources back — instantly.

It works in two modes: **whitelist** (throttle everything except trusted apps) or **blacklist** (only throttle specific targets). Every constraint is fully configurable per-process, and all changes are automatically reversed when you close the script.

---

## Features

|     | Feature                         | Description                                                      |
| --- | ------------------------------- | ---------------------------------------------------------------- |
| 🎯  | **Whitelist & blacklist modes** | Throttle all-except or only-listed processes                     |
| ⚡  | **CPU priority reduction**      | Drop background processes to idle or below-normal priority       |
| 🧠  | **Windows background mode**     | Enable OS-level background scheduling for better responsiveness  |
| 🗜️  | **Memory trimming**             | Reclaim working set RAM with optional multi-pass aggressive mode |
| 🔢  | **CPU affinity control**        | Pin background processes to specific cores via bitmask           |
| 📉  | **CPU rate limiting**           | Cap per-process CPU usage via Windows job objects                |
| 💾  | **I/O priority lowering**       | Reduce disk and network priority for background processes        |
| 🛑  | **Suspend cycles**              | Periodically suspend/resume for extreme throttling               |
| 📋  | **Page & working set limits**   | Lower memory page priority and cap maximum working set size      |
| 🖥️  | **Foreground awareness**        | Always skips the active window and its entire process tree       |
| 🔊  | **A/V output protection**       | Never throttles processes with active audio or video output      |
| 🏪  | **UWP app awareness**           | Automatically skips Microsoft Store / UWP apps                   |
| ⚙️  | **Per-process overrides**       | Fine-tune every setting individually for any process name        |
| 🔄  | **Live process watching**       | WMI subscription throttles newly spawned processes immediately   |
| 🔁  | **Auto-restore on exit**        | All processes are returned to their original state when you quit |

---

## Requirements

- Windows 10 or 11
- [AutoHotkey v2.0](https://www.autohotkey.com/download/) or later
- Administrator privileges (required for priority and affinity changes)

---

## Quick Start

### 1 · Install AutoHotkey

Download and install **AutoHotkey v2** from [autohotkey.com](https://www.autohotkey.com/download/).

### 2 · Run the script

Right-click `Windows Process Optimizer.ahk` and select **Run as administrator**.

A tray icon will appear. The script immediately begins scanning and throttling background processes on a 15-second interval.

### 3 · Configure to your needs

Open the script in any text editor and edit the `CONFIG` object at the top of the file:

```ahk
global CONFIG := {
    mode: "whitelist",               ; "whitelist" = throttle all except listed
                                     ; "blacklist" = only throttle listed targets
    skipWindowsApps: true,           ; Skip UWP / Microsoft Store apps
    skipForegroundProcess: true,     ; Never throttle the active window's process
    skipForegroundProcessTree: true, ; Never throttle the foreground process tree
    skipAvOutputProcesses: true,     ; Skip processes with active audio/video output
    ...
}
```

### 4 · Add exceptions (whitelist mode)

List any processes that should never be throttled:

```ahk
exceptions: [
    "explorer.exe",
    "Flow.Launcher.exe",
    "yasb.exe"
]
```

### 5 · Add targets (blacklist mode)

List specific processes to throttle, with optional per-process overrides:

```ahk
targets: [
    "Taskmgr.exe",
    {
        names: ["svchost.exe", "WmiPrvSE.exe"],
        useCpuRateLimit: true,
        cpuRateLimitPercent: 1,
        useSuspendCycles: true,
        suspendDurationMs: 2000,
        resumeDurationMs: 20
    }
]
```

---

## Configuration Reference

### Global Settings

| Setting                     | Default       | Description                                       |
| --------------------------- | ------------- | ------------------------------------------------- |
| `mode`                      | `"whitelist"` | Operating mode: `"whitelist"` or `"blacklist"`    |
| `skipWindowsApps`           | `true`        | Skip UWP / Microsoft Store apps                   |
| `skipForegroundProcess`     | `true`        | Skip the currently active window's process        |
| `skipForegroundProcessTree` | `true`        | Skip parent/child processes of the foreground app |
| `skipExceptionProcessTree`  | `true`        | Skip parent/child processes of excepted apps      |
| `skipAvOutputProcesses`     | `true`        | Skip processes with active audio or video output  |
| `skipAvOutputProcessTree`   | `true`        | Skip parent/child processes of active A/V apps    |

### Per-Process Settings (defaults & overrides)

| Setting               | Default | Description                                                |
| --------------------- | ------- | ---------------------------------------------------------- |
| `enabled`             | `true`  | Whether throttling applies to this process                 |
| `useIdlePriority`     | `true`  | Use idle priority class instead of below-normal            |
| `useBackgroundMode`   | `true`  | Enable Windows background processing mode                  |
| `useMemoryTrimming`   | `true`  | Trim working set memory                                    |
| `memoryThresholdMB`   | `10`    | Minimum process memory (MB) before trimming applies        |
| `useAggressiveMemory` | `true`  | Run multiple trim passes for greater memory reduction      |
| `memoryTrimPasses`    | `3`     | Number of trim passes when aggressive mode is on           |
| `useCpuAffinity`      | `true`  | Restrict process to specific CPU cores                     |
| `cpuAffinityMask`     | `0x03`  | Core bitmask (`0x03` = cores 0 and 1)                      |
| `useCpuRateLimit`     | `true`  | Cap CPU usage via Windows job object                       |
| `cpuRateLimitPercent` | `5`     | Maximum CPU % allowed per process                          |
| `useIoPriority`       | `true`  | Lower I/O priority for disk and network operations         |
| `useSuspendCycles`    | `false` | Periodically suspend/resume _(extreme — use with caution)_ |
| `suspendDurationMs`   | `100`   | Milliseconds to keep process suspended per cycle           |
| `resumeDurationMs`    | `50`    | Milliseconds to allow process to run between suspends      |
| `usePagePriority`     | `false` | Lower memory page priority                                 |
| `pagePriority`        | `1`     | Page priority level (1 = very low, 5 = normal)             |
| `useSingleCore`       | `false` | Force process onto a single CPU core                       |
| `singleCoreIndex`     | `0`     | Which core to use when `useSingleCore` is true (0-based)   |
| `useWorkingSetLimit`  | `false` | Hard-cap maximum working set size                          |
| `workingSetLimitMB`   | `10`    | Maximum working set in MB                                  |
| `useSchedulingClass`  | `false` | Set thread scheduling class to lowest                      |
| `schedulingClass`     | `0`     | Scheduling class (0 = lowest, 9 = highest)                 |

---

## Tray Icon

The system tray icon provides live status and quick controls.

| Tray Menu Item         | Description                                    |
| ---------------------- | ---------------------------------------------- |
| **Suspend Throttling** | Pause all throttling and restore every process |
| **Exit**               | Restore all processes and quit                 |

Hovering the tray icon shows current mode, foreground process, throttled count, and skipped count.

---

## How It Works

1. **On launch** — scans all running processes and applies throttling to eligible ones.
2. **Every 15 seconds** — re-scans to catch any processes that changed state.
3. **On foreground change** — immediately restores the new active process tree and throttles the previous one.
4. **On new process creation** — a WMI subscription fires within ~1 second to throttle newly spawned processes.
5. **On exit** — every modified process is restored to its original priority, affinity, and mode.

---

<div align="center">

Made with ❤️ by [Evan Schoffstall](https://github.com/evanschoffstall)

MIT License · Free forever · Use it as you see fit

</div>
