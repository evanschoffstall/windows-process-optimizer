<div align="center">

<br/>

<h1>Windows Process Optimizer</h1>

<p><em>Give your active app more breathing room</em></p>

<p>
  <a href="https://www.autohotkey.com"><img src="https://img.shields.io/badge/AutoHotkey-v2-334455?style=for-the-badge&logo=autohotkey&logoColor=white" alt="AutoHotkey v2" /></a>
  <a href="https://www.microsoft.com/windows"><img src="https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows 10/11" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge" alt="MIT License" /></a>
</p>

</div>

---

Windows Process Optimizer is an AutoHotkey v2 script for Windows 10/11.

It gives fewer computer resources to apps you are not using, so the app in front
of you can access sufficent resources.

## What It Does

- Watches which window you are using.
- Skips the active app by default.
- Slows down background apps you choose.
- Can lower CPU, memory, disk, and scheduling priority.
- Can restore changed processes when you pause or exit.

## Requirements

- Windows 10 or 11
- [AutoHotkey v2](https://www.autohotkey.com/download/)
- Administrator mode

## Quick Start

1. Install AutoHotkey v2.
2. Right-click `Windows Process Optimizer.ahk`.
3. Choose **Run as administrator**.
4. Use the tray icon to pause or exit.

## Choose a Mode

Open `Windows Process Optimizer.ahk` and edit `CONFIG` near the top.

Use whitelist mode when you want to throttle almost everything:

```ahk
mode: "whitelist"
```

In whitelist mode, add apps you never want slowed down to `exceptions`:

```ahk
exceptions: [
    "explorer.exe",
    "Flow.Launcher.exe",
    "AutoHotkey64.exe"
]
```

Use blacklist mode when you only want to throttle specific apps:

```ahk
mode: "blacklist"
```

In blacklist mode, add apps to `targets`:

```ahk
targets: [
    "Taskmgr.exe",
    "downloader.exe"
]
```

## Common Settings

Most people may only need these:

- `mode`: choose `"whitelist"` or `"blacklist"`.
- `exceptions`: apps that should never be slowed down.
- `targets`: apps that should be slowed down in blacklist mode.
- `cpuRateLimitPercent`: max CPU percent for throttled apps.
- `cpuAffinityMask`: CPU cores throttled apps may use.
- `useSuspendCycles`: extra harsh throttling. Leave this off unless you really
  need it.

## Default Safety Skips

The script is set up to avoid obvious bad ideas:

- It skips the app you are actively using.
- It skips the active app's process tree.
- It skips Microsoft Store / UWP apps.
- It skips apps with active audio or video output.

You can change these in `CONFIG`, but the defaults are safer.

## Notes

- Background apps may become slow. That is the point.
- Some apps may behave badly if throttled too hard.
- Pause or exit from the tray icon to restore changed processes.

---

<div align="center">

Made with ❤️ by [Evan Schoffstall](https://github.com/evanschoffstall)

</div>
