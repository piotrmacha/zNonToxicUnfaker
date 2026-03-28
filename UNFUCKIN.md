# zNonToxicUnfaker — Othello 4.3.5 Patch Documentation

This document covers the complete reverse engineering investigation that produced
the working patch for Othello 4.3.5. It is intended for contributors who need to
update the patch for future Othello versions, and as a record of everything that
was tried, why it failed, and how the solution was eventually found.

---

## Background

**Gothic 1** has no native mod support. **Union** (`shw32.dll`) is a third-party
plugin loader that injects into the game process and loads `.vdf` plugin packages.

**Othello 4.3.5** is a large gameplay overhaul mod that ships its own modified
version of Union (also named `shw32.dll`) and an additional protection DLL called
`OTHELLO_ABI.DLL` (embedded inside `ScriptsOthello4.0.vdf` under
`System/Autorun`). Together these two files implement a plugin blocking system
that prevents arbitrary Union plugins from loading alongside Othello.

The original `zNonToxicUnfaker` patcher was written for Othello 3.6.10. Its
offsets were completely wrong for 4.3.5 and served only as a starting point for
the investigation described here.

---

## Tools Used

| Tool | Purpose |
| ------ | --------- |
| **x32dbg** (with TitanEngine) | Runtime debugging, breakpoints, call stack capture, memory inspection |
| **IDA Free** | Static analysis of the decrypted in-memory `OTHELLO_ABI.DLL` image |
| **HxD** | Hex editor — ultimately useless here due to packing (see below) |
| **Gothic VDF Tool** | Extracting `OTHELLO_ABI.DLL` from the VDF archive for IDA |
| **DebugView** | Capturing `OutputDebugStringA` log output during early investigation |

---

## Critical Facts That Must Be Understood Before Any Future Work

### The DLL is packed on disk

`OTHELLO_ABI.DLL` is encrypted/packed in its on-disk form inside the VDF.
The bytes visible in HxD on the raw file **do not match** the decrypted bytes
that IDA and x32dbg see at runtime. **File-offset patching in HxD does not
work.** All patching must be done at runtime against the in-memory image.

IDA analyzes the correct decrypted image because it was extracted from VDF and
loaded — the unpacking stub runs and decrypts it before IDA's analysis.

### ASLR is active

`OTHELLO_ABI.DLL` loads at a different base address every session. The base seen
in the log files (`60750000`, `5BEB0000`, `5CC70000`, etc.) changes each run.

**Offset calculation formula:**

```asm
file_offset = runtime_address − runtime_base
IDA_address = 0x10000000 + file_offset
```

Example from one session:

```asm
runtime_base    = 0x5CC70000
runtime_address = 0x5CC83D69
file_offset     = 0x5CC83D69 − 0x5CC70000 = 0x13D69
IDA_address     = 0x10000000 + 0x13D69 = 0x10013D69
```

Always confirm the current base in x32dbg Memory Map before calculating any
offset. Never hardcode a runtime address.

---

## Architecture of the Blocking System

### Two independent mechanisms in OTHELLO_ABI.DLL

**Mechanism 1 — Hardcoded fatal blocklist** (not our target)

Triggered for specific bundled DLL names: `ZBINKFIX.DLL`,
`UNION_HOTBAR_1.OK.DLL`, `UNION_QUICKLOOT.DLL`, `ZUTILITIES.DLL`,
`ZUNIONUTILS.DLL`. Shows the message:

> Can't run the game because detected unsupported X plugin that cannot be patched

Calls `quick_exit` immediately. These are Othello's own bundled replacements and
this message never fires during normal use.

**Mechanism 2 — Dynamic FNV-1a whitelist checker** (our target)

Located in `sub_1004AD50` and several structurally identical sibling functions.
Shows the message:

> Remove the following unsupported plugins: X.DLL

Uses **MessageBoxW** (Unicode), not MessageBoxA. Called via dynamically resolved
function pointer obtained through `GetProcAddress` — there is no direct import.
Calls `quick_exit` after dismissal.

### The random dispatcher — the key discovery

The outer function `sub_1004BEF0` (IDA offset `0x4BEF0`) selects one of several
plugin-checker routines at runtime using a function-pointer table
(`funcs_1004BF79`) and dispatches via `call eax` at IDA address `0x1004BF79`
(file offset `0x4BF79`). This means:

- There are multiple structurally identical checker functions.
- Each run may invoke a different one.
- Patching any single checker left other checkers functional.
- All of them are reachable exclusively through this one `call eax` instruction.

Confirmed checkers identified during investigation:

- `sub_1004AD50` — visible in early x32dbg call stacks
- `sub_10046FA0` — appeared in later call stacks after `sub_1004AD50` was patched

### The FNV-1a hash check (inside each checker)

Each checker iterates the loaded plugin list, hashes each DLL filename with
FNV-1a (initial value `0x811C9DC5`, prime `0x01000193`), and looks up the hash
in a table at `dword_1013EC00`. If not found, the plugin is blocked.

```asm
; FNV-1a hash loop (from sub_1004AD50 and sub_10046FA0)
imul edx, ecx, 1000193h   ; FNV prime multiplication
```

The hash table is a whitelist — only known-approved plugin hashes are stored.
Every unknown plugin fails the lookup and enters the error-building path.

### The MessageBoxW caller (`sub_10013B40`, offset `0x13B40`)

This is a shared function called by all checkers to show the error dialog. It:

1. Resolves `MessageBoxW` via `GetProcAddress` at runtime (hence no import).
2. Calls `ShowCursor`, `ClipCursor`, and `ShowWindow` to prepare the UI.
3. Calls `edi` (the resolved `MessageBoxW`).
4. Falls through to cleanup on return.

The important consequence: **ShowWindow is called before MessageBoxW**. This is
why suppressing MessageBoxW alone still caused the game window to hide — the
window-hiding code runs unconditionally regardless of whether the dialog
actually displays.

---

## What Was Attempted and Why It Failed

### shw32.dll ordinal 1325 (PluginIsIgnored)

**What:** Patched `PluginIsIgnored` (ordinal 1325 in Othello's modified `shw32.dll`)
to always return 0 or 1.

**Why it failed:** `PluginIsIgnored` returns `0` for every plugin tested,
including blocked and allowed ones. It is not part of the blocking path at all.
Patching it caused stack corruption (wrong `ret` argument size) or had no effect.

**Do not revisit.**

### MessageBoxA hook

**What:** Installed a detour on `MessageBoxA` to intercept the error.

**Why it failed:** The plugin checker uses `MessageBoxW` (Unicode), resolved
dynamically via `GetProcAddress`. `MessageBoxA` is never called in this path.

### File-offset patches in HxD

**What:** Attempted to patch specific bytes in the raw `OTHELLO_ABI.DLL` file.

**Why it failed:** The DLL is packed on disk. Raw file bytes do not match the
decrypted in-memory image. IDA and x32dbg see the decrypted image; HxD sees
ciphertext.

### Patch 0x13D69 alone (je → jmp)

**What:** Converted the `je` at `0x13D69` (inside `sub_10013B40`) to an
unconditional `jmp`, skipping the MessageBoxW call.

**Why it failed:** This skips the dialog but not `ShowWindow` and the error-path
setup code that runs before it. The game window hides, `quick_exit` still fires,
and the process hangs with music playing.

### Patch 0x4B114 alone (jnz → jmp)

**What:** Forced the post-loop branch in `sub_1004AD50` to always jump to the
safe-exit label `loc_1004B55B`.

**Why it failed:** `loc_1004B55B` contains MSVC string buffer cleanup code. When
entered from an unintended path with uninitialised string objects, the buffer
integrity check (`cmp ecx, 0Fh`) fails and `_invoke_watson` is called, causing
a silent crash. Additionally, this only patched `sub_1004AD50`; other checkers
selected by the dispatcher still ran normally.

### Patch 0x4B03D (jnz → jmp) — force all plugins to appear whitelisted

**What:** Unconditionally jumped to `loc_1004B0F3` (the "hash found" path) after
the hash lookup, making every plugin appear whitelisted.

**Why it was insufficient alone:** The flag at `[ebp-11h]` is never set when the
error-building code path is entered, so `cmp [ebp-11h], 0` at `0x4B110` still
evaluates as "no blocked plugins" and the error block at `0x4B11A` runs anyway.
`0x4B03D` must be combined with `0x4B114` to be effective — but `0x4B114`
causes the `_invoke_watson` crash (see above). Neither alone nor together did
these fully solve the problem because sibling checker functions were unaffected.

### NOPing quick_exit (IAT patch and direct NOP)

**What:** Replaced the IAT entry for `quick_exit` with a no-op stub, and
separately replaced the `call ds:quick_exit` instruction with NOPs.

**Why it failed:** Suppressing `quick_exit` allows execution to continue past
the error block, but the error block has already called `ShowWindow` to hide the
game window. The process then runs in a broken state with music but no window.

### MessageBoxW hook (return IDOK automatically)

**What:** Installed a detour on `MessageBoxW` to silently return `IDOK`.

**Why it was insufficient:** The window-hiding `ShowWindow` call in
`sub_10013B40` executes before `MessageBoxW` is called. Suppressing the dialog
does not prevent the window from being hidden. The hang persisted.

### 0x4B046 NOP (prevent flag clear)

**What:** NOPed the `mov byte ptr [ebp-11h], 0` instruction that clears the
"blocked plugin found" flag.

**Why it crashed:** The instruction at `0x4B049` — immediately after the
3-byte NOP region — attempts to write through a pointer that was supposed to be
initialized by the removed instruction. This produced an access violation at
`0x900FA505` (null pointer dereference).

---

## The Working Solution

### Two patches, applied to OTHELLO_ABI.DLL at runtime

#### Patch 1 — Skip blocklist registration

```asm
Offset:      0x5FF8A
Before:      74 09  (je +9)
After:       EB 09  (jmp +9)
```

Prevents our plugin's DLL name from being registered in whatever structure the
blocklist-building code populates. This means our name does not appear in the
error message string. Not strictly required for the bypass but keeps the output
clean.

#### Patch 2 — NOP the checker dispatcher

```asm
Offset:      0x4BF79
Before:      FF D0  (call eax)
After:       90 90  (NOP NOP)
```

`sub_1004BEF0` selects a plugin-checker routine through `funcs_1004BF79` and
invokes it here. Because all checker variants are called exclusively through
this single indirect call, two NOPs permanently disable the entire checking
system regardless of which checker the dispatcher would have chosen. No checker
runs, no error is built, no `quick_exit` is called, no window is hidden.

This is the correct level to patch. It is above the individual checkers and
above the dispatcher's random-selection logic, making it robust against any
future addition of new checker variants.

---

## How to Update the Patch for a New Othello Version

If Othello is updated and the patches stop working (the log will show `MISS` for
offset `0x4BF79`), follow this procedure:

### Step 1 — Identify the new base address

Launch the game in x32dbg. Go to **Memory Map**. Find `OTHELLO_ABI.DLL` and
note its base address (e.g. `5CC70000`). This changes every session.

### Step 2 — Break on MessageBoxW

Set a breakpoint on `MessageBoxW` in `user32.dll` (not MessageBoxA). Let the
game run until the plugin error dialog appears. The debugger will pause.

### Step 3 — Read the call stack

Go to the **Call Stack** tab. Find the frame inside `OTHELLO_ABI.DLL` that
is closest to `user32.MessageBoxW`. Note its runtime address.

### Step 4 — Locate the new dispatcher

Walk up the call stack until you find a frame in `OTHELLO_ABI.DLL` that is NOT
inside `sub_10013B40` (the MessageBoxW caller) and NOT inside the checker
function directly. This outer frame is the dispatcher equivalent.

Convert the dispatcher's `call eax` runtime address to a file offset:

```asm
new_offset = runtime_address − runtime_base
```

Verify in IDA at `0x10000000 + new_offset` that you see `call eax` (`FF D0`).

### Step 5 — Update the patch table

Replace `0x4BF79` in `k_OthelloPatches` with the new offset. The expected bytes
remain `FF D0` and the replacement remains `90 90` as long as the dispatcher
still uses an indirect `call eax`. If it uses a different calling convention,
adjust accordingly.

### Step 6 — Verify Patch 1 (0x5FF8A) still applies

Check the log. If `0x5FF8A` shows `MISS`, find the new blocklist registration
jump using IDA by searching for the string construction code near the error
message text.

---

## Confirmed Dead Ends — Do Not Revisit

- `shw32.dll` ordinal 1325 (`PluginIsIgnored`) — irrelevant, returns 0 for all plugins
- `shw32.dll` ordinal 1324 (`PluginIsUnIgnored`) — not called in blocking path
- `shw32.dll` ordinal 754 (`AddIgnoredAdaptiveFunction`) — call count = 0
- `MessageBoxA` — plugin error uses `MessageBoxW` exclusively
- TLS callback — loop body executes zero times
- File-offset patching in HxD — DLL is packed on disk
- Hooking `MessageBoxW` alone — window hides before dialog shows
- Patching `quick_exit` IAT or call site alone — window still hides
- Patches targeting only a single checker (`sub_1004AD50` or `sub_10046FA0`) — dispatcher selects others
- DLL rename to avoid the blocklist — confirmed whitelist, all unknown names blocked

---

## Logging

The patcher writes a log file (`unfaker.txt`) next to the plugin DLL. A
successful run looks like:

```asm
[Unfaker] Started.
[Unfaker] Patching OTHELLO_ABI.DLL at 60750000
  -> @0005FF8A: OK
  -> @0004BF79: OK
```

If either offset shows `MISS`, the Othello version has changed and the offsets
need to be updated following the procedure above.
