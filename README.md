# KernelMinHook

KernelMinHook is a small kernel-mode hooking library written in C.

As the name suggests, the project was initially inspired by MinHook, but adapted here as a kernel-oriented implementation focused on lower-level behavior, trampoline building, code cave reuse, and protected patching.

I built it as a low-level project to better understand how trampoline-based hooks work in kernel space: finding room for a relay, relocating overwritten instructions, patching protected code safely, and restoring the original bytes cleanly.

The codebase is intentionally compact. The goal is not to build a huge framework, but to keep the core mechanics visible and easy to follow.

---

## Overview

This project covers the main pieces of a minimal hook engine in kernel mode:

- hook creation and removal
- trampoline generation
- prologue relocation
- nearby code cave reuse
- MDL-backed patching
- runtime enable / disable
- queued hook state application

It is mainly meant as a technical study project and as a clean reference for low-level Windows internals work.

---

## Architecture Diagram
<img width="1726" height="1046" alt="image" src="https://github.com/user-attachments/assets/b91d86f3-d14a-4796-8463-90e7b7bdc5a1" />





How to use it your code ! ( simple as minhook) :) 

<img width="1695" height="458" alt="image" src="https://github.com/user-attachments/assets/0a270a43-213b-4871-b1d7-932d412811f7" />


---

## How it works

The flow is simple:

1. initialize the hook manager
2. register a target function and a detour
3. find a usable executable buffer near the target
4. disassemble and relocate the overwritten instructions
5. build a trampoline
6. patch the target entry
7. enable, disable, or remove the hook when needed

The idea is to keep the implementation small while still covering the parts that actually matter in a trampoline-based detour system.

---

## Project structure

### hook.c

This is the main hook manager.

It handles:

- initialization and cleanup
- hook registration
- hook removal
- enable / disable
- queued state changes
- backup and restoration of patched bytes
- internal hook entry storage

### buffer.c

This file handles executable buffer reuse.

It is responsible for:

- scanning memory near the target
- finding reusable code cave regions
- tracking allocated trampoline slots
- releasing and resetting used regions

### trampoline.c

This is where the trampoline is built.

It handles:

- instruction decoding
- relocation of overwritten instructions
- branch rewriting
- x64 RIP-relative fixups
- relay generation
- patch-above fallback when the target prologue is too small

### hde/

This folder contains the lightweight disassembler used by the trampoline builder.

---

## Notes on the implementation

### Code cave reuse

Instead of relying on a separate executable allocation path, the library looks for nearby padding regions that can be reused as trampoline storage.

Typical byte patterns include:

- `0xCC`
- `0x90`
- `0x00`

This keeps the trampoline close to the original target and keeps the implementation simple.

### MDL-backed patching

Patching is done through an MDL-based workflow using routines such as:

- `IoAllocateMdl`
- `MmProbeAndLockPages`
- `MmMapLockedPagesSpecifyCache`
- `MmProtectMdlSystemAddress`

That gives a controlled writable mapping before writing patch bytes.

### Trampoline relocation

The trampoline builder copies the original instructions into a temporary buffer and fixes what needs to be fixed before writing the final relay.

That includes:

- relative calls
- direct and short jumps
- conditional branches
- RIP-relative adjustments on x64

### Patch-above support

If the target prologue is too small to patch directly, the code can fall back to a patch-above strategy when the surrounding bytes allow it.

---

## Compatibility

This project has been tested and validated on Windows 10.

Windows 11 compatibility is not fully confirmed yet and may require additional validation depending on the target build and execution context.

---

## Why I made this

I wanted a minimal codebase that stays close to the actual mechanics of hooking, without hiding everything behind layers of abstraction.

This project gave me a clean way to work on:

- instruction relocation
- trampoline layout
- protected code patching
- hook lifecycle management
- low-level Windows systems internals

---

## Technical highlights

- written in C
- kernel-mode oriented
- inspired by MinHook
- x86 / x64 support
- trampoline-based redirection
- relocation-aware patching
- nearby executable buffer reuse
- MDL-backed writes
- compact internal hook table
- tagged pool allocations

---

## Current limitations

This repository is intentionally small, so a few things are still minimal:

- status strings are not fully implemented
- diagnostics are lightweight
- some relocation edge cases could still be expanded
- executable region validation stays simple on purpose
- Windows 11 behavior still needs broader validation

That tradeoff keeps the project readable end to end.

---

## Repository status

KernelMinHook is mainly a technical showcase project.

It is meant to be small enough to read quickly, while still showing the real structure of a kernel trampoline hook engine.

Planned improvements:

- better diagnostics
- fuller status reporting
- more relocation edge-case coverage
- cleaner validation around reusable executable regions
- broader compatibility validation
