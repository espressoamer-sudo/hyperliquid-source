# RE-001: async pointer-element drop and packed reference count

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

Question: what does `0x5cfcae0` release for each pointer-array element in
`0x5ce8da0`? The parent passes each pointer value from its +0x150 array, not
the array slot address. This body consumes that argument as an object address.
The parent is boundary context; this packet owns the callee's normal-return
sequence and packed counter distinction. The pair-reference callbacks
`0x5ce8880` and `0x5ce8620` already have separate fixed-buffer/nested-counter
packets and are not newly recovered here.

## Observations from the captured bytes

Actual FDE `0x5cfcae0..0x5cfcbe3`: 259 bytes, 72 completely decoded
instructions. There is no byte normalization. Full body and FDE/CIE bytes,
all calls, direct branches and relocated tail jump are in `records.json`.

Let B be entry RDI, retained in RBX. Normal-return operations are ordered:

1. Load P=[B]. If P is zero, skip this first release. Otherwise load RAX=-64
   and `lock xadd qword [P], RAX` at `0x5cfcaf7`. RAX receives the **old**
   word, while memory receives old-64 modulo 2^64.
2. Shift old RAX right by 6 and compare it against 1. Old high-count 1 calls
   through `[ [P+0x10] + 0x10 ]`, retaining P as RDI. Old high-count greater
   than 1 skips that callback. Old high-count zero takes a diagnostic call
   with length 0x27 and then UD2 at `0x5cfcb24`. The counter has already
   changed before this diagnostic; it is not an early underflow guard.
3. Set R15=B+0x18 and call `0x5ce1e50` with that field address. On return,
   load Q=[B+0x18], `lock dec [Q]`, and invoke slot `0x64e17b0` only when
   the decrement reaches zero. Its argument is B+0x18. This field is not
   null-checked on the normal path.
4. Load R=[B+8]. If nonzero, `lock dec [R]` and invoke slot `0x64e17a8`
   on zero, with argument B+8. A null pointer skips this release.
5. Tail-jump through slot `0x64df4a0` with RDI=B, RSI=0x78, EDX=0.
   It is unconditional after these normal-path stages, unlike a weak-count
   guard in the pair-wrapper callbacks.

The imports are ELF RELATIVE slot addends in the exports; source-level
deallocator/type names are inferred. Dynamic vtable method +0x10 remains
unresolved. The -64/XADD/SHR sequence demonstrates a high 58-bit count and
low six untouched bits at this release site; the low bits' meanings and a
complete synchronization protocol are not established.

## Reproduce and distinguish incorrect reconstructions

```sh
python3 research/work-items/RE-001-async-pointer-element-drop-115/verify.py
```

Use Python, Capstone 5.0.6 and pyelftools 0.32. `--write` regenerates the
exports. Full-image digest, actual FDE, complete decode, exact instruction
pins, direct-branch instruction boundaries and GOT relocation uniqueness are
checked. Nine operative byte mutations are rejected with the image SHA guard
disabled, including the decrement constant, shift, count comparison, callback
offset, field offsets and final allocation size.

Independent arithmetic checks cover count classes 0, 1, 2, 3 and 2^58-1,
each with all 64 low-bit patterns, plus eight optional-reference cases:
328 cases, zero mismatches. They preserve low flags and distinguish old count
from post-subtraction count. Old word 0x40 becomes 0 and invokes the callback;
old 0 becomes 0xffffffffffffffc0 and takes the diagnostic. These are scalar
lowerings, not execution or interpretation of captured instructions.

## Limits and next question

Observed cleanup-pad instructions are retained, but LSDA action/call-site
selection is not decoded. No exceptional path is claimed complete. Valid
object pointers, sufficient storage, stable nonaliasing fields, valid counts
and normally returning helpers are assumptions. The vtable method, the
`0x5ce1e50` field helper, allocator and panic constructor remain opaque.
No Rust layout name, full destructor closure or progress gate is claimed.

Next question: determine how `0x5ce1e50` transforms the +0x18 field before
the required reference decrement, and bind the dynamically called method.
