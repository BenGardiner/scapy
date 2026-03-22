# Scapy Automotive Contrib — Code Constitution

Derived from a review of the existing automotive contrib code:
`scapy/contrib/isotp/isotp_soft_socket.py`,
`scapy/contrib/automotive/gm/gmlanutils.py`,
`scapy/contrib/automotive/uds.py`,
`scapy/contrib/automotive/doip.py`,
`scapy/contrib/automotive/scanner/enumerator.py`,
`scapy/contrib/automotive/ecu.py`.

---

## 1. File Header

Every contrib source file must start with the following lines, in order:

```python
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) <Author> <email>

# scapy.contrib.description = <one-line human description>
# scapy.contrib.status = <loads | library | skip>
```

Socket and utility modules must also have a multi-line **module-level RST
docstring** that explains the purpose, modes of operation, and a usage
example.  The docstring must be RST-compliant (no indented bullet lists
without a preceding blank line; no trailing code-block indentation errors).

---

## 2. Import Organisation

Imports appear in exactly three groups, separated by a blank line:

1. **Standard library** — alphabetical order.
2. **Typing** — preceded by the comment `# Typing imports`, then
   `from typing import (...)`.  Imports are one per line, alphabetical.
3. **Scapy** — one `from scapy... import ...` per logical module.

After the Scapy imports, place the `if TYPE_CHECKING:` guard for any
forward-referenced types (e.g. `CANSocket`).

**All imported symbols must be used.**  Remove any import that is not
referenced in the file body.

---

## 3. Module-level Constants

- Use **ALL_CAPS** for every protocol constant and state integer.
- Group related constants under a single short comment (e.g.
  `# TP.CM control bytes`), not a full banner.
- Prefer explicit hex literals; add an inline decimal comment for
  protocol IDs that appear in specifications.
- Every constant that is part of the public API should have a `#:` RST
  attribute docstring comment on the line immediately above it.
- Define all state-machine state integers at module level, not inside
  classes.

---

## 4. Type Annotations

- Use **comment-based type hints** throughout (`# type: (args) -> ret`),
  matching the Python 2-compatible style used across the codebase.
- Use `# type: (...) -> None` in the function body line for `__init__`
  and other multi-parameter methods.
- Do **not** use PEP 526 variable annotations (`x: int = 0`) in
  production code.
- Prefer runtime guards (e.g. `if self.x is None: return`) over
  `# type: ignore[arg-type]`.  Use `# type: ignore` only as a last
  resort when there is no cleaner alternative.
- Use the `TYPE_CHECKING` guard for circular or optional imports.

---

## 5. Class Design

- Socket-wrapper classes inherit from `SuperSocket`.
- The protocol implementation (state machine, background polling) lives
  in a **separate implementation class** (e.g. `J1939SocketImplementation`)
  so that the wrapper can be garbage-collected without keeping the
  background thread alive.
- Use `__slots__` only on lightweight value-objects (e.g. `Handle`,
  packet subclasses with custom extra attributes).
- Use `@classmethod` for shared singleton resources (e.g.
  `TimeoutScheduler`).
- Implementation classes include a `__del__` method that calls `close()`
  so that resources are released even if the caller forgets.

---

## 6. `__init__` Structure

Parameters are listed one per line with aligned `# type:` comments:

```python
def __init__(
    self,
    param1=default,         # type: SomeType
    param2=default,         # type: OtherType
):
    # type: (...) -> None
```

State variable initialisation follows this order inside the body:

1. Core parameters (`self.param = param`).
2. Protocol addressing / network-management parameters (e.g. `name`,
   `preferred_address`) — grouped with the core params they relate to.
3. Receive-side state variables.
4. Transmit-side state variables.
5. Protocol timeout values.
6. All timer handles (`None`-initialised), together in one group.
7. Miscellaneous flags and last-value trackers.
8. I/O queues.
9. Poll-rate constant and background-polling schedule.
10. Any initial protocol actions (e.g. address-claim broadcast).

Do **not** bolt on new subsystems at the very bottom of `__init__` after
unrelated scheduling setup; integrate them into the appropriate position
in the order above.

---

## 7. Class and Method Docstrings

- **Class docstrings**: multi-line RST.  List all constructor parameters
  with `:param name: description` and `:type name: type`.  Include a
  concise usage example.
- **Public method docstrings**: one-line summary, optional blank line +
  detail paragraph(s), `:param:` / `:returns:` RST fields.
- **Private methods** (`_` prefix): a one-liner is sufficient; use
  multi-line only when the logic is non-obvious.
- Timer callbacks and poll loops must state *when* they are invoked.

---

## 8. Private vs Public API

| Prefix | Meaning |
|---|---|
| no prefix | Public API — requires full docstring and type annotations. |
| `_single` | Internal / protected — not part of the public API; one-liner docstring is acceptable. |
| `__double` | Python dunder methods only (`__init__`, `__del__`, `__repr__`, …).  Do **not** use double-underscore name mangling on ordinary private methods. |

---

## 9. Section Banners

Use `# ---` comment banners **sparingly** — at most one banner per
major logical section within a class (e.g. *RX state machine*, *TX state
machine*, *Network Management*).  Do not place a banner above every
method.  The section banners in the ISOTP soft socket are the reference:
short single-line comments, not `# ---...---` boxes.

---

## 10. Logging

- Define a **module-level logger**:
  `log_<module> = logging.getLogger("scapy.contrib.automotive.<module>")`.
- `log_<module>.debug()` — normal protocol flow events.
- `log_<module>.warning()` — unexpected but recoverable situations
  (timeouts, conflicts, aborts).
- `log_<module>.error()` — unrecoverable errors (rare in protocol layers).
- Never use `print()` for diagnostic output.

---

## 11. Error Handling

- Use `Scapy_Exception` for protocol-level state errors.
- Wrap every timer-handle cancellation in `try/except Scapy_Exception: pass`.
- Wrap every queue `close()` call in `try/except (OSError, EOFError): pass`.
- Avoid bare `except:` clauses; use `except Exception:` for broad
  catch-all handlers.

---

## 12. State Machines

- All states are **module-level integer constants** (ALL_CAPS), not
  class-level or in-method literals.
- Each state constant has a short inline comment describing it.
- State transitions are logged at `debug` level; resets and error states
  at `warning` level.
- The initial state is always set in `__init__`; never assume a default.

---

## 13. Threading and Timers

- Use `TimeoutScheduler` (singleton, `heapq`-based) for all timer
  operations.
- Use `ObjectPipe` for thread-safe inter-thread message queues.
- Store **all** timer handles as instance variables (initialised to
  `None`), and cancel them all in `close()`.
- `close()` must be idempotent and guard against double-close with
  `self.closed = True` at the top.

---

## 14. Code Quality

- No unused imports.
- No unused local variables.
- Lines should not exceed **99 characters**.
- Use `%`-style format strings for log messages (passed as arguments,
  not interpolated).  Use `.format()` for non-log string construction.
- Use `f-strings` only if the minimum supported Python version is ≥ 3.6
  *and* the string is not a logging argument.
