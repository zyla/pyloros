# Nested `claude -p` hangs when spawned from a Claude Code session

## Summary

Running `claude -p "Say hi"` as a subprocess of an active Claude Code session
hangs indefinitely. The process connects to `api.anthropic.com`, completes TLS
handshakes, exchanges data, then enters a busy-loop spinning on an eventfd —
never producing output. The same command completes in ~3 seconds from a normal
terminal.

This means the live API test (`test_binary_claude_code_through_proxy`) cannot run
in an agentic environment. It must be run from a standalone terminal.

## Investigation

### What works

- `claude --version` returns instantly even when nested (exits before the "do work" path).
- `claude -p "Say hi"` from a normal terminal completes in ~3 seconds.

### What was tried (all still hang)

| Variant | Rationale | Result |
|---------|-----------|--------|
| `timeout 30 claude -p ...` | Baseline | Hangs, killed at timeout |
| `env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT timeout 30 claude -p ...` | Maybe claude detects parent via env vars | Still hangs |
| `... < /dev/null` | Maybe stdin (an IPC socket) confuses it | Still hangs |
| `timeout 30 bash -c 'claude ... > /tmp/out 2>/tmp/err'` | Redirect stdout/stderr away from IPC sockets | Still hangs |
| `timeout 30 setsid claude -p ...` | Detach from session/process group | Still hangs |
| `nohup timeout 15 claude -p ...` | Detach from terminal signals | Still hangs |
| Close all FDs > 2 then exec claude | Eliminate inherited file descriptors | Still hangs |
| Close all FDs > 2 AND redirect 0/1/2 to files | Combined FD cleanup | Still hangs |
| Unset all 6 extra env vars from Claude Code session | Eliminate all env differences | Still hangs |

### Environment comparison

`env` diff between a normal terminal and a Claude Code bash subprocess:

```
COREPACK_ENABLE_AUTO_PIN=0        # extra in Claude Code
NoDefaultCurrentDirectoryInExePath=1
CLAUDECODE=1
GIT_EDITOR=true
OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=delta
CLAUDE_CODE_ENTRYPOINT=cli
SHLVL=3                           # vs 2 outside
```

Unsetting all of these did not help.

### strace findings

**`strace -f -e trace=openat,connect,flock`**: No flock calls. No `/proc/<pid>`
snooping (only `/proc/self/*`). Two successful TCP connects to
`api.anthropic.com:443` (160.79.104.10).

**`strace -f -e trace=epoll_wait,read,write,recvfrom,sendto`**: The process
completes TLS handshakes on two sockets (fd 17 and 18), exchanges encrypted
data with the API, then enters a **busy loop** where the main thread (320748)
repeatedly reads `\1\0\0\0\0\0\0\0` from an eventfd (fd 8). This is a libuv
eventfd notification pattern — the Node.js event loop is spinning, processing
notifications but never reaching a "done" state.

### FD inheritance

The Claude Code bash subprocess inherits IPC **sockets** on fd 0, 1, 2 (not
pipes or a PTY):

```
fd 0 -> socket:[364712]
fd 1 -> socket:[362248]
fd 2 -> socket:[362250]
```

However, redirecting all three to files/`/dev/null` and closing all higher FDs
did not fix the issue, so the sockets themselves are not the direct cause.

### Process tree check

`/proc` access patterns show only `/proc/self/*` reads — claude does **not**
walk the process tree to detect a parent claude process.

## Conclusion

The root cause remains unknown. The child `claude` process successfully
connects to the API and exchanges data but then gets stuck in the Node.js event
loop. Possible explanations:

1. **Shared Node.js runtime state**: Some aspect of the Node.js/V8 runtime is
   inherited or shared that causes the child's event loop to malfunction.
2. **IPC channel detection**: Node.js may detect an inherited IPC channel via a
   mechanism we haven't identified (not env vars, not FD numbers, not
   `/proc`).
3. **File-based coordination**: Claude Code may use a file in `~/.claude/` as a
   coordination mechanism that causes the child to wait.

The practical workaround is to skip the test when `CLAUDECODE=1` is set and
run it manually from a standalone terminal.
