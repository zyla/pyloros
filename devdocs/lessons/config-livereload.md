# Config Live-Reload

## Key insight: no ArcSwap needed

`serve(mut self, ...)` owns all ProxyServer fields and runs the accept loop.
We can simply mutate fields in the accept loop when a reload message arrives.
New connections clone the updated Arcs; old connections continue with their
existing clones. No lock-free data structures or ArcSwap needed.

## File watcher debouncing

Editors often do write-to-temp + rename when saving. This produces multiple
inotify events in quick succession. Watching the parent directory (not the
file itself) catches rename-into events. After the first relevant event,
drain all events for 200ms before triggering reload.

## Notify race condition in tests

`tokio::sync::Notify::notified()` only registers the waiter when first polled.
In current_thread runtime (default for `#[tokio::test]`), the server task can't
run between `reload_tx.send().await` and `notified.await`, so there's no race.
In multi-thread runtime, use `enable()` on the pinned `Notified` future before
sending the trigger.

## reqwest connection reuse after reload

reqwest pools CONNECT tunnels. After a config reload, the old tunnel still uses
the pre-reload filter engine. Tests must create a new `reqwest::Client` (via new
`ReportingClient`) for post-reload assertions to verify new-connection behavior.
