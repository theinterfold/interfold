# e3-console

This is injectable command output, not protocol logging or durable event storage.

- Keep `Console` cheap to clone and destination-independent; callers should not special-case stdout
  when the same command runs through a daemon or a captured test channel.
- `ConsoleHandle::flush` drains only after all cloned senders are dropped. Do not retain a clone
  across a drain wait or treat the handle's own drop as completion of pending output.
- Writer mode appends one newline per message and flushes at channel closure. Preserve this framing
  for daemon/client output consumers.
- Sends and writer shutdown are currently best-effort, and the queue is unbounded. Do not use this
  path for acknowledged delivery or describe it as bounded backpressure.

The [README](README.md#tests) records the current check/coverage boundary. Output changes should add
focused async writer/channel coverage here and exercise the command consumer.
