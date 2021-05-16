# ebpf programs

This repository contains my work on trying to trace kernel syscalls and
functions using ebpf. I've also traced return values of core kernel functions
based on commands invoking it.

* `ret_check` gets the return value of kernel's memory policy function on the
  condition that it is executed by a specific C reproducer (used it for
  debugging core functions).

* `my-openat-tracer.py` for getting information on all open-at syscall
  invocations. This gave me an idea on the disk activity of system so I could
  stop the processes causing unnecessary opening of files at a high rate. Note
  to self, python can be dead-slow at catching all perf ring buffer events
  during high activity.

* Rest are trials. Still under progress.
