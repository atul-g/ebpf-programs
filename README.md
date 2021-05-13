# Messing with bpf

1. Using `bpftrace` -  run the command as root user: `bpftrace
   bpftrace-run.bpf` Refer to other available arguments via
   `/sys/kernel/tracing/events/syscalls/<some_syscall_enter_or_exit>/format`

2. Installing bpfcc-tools in ubuntu installs a slightly older version, which
   yields a "bcc.containers not found" module error when trying to run
   `execsnoop.py`. Apart from that, `execsnoop.py` injects bpf code into kernel
   which makes use of bpf helper functions which were only added in kernel 5.5
   and later while my ubuntu used a 5.4. So for these reasons, I downloaded
   `execsnoop.py` from the v0.10 tag (branch) from github.

3. Also, change the shebang in `execsnoop.py` to "python3" and chmod it to
   "+x", so you can simply run `sudo ./execsnoop.py`.

4. For BCC, check out their API [reference
   guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
   for understanding the arguments of certain functions and what they do.
