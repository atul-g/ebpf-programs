#!/usr/bin/python3

from bcc import BPF
from time import sleep

bpf_code = '''
#include <linux/sched.h>

// bpf needs a ring buffer to send info back up to the userspace
// for analysis. These "info" are going to be of the following struct
// type data_t.

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN]; //TASK_COMM_LEN comes from sched.h
};

// This is the buffer through which bpf can send back the information/data
// to the userspace and we can actually mess it with apart from just printing
BPF_PERF_OUTPUT(events); //events will be the name of the buffer, can be anything

//note we can create more than 1 perf_buffers

// The following struct has fields directly coming from the file
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// since we are going to be inserting this bpf code at the openat syscall
// hook.

struct sys_enter_openat_args {
    // the below u64 sized fields helps in ignoring all the actual openat
    // args up TILL offset 8, so from the format file, that will be the
    // first 4 fields. We don't need them, that's why.
    uint64_t _unused;

    int _nr;
    u64 dfd; //format says int, but I'm giving u64 because it has
             // size 8 and it is unsigned.
    const char *filename;
    u64 flags;  //u64 because same reason as for dfd
    u64 mode;   //u64 cuz same reason
};

int my_sys_enter_openat_fn(struct sys_enter_openat_args *args)
{

    struct data_t data = {}; //all 0 initialization of struct

    //"u64 bpf_get_current_pid_tgid()" is a helper function that returns
    //the process id and the thread group id which the process belongs
    //too. The upper 32 bits are tgid.
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(tgid_pid >> 32);
    
    //u32 pid = (u32)(tgid_pid); <- dont need this

    data.pid = tgid;
    bpf_probe_read_str(data.comm, TASK_COMM_LEN, args->filename);

    // there is a doube // because remember this is a python string
    // so, python interpreter would convert it into a newline and then
    // pass this string to bcc to compile into bpf. We don't want that.
    bpf_trace_printk("ATUL: openat was fired by tgid: %d!\\n", tgid);

    //through this code, bpf is sending data to the userspace
    events.perf_submit(args, &data, sizeof(data));

    return 0;
}
'''

bpf = BPF(text = bpf_code)

# this line basically attaches our bpf at the tracepoint specified by tp
bpf.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="my_sys_enter_openat_fn")

'''
NOTE: Commented this out since we have a while loop now.

# Our bpf probe is now active for 10 seconds, after 10 seconds, you
# wont see any further syscall being catched and our function being executed
# in the /sys/kernel/tracing/tracing_pipe file, simply because this python
# file would have exit()-ed after the sleep
sleep(10)
'''

def handle_openat_syscall(cpu, data, size):
    event = bpf["events"].event(data)
    pid = event.pid
    comm = event.comm
    print("PID:", pid, "\tCOMM:", comm)

bpf['events'].open_perf_buffer(handle_openat_syscall)

#After this, cat /sys/kernel/debug/tracing/trace_pipe in a different
#terminal

while True:
    try:
        # this polls the perf buffers to see if there is any new data from
        # bpf to the userspace to use
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
