#include <iostream>
#include <bcc/BPF.h>

//This is a raw string. Helps in retaining the actual meaning of the escape
//sequences and special characters to send it to kernel as bpf code.
std::string bpf_source = R"(

//this is the communication ring buffer which we can write to from
//kernel space and read from the user space
BPF_PERF_OUTPUT(event);

struct data_t {
	pid_t pid;
	char comm[256];
};

int my_mmap_fn(void *ctx)
{
	struct data_t data = {};

	//the tgid in kernel's view is the PID in userspace view
	//upper 32 bytes are tgid, lower are pid which are IDs allocated
	//to every thread of a process so that kernel can schedule it. We
	//only need the tgid and report it back as the PID.
	data.pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(data.comm, 256);

	bpf_trace_printk("ATULU: Called my_mmap\n");

	event.perf_submit(ctx, &data, sizeof(data));
	return 0;
}

)";

struct data_t {
	pid_t pid;
	char comm[256];
};

void handler(void *ctx, void *data, int sz)
{
	data_t *d = static_cast<data_t *>(data);
	std::cout <<
		"PID: " <<
		d->pid <<
		" COMM: " <<
		d->comm << std::endl;

}

int main() {

	ebpf::BPF bpf;
	bpf.init(bpf_source);

	// we try to get what the actual syscall function name is based on the
	// base syscall name as input argument. This helper function will try
	// different prefixes and use the right one to concatenate with the
	// syscall name. This code will return the input argument itself if
	// the binary is run without sudo/root.
	auto syscall_name = bpf.get_syscall_fnname("mmap");
	std::cout<<"The syscall which we are going to use as hook: "<<syscall_name
		<< std::endl;

	ebpf::StatusTuple res = bpf.attach_kprobe(syscall_name, "my_mmap_fn");
	if (res.code() != 0) {
		std::cerr << res.msg() << std::endl;
		return res.code();
	}

	//open_perf_buffer() can be found in /usr/include/bcc/BPF.h
	//when looking at it, you see that the 2nd argument is
	//"perf_reader_raw_cb cb". The type "perf_reader_raw_cb" is a
	//typedef defined in libbpf.h, and that's where you see what
	//the signature of the handler function is supposed to be.
	auto res_open_perf = bpf.open_perf_buffer("event", handler);
	if (res_open_perf.code() != 0) {
		std::cerr << res_open_perf.msg() << std::endl;
		return 1;
	}

	while (0 <= bpf.poll_perf_buffer("event")) {

	}

	sleep(10);

	return 0;
}

