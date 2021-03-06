#include <iostream>
#include <bcc/BPF.h>

std::string bpf_source = R"(
#include <linux/sched.h>

//this is the binary file name of the C reproducer
#define C_REPRO_NAME "mbind-repro"
#define NAME_SIZE 11

//writing own implementation of strncmp, as bpf doesn't provide
//libc
static int string_cmp(const char *s1, const char *s2, size_t n)
{
	int res = 0;
	for (int i = 0; i < n; i++) {
		if (s1[i] != s2[i]) {
			res = 1;
			break;
		}
	}

	return res;
}

int check_set_nodemask(struct pt_regs *ctx)
{
	char comm[TASK_COMM_LEN];

	//get the tgid and pass it on as pid
	u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);

	//we get the current process name
	bpf_get_current_comm(&comm, sizeof(comm));

	bpf_trace_printk("PID: %d \t COMM: %s\n", pid, comm);

	if (string_cmp(comm, C_REPRO_NAME, NAME_SIZE) == 0) {
		//the return value of mpol_set_nodemask()
		int ret = PT_REGS_RC(ctx);
		bpf_trace_printk("Return value of function mpol_set_nodemask: %d\n", ret);
	}

	return 0;	
}
)";

int main() {
	ebpf::BPF bpf;
	bpf.init(bpf_source);

	ebpf::StatusTuple res = bpf.attach_kprobe("mpol_set_nodemask.part.0",
			"check_set_nodemask",
			0,
			BPF_PROBE_RETURN,
			0);
	
	if (res.code() != 0) {
		std::cerr << res.msg() << std::endl;
		return res.code();
	}

	while (true) {

	}
	
	return 0;
}
