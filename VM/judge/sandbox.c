#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>			//dup2
#include <seccomp.h>		//seccomp
#include <signal.h>
#include <sys/time.h>		//rlimit
#include <sys/resource.h>	//rlimit
#include <sys/types.h>
#include <sys/wait.h>

#define CHILD_STACK_SIZE (128 * 1024 * 1024)

struct sandbox_config {
	char *exe_file;
	char *input_path;
	char *output_path;
	char *error_path;
	int time_limit;
	int memory_limit;
	int case_number;
};
typedef struct sandbox_config sandbox_config;

struct sandbox_timeout_arg {
	int timeout;
	int cpid;
};
typedef struct sandbox_timeout_arg sandbox_timeout_arg;

struct judge_result {

};
typedef struct judge_result judge_result;

void check_config(sandbox_config config) {

}

typedef struct rlimit rlimit;

int set_rlimit(sandbox_config *config) {
	int rc = -1;
	//stack size
	rlimit rlim_stack;
	rlim_stack.rlim_cur = rlim_stack.rlim_max = (rlim_t)(config->stack_size);
	rc = setrlimit(RLIMIT_STACK, &rlim_stack);
	if (rc < 0)
		goto out;
	//time limit
	rlimit rlim_time;
	rlim_time.rlim_cur = rlim_time.rlim_max = (rlim_t)(config->time_limit / 1000 + 1);
	rc = setrlimit(RLIMIT_CPU, &rlim_time);
	if (rc < 0)
		goto out;
	//memory limit
	rlimit rlim_mem;
	rlim_mem.rlim_cur = rlim_mem.rlim_max = (rlim_t)(config->memory_limit);
	rc = setrlimit(RLIMIT_AS, &rlim_mem);
	if (rc < 0)
		goto out;
	/*
	//output limit
	rlimit rlim_out;
	rlim_out.rlim_cur = rlim_out.rlim_max = (rlim_t)(config->output_limit);
	rc = setrlimit(RLIMIT_FSIZE, &rlim_out);
	if (rc < 0)
		goto out;
	*/
out:
	return -rc;
}

int set_redirect(sandbox_config *config) {
	int rc = -1;
	FILE *input_file = NULL, output_file = NULL, error_file = NULL;

	if(config->input_path){
		input_file = fopen(config->input_path, "r");
		if (!input_file)
			goto out;
		// redirect file -> stdin
		rc = dup2(fileno(input_file), fileno(stdin));        
		if (rc == -1)
			goto out;
		close(input_file);
	}

	if(config->output_path){
		output_file = fopen(config->output_path, "w");
		if (!output_file)
			goto out;
		// redirect stdout -> file
		rc = dup2(fileno(output_file), fileno(stdout));
		if (rc == -1)
			goto out;
		close(output_file);
	}

	if(config->error_path){
	error_file = fopen(_config->error_path, "w");
		if(!error_file)        	
			goto out;
		// redirect stderr -> file
		rc = dup2(fileno(error_file), fileno(stderr));
		if (rc == -1)
			goto out;
		close(error_file);
	}
out:
	return -rc;
}

int set_seccomp(sandbox_config *config) {
	int whitelist[] = {	SCMP_SYS(access), SCMP_SYS(arch_prctl), SCMP_SYS(brk),
						SCMP_SYS(close), SCMP_SYS(exit_group), SCMP_SYS(fstat),
						SCMP_SYS(lseek), SCMP_SYS(munmap), SCMP_SYS(uname),
						SCMP_SYS(mmap), SCMP_SYS(mprotect), SCMP_SYS(read),
						SCMP_SYS(readlink), SCMP_SYS(sysinfo), SCMP_SYS(write),
						SCMP_SYS(writev) };
	int whitelist_size = sizeof(whitelist) / sizeof(int);
	int rc = -1, i;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if(ctx == NULL)
		goto out;

	for(i = 0;i < whitelist_size;i++){
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, whitelist[i], 0);
		if (rc < 0)
			goto out;
	}
	//execve
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1,
					SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)config->test_data_dir));
	if(rc < 0)
		goto out;
	//open, only allow read mode
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
					SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0));
	if(rc < 0)
		goto out;
	rc = seccomp_load(ctx);
	if(rc < 0)
		goto out;
out:
	seccomp_release(ctx);
	return -rc;
}

int sandbox_process(sandbox_config *config) {
	if(set_rlimit(config)){
		//set rlimit error
	}
	if(set_redirect(config)){
		//set redirect error
	}
	if(set_seccomp(config)){
		//set seccomp error
	}	
	execve(config.filename, config.argv, config.env);
	// execve error
	return 0;
}

void *sandbox_timeout(void *arg) {
	sandbox_timeout_arg *timeout_arg = arg;
	int ret;

	ret = pthread_detach(pthread_self());
	if(ret != 0){
		//pthread_detach error
	}
	ret = sleep((unsigned int)timeout_arg.timeout);
	if(ret != 0){
		//sleep error
	}
	ret = kill(timeout_arg.cpid, SIGKILL);
	if(ret == -1){
		//kill error
	}
	return NULL;
}


int main(int argc, char *argv)
{
	struct timeval start_time, end_time;
	struct rusage child_usage;
	sandbox_config *config;
	int wstatus, ret;

	if(argc == 7){
		//arg for judge
		config.exe_file = argv[1];
		config.input_path = argv[2];
		config.output_path = argv[3];
		config.error_path = argv[4];
		config.time_limit = argv[5];
		config.memory_limit = argv[6];
	//	case_number = argv[7];
	}

	gettimeofday(&start_time, NULL);

	pid_t cpid = fork();

	if(cpid < 0){
//fork error
	}
	else if(cpid == 0){
//child process
		sandbox_process(config);
	}
	else{
//parent process
		pthread_t tid;
		sandbox_timeout_arg timeout_arg;
		timeout_arg.timeout = config.time_limit + 1;
		timeout_arg.cpid = cpid;
		pthread_create(tid, NULL, sandbox_timeout, &timeout_arg);


		ret = waitpid(cpid, &wstatus, WUNTRACED);
		if(ret == -1){
			kill(cpid, SIGKILL);
			//waitpid error
		}

		gettimeofday(&end_time, NULL);

		ret = getrusage(RUSAGE_CHILDREN, &child_usage);
		if(ret == -1){
			//getrusage error
		}
	}
	return 0;
}