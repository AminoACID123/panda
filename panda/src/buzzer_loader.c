#include "panda/buzzer_userspace.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termio.h>
#include <termios.h>


#define FATAL(_cond, _msg...)		\
	do {                            \
		if (_cond) {                \
			bz_guest_error(_msg);    \
			exit(1);                \
		}                           \
	} while (0)

#define HCI_UART_H4 0
#define BTPROTO_HCI 1

#define HCIDEVUP	        _IOW('H', 201, int)
#define HCISETSCAN          _IOW('H', 221, int)

#define HCI_UART_RAW_DEVICE	0
#define HCI_UART_RESET_ON_INIT	1
#define HCI_UART_CREATE_AMP	2
#define HCI_UART_INIT_PENDING	3
#define HCI_UART_EXT_CONFIG	4
#define HCI_UART_VND_DETECT	5

#define HCIUARTSETPROTO     _IOW('U', 200, int)
#define HCIUARTGETPROTO     _IOR('U', 201, int)
#define HCIUARTGETDEVICE    _IOR('U', 202, int)
#define HCIUARTSETFLAGS     _IOW('U', 203, int)
#define HCIUARTGETFLAGS     _IOR('U', 204, int)

#define HCI_CHANNEL_USER 1
#define HCI_CHANNEL_RAW 0

#define B115200 0010002

unsigned int speed = B115200;
bool flowctrl = true;

HarnessState harness_state;
char* target;

int open_serial(const char *path)
{
	struct termios ti;
	int fd, ret, saved_ldisc, ldisc = N_HCI;
	fd = open(path, O_RDWR | O_NOCTTY);

	FATAL(fd < 0, "Failed to open serial\n");

    ret = tcflush(fd, TCIFLUSH);
	FATAL(ret < 0, "Failed to flush serial");

    ret = ioctl(fd, TIOCGETD, &saved_ldisc);
	FATAL(ret < 0, "Failed to get ldisc");

	memset(&ti, 0, sizeof(ti));
	cfmakeraw(&ti);

	ti.c_cflag |= (speed | CLOCAL | CREAD);

	if (flowctrl) {
		ti.c_cflag |= CRTSCTS;
	}

    ret = tcsetattr(fd, TCSANOW, &ti);
	FATAL(ret < 0, "Failed to set serial\n");

    ret = ioctl(fd, TIOCSETD, &ldisc);
	FATAL(ret < 0, "Failed to set ldisc\n");

	printf("Switched line discipline from %d to %d\n", saved_ldisc, ldisc);
	return fd;
}

int attach_device(void)
{
	int fd, ret;
	char* dev_path = alloc_printf("/dev/ttyS%d", harness_state.device_no);
	bz_print("Opening HCI device: %s", dev_path);
	fd = open_serial(dev_path);

    ret = ioctl(fd, HCIUARTSETFLAGS, 1 << HCI_UART_RAW_DEVICE);
    FATAL(ret < 0, "Failed to set flags\n");

    ret = ioctl(fd, HCIUARTSETPROTO, HCI_UART_H4);
    FATAL(ret < 0, "Failed to set proto\n");

    ret = ioctl(fd, HCIUARTGETDEVICE);
    FATAL(ret < 0, "Failed to get device\n");

    bz_print("Device %d attached", ret);

    return ret;
}

void download_files(void) {
	int ret = 0;
	FILE* file = NULL;
	uint8_t* data_buffer = NULL;

	bz_req_harness_info((uintptr_t)&harness_state);

	for (int i = 0 ; i < harness_state.num; ++i) {
		uint32_t size = harness_state.files[i].size;
		char* name = harness_state.files[i].name;

		data_buffer = realloc(data_buffer, size);
		// if (data_buffer) free(data_buffer);
		// data_buffer = malloc(size);
		memset(data_buffer, 0xFF, size);

		bz_print("Prepare to download %s of %d bytes", name, size);
		bz_req_file(data_buffer);

		file = fopen(name, "w+");
		FATAL(!file, "Fail to open: %s", name);

		ret = fwrite(data_buffer, 1, size, file);
		FATAL(ret != size, "Fail to write: %s", name);

		fclose(file);

		if (harness_state.files[i].is_exec) {
			ret = chmod(name, S_IRWXU);
			FATAL(ret != 0, "Error setting executable permission");
		}
		if (harness_state.files[i].is_target) {
			target = alloc_printf("%s/%s", "/tmp", harness_state.files[i].name);
		}
		bz_print("Downloaded file: %s", name);
	}

}

void run_target(void) {

	char* ld_library_path = "/tmp";
	char* ld_preload = "/tmp/buzzer_preload.so";
	char* asan_options = harness_state.asan_enabled ? "ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:log_path=/tmp/data.log:abort_on_error=true" : "";

	char* cmd = alloc_printf("LD_LIBRARY_PATH=%s:$LD_LIBRARY_PATH " \
							 "LD_PRELOAD=%s " \
							 "LD_BIND_NOW=1 "\
							 "%s "\
							 "%s %s", \
							 ld_library_path, ld_preload, asan_options, target, harness_state.argv);
	
	bz_print("Execute: %s", cmd);
	system(cmd);

	// pid_t pid = fork();
	// if (!pid) {
	// 	if (setsid() < 0)
	// 		bz_guest_error("setsid");

	// 	setenv("LD_LIBRARY_PATH", "/tmp", 1);
	// 	setenv("LD_PRELOAD", "/tmp/buzzer_preload.so", 1);
	// 	setenv("LD_BIND_NOW", "1", 1);
	// 	if (harness_info.asan_enabled) {
	// 		setenv("ASAN_OPTIONS", "detect_leaks=0:allocator_may_return_null=1:log_path=/tmp/data.log:abort_on_error=true", 1);
	// 	}

	// 	int n = 10, i = 0;
	// 	char** argv = calloc(n, sizeof(char*));
	// 	char* arg = strtok(harness_info.argv, " ");

	// 	while (arg != NULL) {
	// 		argv[i++] = arg;
	// 		if (i > n) argv = realloc(argv, sizeof(char*) * i);
	// 		bz_print("arg: %s", arg);
	// 		arg = strtok(NULL, "");
	// 	}
	// 	argv[i] = NULL;
		
	// 	bz_print("Starting target: %s", target);
	// 	execv(target, argv);					
	// 	bz_guest_error("fail to execv: %s", target);
	// }
}

int main(int argc, char** argv){

	// uint64_t panic_handler = 0x0;
	// uint64_t kasan_handler = 0x0;
	int ret = 0;
	ret = chdir("/tmp");
	FATAL(ret < 0, "%s", strerror(errno));

    // panic_handler = get_address("T panic\n");
    // bz_print("Kernel Panic Handler Address:\t%lx\n", panic_handler);

    // kasan_handler = get_address("t kasan_report_error\n");
    // if (kasan_handler){
    //   bz_print("Kernel KASAN Handler Address:\t%lx\n", kasan_handler);
    // }

    // /* submit panic address */
    // perform_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler);
    // /* submit KASan address */
    // if (kasan_handler){
    //   perform_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, kasan_handler);
    // }


	download_files();

	attach_device();

	run_target();

    while(true){}
  
	return 0;
}
