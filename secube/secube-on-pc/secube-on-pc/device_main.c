#include "device_main.h"
#include "se3c0.h"
#include "se3c1.h"
#include "se3_flash.h"
#include "se3_proto.h"
#include "se3_cmd.h"


void device_init()
{
	se3c0_init();
	se3_flash_init();
    se3c1_init();
}

void device_loop()
{
	for (;;) {
		sim_mutex_acquire();
		if (se3c0.comm.req_ready) {
			se3c0.comm.resp_ready = false;
            se3_cmd_execute();
			se3c0.comm.req_ready = false;
			se3c0.comm.resp_ready = true;
		}
		sim_mutex_release();
		Sleep(0);
	}
}

