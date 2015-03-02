/*
 * Block driver for RAW files (posix)
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu-common.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "trace.h"
#include "block/thread-pool.h"
#include "qemu/iov.h"
#include "qemu/uri.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>


#if 1
#define logout(fmt, ...) \
                fprintf(stderr, "vdi\t%-24s" fmt, __func__, ##__VA_ARGS__)
#else
#define logout(fmt, ...) ((void)0)
#endif

typedef struct BDRVEwfState {
} BDRVEwfState;

typedef struct BDRVEwfReopenState {
} BDRVEwfReopenState;

static int ewf_probe(const uint8_t *buf, int buf_size, const char *filename)
{
	return 0;
}

static int vdi_open(BlockDriverState *bs, int flags)
{

}

static BlockDriver bdrv_ewf = {
	.format_name = "ewf",
	.protocol_name = "ewf",
 	.instance_size = sizeof(BDRVEwfState),
	.bdrv_probe = ewf_probe,
	.bdrv_open_filename = ewf_open,
	.bdrv_close = ewf_close,
	.bdrv_read = ewf_co_read,
};

static void bdrv_ewf_init(void)
{
    /*
     * Register all the drivers.  Note that order is important, the driver
     * registered last will get probed first.
     */
    bdrv_register(&bdrv_ewf);
}

block_init(bdrv_ewf_init);
