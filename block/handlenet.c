/*
 * Block protocol for block driver correctness testing
 *
 * Copyright (C) 2010 IBM, Corp.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <stdarg.h>
#include <hdl/hdl.h>
#include "qemu/sockets.h" /* for EINPROGRESS on Windows */
#include "block/block_int.h"


/* Valid HANDLE.NET handle looks like hdl:handle */
static int handlenet_open(BlockDriverState *bs, const char *filename, int flags)
{
    int ret;

    /* Parse the hdl: prefix */
    if (strncmp(filename, "hdl:", strlen("hdl:"))) {
        return -EINVAL;
    }
    filename += strlen("hdl:");

    /* Resolve the handle */
    HDLContext *ctx = HDLInitResolver();
    if (!ctx) {
        fprintf(stderr, "handlenet: Error: unable to create HANDLE.NET resolver.\n");
        return -EINVAL;
    }
    HDLValue **values;
    unsigned int nValues;
    ret = HDLResolve(ctx, filename, strlen(filename), NULL, 0, NULL, 0, &values, &nValues);
    if (ret != HDL_RC_SUCCESS) {
        fprintf(stderr, "handlenet: Error %i: %s.\n", ret, HDLGetErrorString(ret));
        HDLDestroyResolver(ctx);
        return -EINVAL;
    }
    if (!values || !nValues){
      fprintf(stderr, "handlenet: Error: No values found.\n");
      HDLDestroyResolver(ctx);
      return -EINVAL;
    }

    /* Best effort search for a URL */
    char *resolved_filename = 0;
    int i;
    for (i = 0; i < nValues; ++i) {
        /* TODO: proper UTF8 collation aware strcmp */
        if (!strncmp("URL", values[i]->type, values[i]->typeLen)) {
            resolved_filename = g_strndup(values[i]->data, values[i]->dataLen);
            break;
        }
    }
    HDLDestroyValueList(values, nValues);
    HDLDestroyResolver(ctx);
    fprintf(stderr, "handlenet: Info: resolved to %s\n", resolved_filename);

    /* Open the test file */
    ret = bdrv_file_open(&bs->file, resolved_filename, flags);
    g_free(resolved_filename);
    if (ret < 0) {
        bdrv_delete(bs->file);
        bs->file = NULL;
        return ret;
    }

    return 0;
}

static void handlenet_close(BlockDriverState *bs)
{
    bdrv_delete(bs->file);
    bs->file = NULL;
}

static int64_t handlenet_getlength(BlockDriverState *bs)
{
    return bdrv_getlength(bs->file);
}

static BlockDriverAIOCB *handlenet_aio_readv(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_aio_readv(bs->file, sector_num, qiov, nb_sectors,
                   cb, opaque);
}

static BlockDriverAIOCB *handlenet_aio_writev(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return bdrv_aio_writev(bs->file, sector_num, qiov, nb_sectors,
                    cb, opaque);
}

static BlockDriverAIOCB *handlenet_aio_flush(BlockDriverState *bs,
                                             BlockDriverCompletionFunc *cb,
                                             void *opaque)
{
    return bdrv_aio_flush(bs->file, cb, opaque);
}

static BlockDriver bdrv_handlenet = {
    .format_name        = "handlenet",
    .protocol_name      = "hdl",

    .instance_size      = 1,

    .bdrv_getlength     = handlenet_getlength,

    .bdrv_file_open     = handlenet_open,
    .bdrv_close         = handlenet_close,

    .bdrv_aio_readv     = handlenet_aio_readv,
    .bdrv_aio_writev    = handlenet_aio_writev,
    .bdrv_aio_flush     = handlenet_aio_flush,
};

static void bdrv_handlenet_init(void)
{
    bdrv_register(&bdrv_handlenet);
}

block_init(bdrv_handlenet_init);
