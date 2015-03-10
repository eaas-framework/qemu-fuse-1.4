/*
 * Block driver for EWF segment files
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
#include "block/block_int.h"

#include <string.h>
#include <libewf.h>


/* Error logging helper */
#define EWF_LOGF(output, fmt, ...) \
		fprintf(output, "ewf.c:%i -> " fmt "\n", __LINE__, ##__VA_ARGS__)


typedef struct BDRVEwfState
{
	libewf_handle_t* input_handle;
	int64_t bytes_per_sector;
} BDRVEwfState;


static void ewf_print_error(FILE* stream, libewf_error_t* error)
{
	if (error == NULL)
		return;

	libewf_error_fprint(error, stream);
	libewf_error_free(&error);
	error = NULL;
}


static int ewf_probe(const uint8_t* buf, int buf_size, const char* filename)
{
	libewf_error_t* error = NULL;
	int number_of_filenames = 0;
	char** filenames = NULL;
	int check_code = 0;
	int i;

	/* Collect all segment files according to the EWF naming schema */
	if (libewf_glob(filename, strlen(filename), LIBEWF_FORMAT_UNKNOWN,
			&filenames, &number_of_filenames, &error) != 1) {
		libewf_error_free(&error);
		return 0;  /* Failure! */
	}

	for (i = 0; i < number_of_filenames; ++i) {
		check_code = libewf_check_file_signature(filenames[i], &error);
		if (check_code == 1)
			continue;

		/* Invalid signature found! */

		if (check_code < 0) {
			EWF_LOGF(stderr, "Checking file signature for '%s' failed!", filenames[i]);
			ewf_print_error(stderr, error);
		}

		break;
	}

	/* Cleanup globbed filenames */
	if (libewf_glob_free(filenames, number_of_filenames, &error) != 1)
		ewf_print_error(stderr, error);

	return (check_code == 1) ? 100 : 0;
}


static int ewf_open(BlockDriverState* bs, int flags)
{
	BDRVEwfState* s = (BDRVEwfState*) bs->opaque;

	libewf_error_t* error = NULL;
	uint64_t number_of_sectors = 0;
	uint32_t bytes_per_sector = 0;
	char** filenames = NULL;
	int numfiles = 0;

	/* Collect all segment files according to the EWF naming schema */
	if (libewf_glob(bs->filename, strlen(bs->filename), LIBEWF_FORMAT_UNKNOWN,
			&filenames, &numfiles, &error) != 1) {
		EWF_LOGF(stderr, "Globbing EWF files for '%s' failed!", bs->filename);
		ewf_print_error(stderr, error);
		goto on_error;  /* Failure! */
	}

	/* Prepare the handle pointer */
	if (libewf_handle_initialize(&(s->input_handle), &error) != 1) {
		EWF_LOGF(stderr, "Initializing handle for '%s' failed!", bs->filename);
		ewf_print_error(stderr, error);
		goto on_error;  /* Failure! */
	}

	/* Open a handle for globbed segment files */
	if (libewf_handle_open(s->input_handle, filenames, numfiles, LIBEWF_OPEN_READ, &error) != 1) {
		EWF_LOGF(stderr, "Opening handle for '%s' failed!", bs->filename);
		ewf_print_error(stderr, error);
		goto on_error;  /* Failure! */
	}

	/* Query the total number of sectors contained in EWF files */
	if (libewf_handle_get_number_of_sectors(s->input_handle, &number_of_sectors, &error) != 1) {
		EWF_LOGF(stderr, "Querying the number of sectors for '%s' failed!", bs->filename);
		ewf_print_error(stderr, error);
		goto on_error;
	}

	bs->total_sectors = (int64_t) number_of_sectors;

	/* Query the number of bytes per sector contained in EWF files */
	if (libewf_handle_get_bytes_per_sector(s->input_handle, &bytes_per_sector, &error) != 1) {
		EWF_LOGF(stderr, "Querying the number of bytes per sector for '%s' failed!", bs->filename);
		ewf_print_error(stderr, error);
		goto on_error;
	}

	s->bytes_per_sector = (int64_t) bytes_per_sector;

	EWF_LOGF(stdout, "File '%s' consists of %lu sectors.", bs->filename, number_of_sectors);
	EWF_LOGF(stdout, "File '%s' contains %u bytes per sector.", bs->filename, bytes_per_sector);

	/* Cleanup globbed filenames */
	if (libewf_glob_free(filenames, numfiles, &error) != 1)
		ewf_print_error(stderr, error);

	return 0;

	on_error: {

		if (s->input_handle != NULL) {
			if (libewf_handle_close(s->input_handle, &error) != 0)
				ewf_print_error(stderr, error);

			if (libewf_handle_free(&(s->input_handle), &error) != 1)
				ewf_print_error(stderr, error);
		}

		if (filenames != NULL) {
			/* Cleanup globbed filenames */
			if (libewf_glob_free(filenames, numfiles, &error) != 1)
				ewf_print_error(stderr, error);
		}

		return -1;
	}
}


static void ewf_close(BlockDriverState* bs)
{
	BDRVEwfState* s = (BDRVEwfState*) bs->opaque;
	libewf_error_t* error = NULL;

	if (s->input_handle == NULL)
		return;

	if (libewf_handle_close(s->input_handle, &error) != 0) {
		EWF_LOGF(stderr, "Closing EWF block-driver for '%s' failed!", bs->filename);
		ewf_print_error(stderr, error);
	}

	if (libewf_handle_free(&(s->input_handle), &error) != 1)
		ewf_print_error(stderr, error);
}


static int ewf_read(BlockDriverState* bs, int64_t sector_num, uint8_t* buf, int nb_sectors)
{
	BDRVEwfState* s = (BDRVEwfState*) bs->opaque;

	libewf_error_t* error = NULL;

	/* Compute offset and size of the EWF data */
	const size_t size = (size_t) s->bytes_per_sector * (size_t) nb_sectors;
	const off64_t offset = (off64_t) (sector_num * s->bytes_per_sector);

	/* Try to read requested blocks from EWF file */
	if (libewf_handle_read_buffer_at_offset(s->input_handle, buf, size, offset, &error) == -1) {
		EWF_LOGF(stderr, "Reading from '%s' failed!", bs->filename);
		ewf_print_error(stderr, error);
		return EIO;  /* Failure! */
	}

	return 0;
}


static BlockDriver bdrv_ewf = {
	.format_name = "ewf",
	.protocol_name = "ewf",
 	.instance_size = sizeof(BDRVEwfState),
 	.bdrv_probe = ewf_probe,
 	.bdrv_open = ewf_open,
	.bdrv_close = ewf_close,
	.bdrv_read = ewf_read,
};


static void bdrv_ewf_init(void)
{
    /*
     * Register all the drivers. Note that order is important,
     * the driver registered last will get probed first.
     */

    bdrv_register(&bdrv_ewf);
}

block_init(bdrv_ewf_init);
