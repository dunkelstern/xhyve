/*-
 * Copyright (c) 2013  Peter Grehan <grehan@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * The block API to be used by bhyve block-device emulations. The routines
 * are thread safe, with no assumptions about the context of the completion
 * callback - it may occur in the caller's context, or asynchronously in
 * another thread.
 */

#pragma once

#include <sys/uio.h>
#include <sys/unistd.h>

#define BLOCKIF_IOV_MAX 33 /* not practical to be IOV_MAX */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
struct blockif_req {
	struct iovec br_iov[BLOCKIF_IOV_MAX];
	int br_iovcnt;
	off_t br_offset;
	ssize_t br_resid;
	void (*br_callback)(struct blockif_req *req, int err);
	void *br_param;
};
#pragma clang diagnostic pop

typedef struct _blockif_ctxt *blockif_ctxt;

blockif_ctxt blockif_open(const char *optstr, const char *ident);
off_t blockif_size(blockif_ctxt bc);
void blockif_chs(blockif_ctxt bc, uint16_t *c, uint8_t *h, uint8_t *s);
int blockif_sectsz(blockif_ctxt bc);
void blockif_psectsz(blockif_ctxt bc, int *size, int *off);
int blockif_queuesz(blockif_ctxt bc);
int blockif_is_ro(blockif_ctxt bc);
int blockif_candelete(blockif_ctxt bc);
int blockif_read(blockif_ctxt bc, struct blockif_req *breq);
int blockif_write(blockif_ctxt bc, struct blockif_req *breq);
int blockif_flush(blockif_ctxt bc, struct blockif_req *breq);
int blockif_delete(blockif_ctxt bc, struct blockif_req *breq);
int blockif_cancel(blockif_ctxt bc, struct blockif_req *breq);
int blockif_close(blockif_ctxt bc);
