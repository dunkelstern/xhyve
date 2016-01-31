/*-
 * Copyright (c) 2013  Peter Grehan <grehan@freebsd.org>
 * Copyright (c) 2015 xhyve developers
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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/disk.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <dispatch/dispatch.h>

#include <xhyve/support/atomic.h>
#include <xhyve/xhyve.h>
#include <xhyve/mevent.h>
#include <xhyve/block_if.h>

#define BLOCKIF_SIG 0xb109b109

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

struct _blockif_ctxt {
	int magic;

    // backing file fds
	int *fd;
	unsigned long num_fd;

    // sparse lookup table
    int is_sparse;
    int sparse_fd;
    uint32_t *sparse_lut;
    uint32_t sparse_lut_size;
    
	int can_delete;
	int is_readonly;
	size_t size;
	size_t split_size;
	int sect_size;
	int phys_sect_size;
	int phys_sect_offset;
    
    dispatch_queue_t response_queue;
};


#pragma clang diagnostic pop


static inline int blockif_get_fd(blockif_ctxt bc, size_t offset) {
	if (bc->split_size) {
		unsigned long i = offset / bc->split_size;
        if (i >= bc->num_fd) {
            return -1;
        }
		return bc->fd[i];
	} else {
		return bc->fd[0];
	}
}

static ssize_t blockif_sparse_read(blockif_ctxt bc, size_t disk_offset, size_t segment_offset, uint8_t *buf, size_t len) {
    int fd = blockif_get_fd(bc, disk_offset);
    if (fd < 0) {
        errno = EFAULT;
        return -1;
    }
    size_t sector_size = (size_t)bc->sect_size;
    size_t block = 0;

    if (bc->split_size) {
        // split file image, add file segment offset
        size_t i = (disk_offset / (size_t)bc->split_size);
        block += i * (bc->split_size / sector_size);
    }

    // read
    size_t remaining = len;
    while (remaining > 0) {
        size_t current_block = block + (segment_offset / sector_size);
        if (current_block > bc->size / sector_size) {
            fprintf(stderr, "reading past end of disk, requested block %zu of %zu (offset: %zu)\n", current_block, bc->size / sector_size, disk_offset);
            errno = EFAULT;
            return -1;
        }
        
        size_t shift_offset = segment_offset % sector_size; // offset _in_ a sector
        size_t read_len = (remaining > sector_size) ? sector_size : remaining;
        
        uint32_t lut_entry = bc->sparse_lut[current_block];
        if (lut_entry < 0xffffffff) {
            // allocated block, get offset and read from file
            size_t seek_offset = lut_entry * sector_size + shift_offset;
            lseek(fd, (off_t)seek_offset, SEEK_SET);
            
            ssize_t result;
            do {
                result = read(fd, buf, read_len - shift_offset);
            } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));

            if (result < 0) {
                return result;
            }
        } else {
            // sparse block, fill buffer with zeroes
            memset(buf, 0, read_len - shift_offset);
        }
        
        // advance buffer
        if (remaining > sector_size - shift_offset) {
            remaining -= sector_size - shift_offset;
            buf += sector_size - shift_offset;
            segment_offset += sector_size - shift_offset;
        } else {
            remaining = 0;
        }
    }
    
    return (ssize_t)len;
}

static ssize_t blockif_sparse_write(blockif_ctxt bc, size_t disk_offset, size_t segment_offset, uint8_t *buf, size_t len) {
    int fd = blockif_get_fd(bc, disk_offset);
    if (fd < 0) {
        errno = EFAULT;
        return -1;
    }

    size_t sector_size = (size_t)bc->sect_size;
    size_t block = 0;
    
    if (bc->split_size) {
        // split file image, add file segment offset
        size_t i = (disk_offset / (size_t)bc->split_size);
        block += i * (bc->split_size / sector_size);
    }
    
    // read
    size_t remaining = len;
    while (remaining > 0) {
        size_t current_block = block + (segment_offset / sector_size);
        if (current_block > bc->size / sector_size) {
            fprintf(stderr, "writing past end of disk, requested block %zu of %zu (offset: %zu)\n", current_block, bc->size / sector_size, disk_offset);
            errno = EFAULT;
            return -1;
        }

        size_t shift_offset = segment_offset % sector_size; // offset _in_ a sector
        size_t write_len = (remaining > sector_size) ? sector_size : remaining;
        
        uint32_t lut_entry = bc->sparse_lut[current_block];
        if (lut_entry < 0xffffffff) {
            // allocated block, get offset and read from file
            size_t seek_offset = lut_entry * sector_size + shift_offset;
            lseek(fd, (off_t)seek_offset, SEEK_SET);
            
            ssize_t result;
            do {
                result = write(fd, buf, write_len - shift_offset);
            } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));

            if (result < 0) {
                return result;
            }
        } else {
            // sparse block, append to file
            ssize_t result;
            
            // check if the buffer is zeroes only
            int zeroes_only = 1;
            if (write_len % 8 == 0) {
                for (uint64_t *ptr = (uint64_t *)buf; ptr < (uint64_t *)(buf + write_len - shift_offset); ptr++) {
                    if (*ptr != 0) {
                        zeroes_only = 0;
                        break;
                    }
                }
            } else {
                for (uint8_t *ptr = buf; ptr < buf + write_len - shift_offset; ptr++) {
                    if (*ptr != 0) {
                        zeroes_only = 0;
                        break;
                    }
                }
            }
            if (!zeroes_only) {
                // save sector offset into lut
                off_t size = lseek(fd, 0, SEEK_END);
                bc->sparse_lut[current_block] = (uint32_t)((size_t)size / (size_t)sector_size);
                lseek(bc->sparse_fd, (off_t)(current_block * 4), SEEK_SET);
                do {
                    result = write(bc->sparse_fd, bc->sparse_lut + current_block, 4);
                } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));
                if (result < 0) {
                    return result;
                }
                fsync(bc->sparse_fd);
                
                // create sector
                lseek(fd, 0, SEEK_END);
                char zeroBuffer[sector_size];
                memset(zeroBuffer, 0, sector_size);
                write(fd, zeroBuffer, sector_size);
                
                // overwrite with data
                size_t seek_offset = bc->sparse_lut[current_block] * sector_size + shift_offset;
                lseek(fd, (off_t)seek_offset, SEEK_SET);
                do {
                    result = write(fd, buf, write_len - shift_offset);
                } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));

                if (result < 0) {
                    return result;
                }
                fsync(fd);
            }
        }
        
        // advance buffer
        if (remaining > sector_size - shift_offset) {
            remaining -= sector_size - shift_offset;
            buf += sector_size - shift_offset;
            segment_offset += sector_size - shift_offset;
        } else {
            remaining = 0;
        }
    }
    
    return (ssize_t)len;
}

static ssize_t blockif_read_data(blockif_ctxt bc, uint8_t *buf, size_t len, size_t offset) {
	// find correct fd
	int fd = blockif_get_fd(bc, offset);
    if (fd < 0) {
        errno = EFAULT;
        return -1;
    }

	ssize_t bytes = 0;
   
    if (!bc->is_sparse) {
        if (bc->split_size) {
            lseek(fd, (off_t)(offset % bc->split_size), SEEK_SET);
        } else {
            lseek(fd, (off_t)offset, SEEK_SET);
        }
    }
    
	// is this a multi part read
	if ((bc->split_size) && (offset % bc->split_size + len > bc->split_size)) {
		// read is longer than current segment

		// read until end of segment
		size_t len1 = bc->split_size - (offset % bc->split_size);
        do {
            if (bc->is_sparse) {
                bytes = blockif_sparse_read(bc, offset, (offset % bc->split_size), buf, len1);
            } else {
                bytes = read(fd, buf, len1);
            }
        } while ((bytes < 0) && ((errno == EAGAIN) || (errno == EINTR)));
		if (bytes < 0) {
			return bytes;
		}

		// get next fd and read the rest
		size_t len2 = len - len1;
		fd = blockif_get_fd(bc, offset + len1);

        ssize_t result;
        do {
            if (bc->is_sparse) {
                result = blockif_sparse_read(bc, offset + len1, 0, buf + len1, len2);
            } else {
                lseek(fd, 0, SEEK_SET);
                result = read(fd, buf + len1, len2);
            }
        } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));
        
		if (result < 0) {
			return result;
		}
		bytes += result;
	} else {
		// read does not cross segment border
        do {
            if (bc->is_sparse) {
                bytes = blockif_sparse_read(bc, offset, (offset % bc->split_size), buf, len);
            } else {
                bytes = read(fd, buf, len);
            }
        } while ((bytes < 0) && ((errno == EAGAIN) || (errno == EINTR)));
	}

	// return read bytes
	return bytes;
}

static ssize_t blockif_write_data(blockif_ctxt bc, uint8_t *buf, size_t len, size_t offset) {
	// find correct fd
	int fd = blockif_get_fd(bc, offset);
    if (fd < 0) {
        errno = EFAULT;
        return -1;
    }

	ssize_t bytes = 0;

    if (!bc->is_sparse) {
        if (bc->split_size) {
            lseek(fd, (off_t)(offset % bc->split_size), SEEK_SET);
        } else {
            lseek(fd, (off_t)offset, SEEK_SET);
        }
    }

	// is this a multi part write
	if ((bc->split_size) && (offset % bc->split_size + len > bc->split_size)) {
		// write is longer than current segment

		// write until end of segment
		size_t len1 = bc->split_size - (offset % bc->split_size);
        do {
            if (bc->is_sparse) {
                bytes = blockif_sparse_write(bc, offset, (offset % bc->split_size), buf, len1);
            } else {
                bytes = write(fd, buf, len1);
            }
        } while ((bytes < 0) && ((errno == EAGAIN) || (errno == EINTR)));
        
		if (bytes < 0) {
			return bytes;
		}

		// get next fd and write the rest
		size_t len2 = len - len1;
		fd = blockif_get_fd(bc, offset + len1);
        
        ssize_t result;
        do {
            if (bc->is_sparse) {
                result = blockif_sparse_write(bc, offset + len1, 0, buf + len1, len2);
            } else {
                lseek(fd, 0, SEEK_SET);
                result = write(fd, buf + len1, len2);
            }
        } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));

		if (result < 0) {
			return result;
		}
		bytes += result;
	} else {
		// write does not cross segment border
        do {
            if (bc->is_sparse) {
                bytes = blockif_sparse_write(bc, offset, (offset % bc->split_size), buf, len);
            } else {
                bytes = write(fd, buf, len);
            }
        } while ((bytes < 0) && ((errno == EAGAIN) || (errno == EINTR)));
	}

	// return written bytes
	return bytes;
}

blockif_ctxt blockif_open(const char *optstr, UNUSED const char *ident) {
	blockif_ctxt bc;
    
    bc = calloc(1, sizeof(struct _blockif_ctxt));
    if (bc == NULL) {
        perror("calloc");
        return NULL;
    }
    
    bc->magic = (int) BLOCKIF_SIG;
    bc->response_queue = dispatch_queue_create("org.xhyve.blockif.response", DISPATCH_QUEUE_SERIAL);

	/*
	 * The first element in the optstring is always a pathname.
	 * Optional elements follow
	 */
    int extra = 0;
    int ssopt = 0, pssopt = 0;
    char *nopt, *xopts, *cp, tmp[255];
	nopt = xopts = strdup(optstr);
	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
        if (cp == nopt) {		/* file or device pathname */
			continue;
        } else if (!strcmp(cp, "nocache")) {
            perror("xhyve: nocache support unimplemented");
            blockif_close(bc);
            return NULL;
        } else if (!strcmp(cp, "sync") || !strcmp(cp, "direct")) {
            extra |= O_SYNC;
        } else if (!strcmp(cp, "ro")) {
			bc->is_readonly = 1;
        } else if (sscanf(cp, "sectorsize=%d/%d", &ssopt, &pssopt) == 2) {
            // not further actions
        } else if (sscanf(cp, "sectorsize=%d", &ssopt) == 1) {
			pssopt = ssopt;
        } else if (sscanf(cp, "size=%s", tmp) == 1) {
			uint64_t num = 0;
			if (expand_number(tmp, &num)) {
                perror("xhyve: could not parse size parameter");
                blockif_close(bc);
                return NULL;
			}
			bc->size = (size_t)num;
		} else if (sscanf(cp, "split=%s", tmp) == 1) { /* split into chunks */
			uint64_t num = 0;
			if (expand_number(tmp, &num)) {
                perror("xhyve: could not parse split parameter");
                blockif_close(bc);
                return NULL;
			}
            bc->split_size = (size_t)num;
		} else if (!strcmp(cp, "sparse")) {
            bc->is_sparse = 1;
        } else {
			fprintf(stderr, "Invalid device option \"%s\"\n", cp);
            blockif_close(bc);
            return NULL;
		}
	}
    
    if (bc->split_size != 0) {
        // open multiple files
        if (bc->size == 0) {
            perror("xhyve: when using 'split' a 'size' is required!");
            blockif_close(bc);
            return NULL;
        }

        bc->num_fd = (bc->size / bc->split_size) + 1;
        bc->fd = malloc(sizeof(int) * bc->num_fd);
        for (size_t i = 0; i < bc->num_fd; i++) {
            bc->fd[i] = -1;
        }

        printf("Split disk, opening %zu image parts\n", bc->num_fd);

        for (size_t i = 0; i < bc->num_fd; i++) {
            size_t len = strlen(nopt) + 6;
            char *filename = calloc(len, 1);
            snprintf(filename, len, "%s.%04zu", nopt, i);

            printf(" - %s\n", filename);

            bc->fd[i] = open(filename, (bc->is_readonly ? O_RDONLY : O_RDWR | O_CREAT) | extra);
            if (bc->fd[i] < 0 && !bc->is_readonly) {
                perror("Could not open backing file r/w, reverting to readonly");
                /* Attempt a r/w fail with a r/o open */
                bc->fd[i] = open(filename, O_RDONLY | extra);
                bc->is_readonly = 1;
            }
            free(filename);

            if (bc->fd[i] < 0) {
                perror("Could not open backing file");
                blockif_close(bc);
                return NULL;
            }

            if (lseek(bc->fd[i], 0, SEEK_END) == 0) {
                // create image file
                fchmod(bc->fd[i], 0660);
                if (!bc->is_sparse) {
                    printf("   -> file does not exist, creating empty file\n");

                    char buffer[1024];
                    memset(buffer, 0, 1024);
                    for(size_t j = 0; j < bc->split_size / 1024; j++) {
                        ssize_t result;
                        do {
                            result = write(bc->fd[i], buffer, 1024);
                        } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));
                    }
                }
                lseek(bc->fd[i], 0, SEEK_SET);
            }
        }
    } else {
        // open a single file
        printf("Single image disk\n");

        bc->fd = malloc(sizeof(int));
        bc->fd[0] = -1;

        bc->fd[0] = open(nopt, (bc->is_readonly ? O_RDONLY : O_RDWR | O_CREAT) | extra);
        if (bc->fd[0] < 0 && !bc->is_readonly) {
            perror("Could not open backing file r/w, reverting to readonly");
            /* Attempt a r/w fail with a r/o open */
            bc->fd[0] = open(nopt, O_RDONLY | extra);
            bc->is_readonly = 1;
        }

        if (bc->fd[0] < 0) {
            perror("Could not open backing file");
            blockif_close(bc);
            return NULL;
        }

        if (lseek(bc->fd[0], 0, SEEK_END) == 0) {
            // TODO: make growing disks possible
            // create image file
            fchmod(bc->fd[0], 0660);
            if (!bc->is_sparse) {
                printf(" -> file does not exist, creating empty file\n");
                char buffer[1024];
                memset(buffer, 0, 1024);
                for(size_t i = 0; i < bc->size / 1024; i++) {
                    ssize_t result;
                    do {
                        result = write(bc->fd[0], buffer, 1024);
                    } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));
                }
            }
        }
        bc->size = (size_t)lseek(bc->fd[0], 0, SEEK_END);
    }
    
    /*
     * Deal with raw devices
     */
    bc->sect_size = DEV_BSIZE;
    bc->phys_sect_offset = 0;
    bc->can_delete = 0;
    struct stat sbuf;
    if (fstat(bc->fd[0], &sbuf)) {
        fprintf(stderr, "Could not stat first disk image file, assuming physical sector size of 512!\n");
        bc->phys_sect_size = 512;
    } else {
        bc->phys_sect_size = (int)sbuf.st_blksize;
    }

    if ((bc->split_size == 0) && (S_ISCHR(sbuf.st_mode))) {
        off_t blocks;
        if (ioctl(bc->fd[0], DKIOCGETBLOCKCOUNT, &blocks) < 0 ||
            ioctl(bc->fd[0], DKIOCGETBLOCKSIZE, &bc->sect_size))
        {
            perror("Could not fetch dev blk/sector size");
            blockif_close(bc);
            return NULL;
        }
        assert(blocks != 0);
        assert(bc->sect_size != 0);
        
        bc->size = (size_t)(blocks * bc->sect_size);
    }
    
    if (ssopt != 0) {
        if (!powerof2(ssopt) || !powerof2(pssopt) || ssopt < 512 ||
            ssopt > pssopt) {
            fprintf(stderr, "Invalid sector size %d/%d\n",
                ssopt, pssopt);
            blockif_close(bc);
            return NULL;
        }

        /*
         * Some backend drivers (e.g. cd0, ada0) require that the I/O
         * size be a multiple of the device's sector size.
         *
         * Validate that the emulated sector size complies with this
         * requirement.
         */
        if (S_ISCHR(sbuf.st_mode)) {
            if (ssopt < bc->sect_size || (ssopt % bc->sect_size) != 0) {
                fprintf(stderr, "Sector size %d incompatible "
                        "with underlying device sector size %d\n",
                        ssopt, bc->sect_size);
                blockif_close(bc);
                return NULL;
            }
        }
        
        bc->sect_size = ssopt;
        bc->phys_sect_size = (int)pssopt;
        bc->phys_sect_offset = 0;
    }

    if (bc->is_sparse) {
        size_t len = strlen(nopt) + 6;
        char *filename = calloc(len, 1);
        snprintf(filename, len, "%s.lut", nopt);
        
        // open lut file
        bc->sparse_fd = open(filename, (bc->is_readonly ? O_RDONLY : O_RDWR | O_CREAT) | extra);
        if (bc->sparse_fd < 0 && !bc->is_readonly) {
            perror("Could not open sparse lut file r/w, reverting to readonly");
            /* Attempt a r/w fail with a r/o open */
            bc->sparse_fd = open(filename, O_RDONLY | extra);
            bc->is_readonly = 1;
        }
        free(filename);
        
        if (bc->sparse_fd < 0) {
            perror("Could not open sparse lut file");
            blockif_close(bc);
            return NULL;
        }
        
        size_t lut_size = (size_t)lseek(bc->sparse_fd, 0, SEEK_END);
        if (lut_size == 0) {
            // TODO: make growing disks possible
            // create lut file
            printf(" -> sparse lut file does not exist, creating empty file\n");
            fchmod(bc->sparse_fd, 0660);
            unsigned char buffer[4] = { 0xff, 0xff, 0xff, 0xff };
            for(size_t i = 0; i < bc->size / (size_t)bc->sect_size; i++) {
                ssize_t result;
                do {
                    result = write(bc->sparse_fd, buffer, 4);
                } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));
            }
            fsync(bc->sparse_fd);
            lut_size = (size_t)lseek(bc->sparse_fd, 0, SEEK_END);
        }
        
        if (lut_size == 0) {
            fprintf(stderr, "Could not initialize sparse lookup table\n");
            blockif_close(bc);
            return NULL;
        }
        
        // read sparse lut
        bc->sparse_lut = malloc((size_t)lut_size);
        bc->sparse_lut_size = (uint32_t)lut_size;
        ssize_t bytes = 0;
        lseek(bc->sparse_fd, 0, SEEK_SET);
        for (size_t i = 0; i < lut_size; i += 4096) {
            ssize_t result;
            do {
                result = read(bc->sparse_fd, ((char *)bc->sparse_lut) + i, 4096);
            } while ((result < 0) && ((errno == EAGAIN) || (errno == EINTR)));
            
            if (result < 0) {
                perror("Could not load sparse lut");
                blockif_close(bc);
                return NULL;
            }
            bytes += result;
        }
    }


    if (bc->magic == ((int) BLOCKIF_SIG)) {
        return bc;
    }
    return NULL;
}

int blockif_read(blockif_ctxt bc, struct blockif_req *br) {
    assert(bc->magic == ((int) BLOCKIF_SIG));
    dispatch_async(bc->response_queue, ^{
        int err = 0;
        assert(bc->magic == ((int) BLOCKIF_SIG));
        
        // as we have to account for split disk images we disassemble
        // the iovec buffers and call read for each of them
        size_t offset = (size_t)br->br_offset;
        for(int i = 0; i < br->br_iovcnt; i++) {
            ssize_t len = blockif_read_data(bc, br->br_iov[i].iov_base, br->br_iov[i].iov_len, offset);
            if (len < 0) {
                err = errno;
            } else {
                br->br_resid -= len;
            }
            offset += br->br_iov[i].iov_len;
        }

        (*br->br_callback)(br, err);
    });
	return 0;
}

int blockif_write(blockif_ctxt bc, struct blockif_req *br) {
    assert(bc->magic == ((int) BLOCKIF_SIG));
    dispatch_barrier_async(bc->response_queue, ^{
        int err = 0;
        assert(bc->magic == ((int) BLOCKIF_SIG));
        
        if (bc->is_readonly) {
            err = EROFS;
        } else {
            // as we have to account for split disk images we disassemble
            // the iovec buffers and call write for each of them
            size_t offset = (size_t)br->br_offset;
            for(int i = 0; i < br->br_iovcnt; i++) {
                ssize_t len = blockif_write_data(bc, br->br_iov[i].iov_base, br->br_iov[i].iov_len, offset);
                if (len < 0) {
                    err = errno;
                } else {
                    br->br_resid -= len;
                }
                offset += br->br_iov[i].iov_len;
            }
        }
        
        (*br->br_callback)(br, err);
    });
    return 0;
}

int blockif_flush(blockif_ctxt bc, struct blockif_req *br) {
    assert(bc->magic == ((int) BLOCKIF_SIG));

    dispatch_barrier_async(bc->response_queue, ^{
        int err = 0;
        assert(bc->magic == ((int) BLOCKIF_SIG));

        for(unsigned long i = 0; i < bc->num_fd; i++) {
            if (fsync(bc->fd[i])) {
                err = errno;
            }
        }

        (*br->br_callback)(br, err);
    });
	return 0;
}

int blockif_delete(blockif_ctxt bc, struct blockif_req *br) {
	assert(bc->magic == ((int) BLOCKIF_SIG));
    
    dispatch_barrier_async(bc->response_queue, ^{
        assert(bc->magic == ((int) BLOCKIF_SIG));
        (*br->br_callback)(br, EOPNOTSUPP);
    });
    return 0;
}

int blockif_cancel(blockif_ctxt bc, struct blockif_req *br) {
	assert(bc->magic == ((int) BLOCKIF_SIG));

    // nothing to cancel really, just call the callback and ignore the call
    dispatch_barrier_async(bc->response_queue, ^{
        assert(bc->magic == ((int) BLOCKIF_SIG));
        (*br->br_callback)(br, 0);
    });
	return 0;
}

int blockif_close(blockif_ctxt bc) {
	assert(bc->magic == ((int) BLOCKIF_SIG));
    dispatch_barrier_async(bc->response_queue, ^{
        assert(bc->magic == ((int) BLOCKIF_SIG));

        // Release resources
        bc->magic = 0;
        if (bc->fd) {
            for(unsigned long i = 0; i < bc->num_fd; i++) {
                if (bc->fd[i] >= 0) {
                    close(bc->fd[i]);
                }
            }
            free(bc->fd);
        }
        
        if (bc->is_sparse) {
            if (bc->sparse_fd >= 0) {
                close(bc->sparse_fd);
            }
            if (bc->sparse_lut) {
                free(bc->sparse_lut);
            }
        }
        free(bc);
    });
	return 0;
}

/*
 * Return virtual C/H/S values for a given block. Use the algorithm
 * outlined in the VHD specification to calculate values.
 */
void blockif_chs(blockif_ctxt bc, uint16_t *c, uint8_t *h, uint8_t *s) {
	off_t sectors;		/* total sectors of the block dev */
	off_t hcyl;		/* cylinders times heads */
	uint16_t secpt;		/* sectors per track */
	uint8_t heads;

	assert(bc->magic == ((int) BLOCKIF_SIG));

	sectors = (off_t)(bc->size / (size_t)bc->sect_size);

	/* Clamp the size to the largest possible with CHS */
    if (sectors > 65535LL*16*255) {
		sectors = 65535LL*16*255;
    }

	if (sectors >= 65536LL*16*63) {
		secpt = 255;
		heads = 16;
		hcyl = sectors / secpt;
	} else {
		secpt = 17;
		hcyl = sectors / secpt;
		heads = (uint8_t) ((hcyl + 1023) / 1024);

        if (heads < 4) {
			heads = 4;
        }

		if (hcyl >= (heads * 1024) || heads > 16) {
			secpt = 31;
			heads = 16;
			hcyl = sectors / secpt;
		}
		if (hcyl >= (heads * 1024)) {
			secpt = 63;
			heads = 16;
			hcyl = sectors / secpt;
		}
	}

	*c = (uint16_t) (hcyl / heads);
	*h = heads;
	*s = (uint8_t) secpt;
}

/*
 * Accessors
 */
off_t blockif_size(blockif_ctxt bc) {
	assert(bc->magic == ((int) BLOCKIF_SIG));
	return (off_t)(bc->size);
}

int blockif_sectsz(blockif_ctxt bc) {
	assert(bc->magic == ((int) BLOCKIF_SIG));
	return (bc->sect_size);
}

void blockif_psectsz(blockif_ctxt bc, int *size, int *off) {
	assert(bc->magic == ((int) BLOCKIF_SIG));
	*size = bc->phys_sect_size;
	*off = bc->phys_sect_offset;
}

int blockif_queuesz(blockif_ctxt bc) {
	assert(bc->magic == ((int) BLOCKIF_SIG));
	return 128;
}

int blockif_is_ro(blockif_ctxt bc) {
	assert(bc->magic == ((int) BLOCKIF_SIG));
	return (bc->is_readonly);
}

int blockif_candelete(blockif_ctxt bc) {
	assert(bc->magic == ((int) BLOCKIF_SIG));
	return (bc->can_delete);
}
