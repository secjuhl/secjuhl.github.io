---
layout: default
title: Dirty Pipe Analysis
permalink: /dirtypipe/
---
This will be a short blog post covering the CVE-2022-0847, also known as the "Dirty Pipe".

This was inspired by the post at https://dirtypipe.cm4all.com/. I was reading alongside the 5.16.10 source code for this.

I will try to cover some code snippets that made this "click" for me.

Understanding the vulnerability:
What is a pipe buffer?
A pipe_buffer is an object used to describe an individual pipe object, with it's corresponding page. It'll usually be one of numerous pipe_buffers in a pipe.
It looks like this in practice.
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
The kernel writes to the pipe objects page through copy_page_from_iter. 
struct page is a structure that references the metadata of a 4096 byte physical address mapping in the kernel.
offset will be where we're writing in the page, and len will be how many bytes we write.
ops is a pointer to a bunch of functions, this is often targeted in object spraying, and used for exploitation as it can create an arbitrary call, due to the fact that the pipe will reference these through certain operations.
the flags cover a variety of behaviors that the kernel trusts, one of these flags is PIPE_BUF_FLAG_CAN_MERGE. Which is described as making buffer merging possible.
The vulnerability comes into play during splice.
ssize_t splice(int fd_in, off_t *_Nullable off_in,
                      int fd_out, off_t *_Nullable off_out,
                      size_t size, unsigned int flags);
In this vulnerability, splice assigns the struct page from the target file descriptor at fd_in to the fd_out file descriptor. This happens during https://elixir.bootlin.com/linux/v5.16.10/source/lib/iov_iter.c#L420.
This leaves the pipe_buffer referencing the memory that represents the file data.

Below is a backtrace, stopped in the referenced path. As observed in the source code, the pipe_buffer that has the page structure assigned, is at no point cleared for any flags.
#0  copy_page_to_iter_pipe (i=0xffffc90000197d80, bytes=0x1, offset=0x3e7, page=0xffffea000009e480) at lib/iov_iter.c:421
#1  __copy_page_to_iter (i=0xffffc90000197d80, bytes=0xc19, offset=0x3e7, page=0xffffea000009e480) at lib/iov_iter.c:860
#2  copy_page_to_iter (page=page@entry=0xffffea000009e480, offset=offset@entry=0x3e7, bytes=bytes@entry=0xc19,
    i=i@entry=0xffffc90000197d80) at lib/iov_iter.c:880
#3  0xffffffff811a668f in shmem_file_read_iter (iocb=0xffffc90000197da8, to=0xffffc90000197d80) at mm/shmem.c:2603
#4  0xffffffff8124280b in call_read_iter (iter=0xffffc90000197d80, kio=0xffffc90000197da8, file=0xffff888004394e00)
    at ./include/linux/fs.h:2156
#5  generic_file_splice_read (in=0xffff888004394e00, ppos=0xffffc90000197e58, pipe=<optimized out>, len=<optimized out>,
    flags=<optimized out>) at fs/splice.c:311
#6  0xffffffff8124394f in splice_file_to_pipe (in=in@entry=0xffff888004394e00, opipe=opipe@entry=0xffff88800432fd80,
    offset=offset@entry=0xffffc90000197e58, len=len@entry=0x1, flags=0x0) at fs/splice.c:1018
#7  0xffffffff81243e89 in do_splice (in=in@entry=0xffff888004394e00, off_in=off_in@entry=0xffffc90000197eb0,
    out=out@entry=0xffff888004394f00, off_out=off_out@entry=0x0 <fixed_percpu_data>, len=len@entry=0x1,
    flags=<optimized out>, flags@entry=0x0) at fs/splice.c:1104
#8  0xffffffff8124412c in __do_splice (in=in@entry=0xffff888004394e00, off_in=off_in@entry=0x7ffdb0689150,
    out=out@entry=0xffff888004394f00, off_out=off_out@entry=0x0 <fixed_percpu_data>, len=len@entry=0x1,
    flags=flags@entry=0x0) at fs/splice.c:1144
The lifetime of a pipe object, can be explained as. The pipe is written to, buf->len is increased, and if we read from it offset is incremented by the amount that we read, while buf->len is decremented based on iov_iter_count. If we've read all data, then the kernel considers the pipe object emptied, and so we move onto the next pipe object. Once all pipe objects have been fully emptied, we move back to the start of the objects, and start from the beginning.
This is shown at, the tail being incremented: https://elixir.bootlin.com/linux/v5.16.10/source/fs/pipe.c#L321
After splice and emptying the pipe buffers, if you now try to write to the pipe the pipe will be referencing the first pipe_buffer object. Of course the conditions at line 455 of pipe.c must also be met, the size of the data we write cannot be page boundary, as it will fail the & (PAGE_SIZE - 1)  check.
Source: https://elixir.bootlin.com/linux/v5.16.10/source/fs/pipe.c#L457
The head being incremented, resulting in indexing the first pipe_buffer object: https://elixir.bootlin.com/linux/v5.16.10/source/lib/iov_iter.c#L424
was_empty is a simple boolean check: https://elixir.bootlin.com/linux/v5.16.10/source/include/linux/pipe_fs_i.h#L134
In this case, if all buffs are emptied and we're starting over this will not equal true, making us pass this condition if we have exhausted all our pipe_buffers accurately, allowing attackers to write arbitrary data to files through a logical error which forgets to clear the flags of the pipe_buffer.
This is the first analysis, I'll be trying to get better at covering them, documenting them, and even posting some exploits that I make for CVEs I can find.
