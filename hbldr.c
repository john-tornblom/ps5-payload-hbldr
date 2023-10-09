/* Copyright (C) 2023 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <arpa/inet.h>
#include <elf.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "mdbg.h"
#include "pt.h"


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? (PROT_READ | 0x10)  : 0) |	\
		     (((x) & PF_W) ? (PROT_WRITE | 0x20) : 0) |	\
		     (((x) & PF_X) ? PROT_EXEC  : 0))


#ifndef IPV6_2292PKTOPTIONS
#define IPV6_2292PKTOPTIONS 25
#endif

/**
 * Parameters for the HB loader.
 **/
#define HBLDR_UNIX_SOCKET "/system_tmp/hbldr.sock"


typedef struct app_launch_ctx {
  uint32_t structsize;
  uint32_t user_id;
  uint32_t app_opt;
  uint64_t crash_report;
  uint32_t check_flag;
} app_launch_ctx_t;


int sceUserServiceGetForegroundUser(uint32_t *user_id);
int sceSystemServiceGetAppIdOfRunningBigApp(void);
int sceSystemServiceKillApp(int app_id, int how, int reason, int core_dump);
int sceSystemServiceLaunchApp(const char* title_id, const char** argv,
			      app_launch_ctx_t* ctx);


intptr_t
kernel_get_proc_file(pid_t pid, int fd) {
  intptr_t fd_files;
  intptr_t fde_file;
  intptr_t file;
  intptr_t proc;
  intptr_t p_fd;

  if(!(proc=kernel_get_proc(pid))) {
    return 0;
  }

  if(kernel_copyout(proc + 0x48, &p_fd, sizeof(p_fd))) {
    return 0;
  }

  if(kernel_copyout(p_fd, &fd_files, sizeof(fd_files))) {
    return 0;
  }

  if(kernel_copyout(fd_files + 8 + (0x30 * fd),
		    &fde_file, sizeof(fde_file))) {
    return 0;
  }

  if(kernel_copyout(fde_file, &file, sizeof(file))) {
    return 0;
  }

  return file;
}


static intptr_t
kernel_get_proc_inp6_outputopts(pid_t pid, int fd) {
  intptr_t inp6_outputopts;
  intptr_t so_pcb;
  intptr_t file;

  if(!(file=kernel_get_proc_file(pid, fd))) {
    return 0;
  }

  if(kernel_copyout(file + 0x18, &so_pcb, sizeof(so_pcb))) {
    return 0;
  }

  if(kernel_copyout(so_pcb + 0x120, &inp6_outputopts,
		    sizeof(inp6_outputopts))) {
    return 0;
  }

  return inp6_outputopts;
}



static int
kernel_inc_so_count(pid_t pid, int fd) {
  intptr_t file;
  int so_count;

  if(!(file=kernel_get_proc_file(pid, fd))) {
    return -1;
  }

  if(kernel_copyout(file, &so_count, sizeof(so_count))) {
    return -1;
  }

  so_count++;
  if(kernel_copyin(&so_count, file, sizeof(so_count))) {
    return -1;
  }
  return 0;
}


int
kernel_overlap_sockets(pid_t pid, int master_sock, int victim_sock) {
  intptr_t master_inp6_outputopts;
  intptr_t victim_inp6_outputopts;
  intptr_t pktinfo;
  unsigned int tclass;

  if(kernel_inc_so_count(pid, master_sock)) {
    return -1;
  }

  if(!(master_inp6_outputopts=kernel_get_proc_inp6_outputopts(pid,
							      master_sock))) {
    return -1;
  }

  if(kernel_inc_so_count(pid, victim_sock)) {
    return -1;
  }

  if(!(victim_inp6_outputopts=kernel_get_proc_inp6_outputopts(pid,
							      victim_sock))) {
    return -1;
  }

  pktinfo = victim_inp6_outputopts + 0x10;
  if(kernel_copyin(&pktinfo, master_inp6_outputopts + 0x10,
		   sizeof(pktinfo))) {

    return -1;
  }

  tclass = 0x13370000;
  if(kernel_copyin(&tclass, master_inp6_outputopts + 0xc0, sizeof(tclass))) {
    return -1;
  }

  return 0;
}



/**
 * Load an ELF into the address space of a process with the given pid.
 **/
static intptr_t
hbldr_load(pid_t pid, uint8_t *elf, size_t size) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  intptr_t base_addr = -1;
  size_t base_size = 0;

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

  // Sanity check, we only support 64bit ELFs.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    puts("[hbldr.elf] hbldr_load: Malformed ELF file");
    return 0;
  }

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  base_size = max_vaddr - min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if(ehdr->e_type == ET_DYN) {
    base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    puts("[hbldr.elf] hbldr_load: ELF type not supported");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((base_addr=pt_mmap(pid, base_addr, base_size, PROT_NONE,
			flags, -1, 0)) == -1) {
    pt_perror(pid, "[hbldr.elf] pt_mmap");
    return 0;
  }

  // Commit segments to reserved address space.
  for(int i=0; i<ehdr->e_phnum; i++) {
    size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
    intptr_t addr = base_addr + phdr[i].p_vaddr;
    int alias_fd = -1;
    int shm_fd = -1;

    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_flags & PF_X) {
      if((shm_fd=pt_jitshm_create(pid, 0, aligned_memsz,
				  PROT_WRITE | PFLAGS(phdr[i].p_flags))) < 0) {
	pt_perror(pid, "[hbldr.elf] pt_jitshm_create");
	error = 1;
	break;
      }

      if((addr=pt_mmap(pid, addr, aligned_memsz, PFLAGS(phdr[i].p_flags),
		       MAP_FIXED | MAP_SHARED, shm_fd, 0)) == -1) {
	pt_perror(pid, "[hbldr.elf] pt_mmap");
	error = 1;
	break;
      }

      if((alias_fd=pt_jitshm_alias(pid, shm_fd, PROT_WRITE | PROT_READ)) < 0) {
	pt_perror(pid, "[hbldr.elf] pt_jitshm_alias");
	error = 1;
	break;
      }

      if((addr=pt_mmap(pid, 0, aligned_memsz, PROT_WRITE | PROT_READ,
		       MAP_SHARED, alias_fd, 0)) == -1) {
	pt_perror(pid, "[hbldr.elf] pt_mmap");
	error = 1;
	break;
      }

      if(pt_copyin(pid, elf + phdr[i].p_offset, addr, phdr[i].p_memsz)) {
	pt_perror(pid, "[hbldr.elf] pt_copyin");
	error = 1;
	break;
      }

      pt_munmap(pid, addr, aligned_memsz);
      pt_close(pid, alias_fd);
      pt_close(pid, shm_fd);
    } else {
      if((addr=pt_mmap(pid, addr, aligned_memsz, PROT_WRITE,
		       MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		       -1, 0)) == -1) {
	pt_perror(pid, "[hbldr.elf] pt_mmap");
	error = 1;
	break;
      }
      if(pt_copyin(pid, elf + phdr[i].p_offset, addr, phdr[i].p_memsz)) {
	pt_perror(pid, "[hbldr.elf] pt_copyin");
	error = 1;
	break;
      }
    }
  }

  // Relocate positional independent symbols.
  for(int i=0; i<ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {
      if((rela[j].r_info & 0xffffffffl) == R_X86_64_RELATIVE) {
	intptr_t value_addr = (base_addr + rela[j].r_offset);
	intptr_t value = base_addr + rela[j].r_addend;
	if(pt_copyin(pid, &value, value_addr, 8)) {
	  pt_perror(pid, "[hbldr.elf] pt_copyin");
	  error = 1;
	  break;
	}
      }
    }
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
    intptr_t addr = base_addr + phdr[i].p_vaddr;

    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(pt_mprotect(pid, addr, aligned_memsz, PFLAGS(phdr[i].p_flags))) {
      pt_perror(pid, "[hbldr.elf] pt_mprotect");
      error = 1;
      break;
    }
  }

  if(error) {
    pt_munmap(pid, base_addr, base_size);
    return 0;
  }

  return base_addr + ehdr->e_entry;
}


/**
 * Create payload args in the address space of the process with the given pid.
 **/
intptr_t
hbldr_args(pid_t pid) {
  int victim_sock;
  int master_sock;
  intptr_t buf;
  int pipe0;
  int pipe1;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "[hbldr.elf] pt_mmap");
    return 0;
  }

  if((master_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "[hbldr.elf] pt_socket");
    return 0;
  }

  pt_setint(pid, buf+0x00, 20);
  pt_setint(pid, buf+0x04, IPPROTO_IPV6);
  pt_setint(pid, buf+0x08, IPV6_TCLASS);
  pt_setint(pid, buf+0x0c, 0);
  pt_setint(pid, buf+0x10, 0);
  pt_setint(pid, buf+0x14, 0);
  if(pt_setsockopt(pid, master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, 24)) {
    pt_perror(pid, "[hbldr.elf] pt_setsockopt");
    return 0;
  }

  if((victim_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "[hbldr.elf] pt_socket");
    return 0;
  }

  pt_setint(pid, buf+0x00, 0);
  pt_setint(pid, buf+0x04, 0);
  pt_setint(pid, buf+0x08, 0);
  pt_setint(pid, buf+0x0c, 0);
  pt_setint(pid, buf+0x10, 0);
  if(pt_setsockopt(pid, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20)) {
    pt_perror(pid, "[hbldr.elf] pt_setsockopt");
    return 0;
  }

  if(kernel_overlap_sockets(pid, master_sock, victim_sock)) {
    puts("[hbldr.elf] kernel_overlap_sockets() failed");
    return 0;
  }

  if(pt_pipe(pid, buf)) {
    pt_perror(pid, "[hbldr.elf] pt_pipe");
    return 0;
  }
  pipe0 = pt_getint(pid, buf);
  pipe1 = pt_getint(pid, buf+4);

  intptr_t args       = buf;
  intptr_t dlsym      = kernel_dynlib_resolve(pid, 0x2001, "LwG8g3niqwA");
  intptr_t rwpipe     = buf + 0x100;
  intptr_t rwpair     = buf + 0x200;
  intptr_t kpipe_addr = kernel_get_proc_file(pid, pipe0);
  intptr_t payloadout = buf + 0x300;

  pt_setlong(pid, args + 0x00, dlsym);
  pt_setlong(pid, args + 0x08, rwpipe);
  pt_setlong(pid, args + 0x10, rwpair);
  pt_setlong(pid, args + 0x18, kpipe_addr);
  pt_setlong(pid, args + 0x20, KERNEL_ADDRESS_DATA_BASE);
  pt_setlong(pid, args + 0x28, payloadout);
  pt_setint(pid, rwpipe + 0, pipe0);
  pt_setint(pid, rwpipe + 4, pipe1);
  pt_setint(pid, rwpair + 0, master_sock);
  pt_setint(pid, rwpair + 4, victim_sock);
  pt_setint(pid, payloadout, 0);

  return args;
}


/**
 * Send a file descriptor to a process that listens on a UNIX domain socket
 * with the given socket path.
 **/
static int
hbldr_sendfd(const char *sockpath, int fd) {
  struct sockaddr_un addr = {0};
  struct msghdr msg = {0};
  struct cmsghdr *cmsg;
  uint8_t buf[24];
  int sockfd;

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, sockpath);

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(struct sockaddr_un);
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);
  
  memset(buf, 0, sizeof(buf));
  cmsg = (struct cmsghdr *)buf;
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type  = SCM_RIGHTS;
  cmsg->cmsg_len   = 20;
  *((int *)&buf[16]) = fd;

  if((sockfd=socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    perror("[hbldr.elf] socket");
    return -1;
  }

  if(sendmsg(sockfd, &msg, 0) < 0) {
    perror("[hbldr.elf] sendmsg");
    close(sockfd);
    return -1;
  }

  return close(sockfd);
}


/**
 * Pipe stdout of a process with the given pid to a file descriptor, where
 * communication is done via a UNIX domain socket of the given socket path.
 **/
static int
hbldr_stdout(pid_t pid, const char *sockpath, int fd) {
  struct sockaddr_un addr = {0};
  intptr_t ptbuf;
  int sockfd;

  if((ptbuf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "[hbldr.elf] pt_mmap");
    return -1;
  }

  if((sockfd=pt_socket(pid, AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    pt_perror(pid, "[hbldr.elf] pt_socket");
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    return -1;
  }

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, sockpath);
  pt_copyin(pid, &addr, ptbuf, sizeof(addr));
  if(pt_bind(pid, sockfd, ptbuf, sizeof(addr))) {
    pt_perror(pid, "[hbldr.elf] pt_bind");
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    pt_close(pid, sockfd);
    return -1;
  }

  if(hbldr_sendfd(sockpath, fd)) {
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    pt_close(pid, sockfd);
    return -1;
  }

  intptr_t hdr = ptbuf;
  intptr_t iov = ptbuf + 0x100;
  intptr_t control = ptbuf + 0x200;

  pt_setlong(pid, hdr + __builtin_offsetof(struct msghdr, msg_name), 0);
  pt_setint(pid, hdr + __builtin_offsetof(struct msghdr, msg_namelen), 0);
  pt_setlong(pid, hdr + __builtin_offsetof(struct msghdr, msg_iov), iov);
  pt_setint(pid, hdr + __builtin_offsetof(struct msghdr, msg_iovlen), 1);
  pt_setlong(pid, hdr + __builtin_offsetof(struct msghdr, msg_control), control);
  pt_setint(pid, hdr + __builtin_offsetof(struct msghdr, msg_controllen), 24);
  if(pt_recvmsg(pid, sockfd, hdr, 0) < 0) {
    pt_perror(pid, "[hbldr.elf] pt_recvmsg");
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    pt_close(pid, sockfd);
    return -1;
  }

  if((fd=pt_getint(pid, control+16)) < 0) {
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    pt_close(pid, sockfd);
    return -1;
  }

  if(pt_munmap(pid, ptbuf, PAGE_SIZE)) {
    pt_perror(pid, "[hbldr.elf] pt_munmap");
    pt_close(pid, sockfd);
    pt_close(pid, fd);
  }

  if(pt_close(pid, sockfd)) {
    pt_perror(pid, "[hbldr.elf] pt_close");
    pt_close(pid, fd);
    return -1;
  }

  return fd;
}


int
hbldr_exec(pid_t pid, int stdout, uint8_t *elf, size_t size) {
  uint8_t caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  intptr_t entry;
  intptr_t args;
  struct reg r;

  if(kernel_set_ucred_uid(pid, 0)) {
    puts("[hbldr.elf] kernel_set_ucred_uid() failed");
    return -1;
  }

  if(kernel_set_ucred_caps(pid, caps)) {
    puts("[hbldr.elf] kernel_set_ucred_caps() failed");
    return -1;
  }

  if(pt_getregs(pid, &r)) {
    perror("[hbldr.elf] pt_getregs");
    return -1;
  }

  if(stdout > 0) {
    unlink(HBLDR_UNIX_SOCKET);
    if((stdout=hbldr_stdout(pid, HBLDR_UNIX_SOCKET, stdout)) < 0) {
      puts("[elfldr.elf] elfldr_stdout() failed");
      return -1;
    }
    unlink(HBLDR_UNIX_SOCKET);
  }

  if(!(args=hbldr_args(pid))) {
    puts("[elfldr.elf] elfldr_args() failed");
    return -1;
  }
  
  if(!(entry=hbldr_load(pid, elf, size))) {
    puts("[hbldr.elf] hbldr_load() failed");
    return -1;
  }

  r.r_rip = entry;
  r.r_rdi = args;
  if(pt_setregs(pid, &r)) {
    perror("[hbldr.elf] pt_setregs");
    return -1;
  }

  if(pt_detach(pid)) {
    perror("[hbldr.elf] pt_detach");
    return -1;
  }
  
  return 0;
}


static pid_t
hbldr_launch_bigapp(uint32_t user_id) {
  app_launch_ctx_t ctx = {.user_id = user_id};
  const char* argv[] = {0};
  struct kevent evt;
  pid_t pid = -1;
  int kq;

  if((kq=kqueue()) < 0) {
    perror("[hbldr.elf] kqueue");
    return -1;
  }

  EV_SET(&evt, getppid(), EVFILT_PROC, EV_ADD, NOTE_FORK | NOTE_TRACK, 0, NULL);
  if(kevent(kq, &evt, 1, NULL, 0, NULL) < 0) {
    perror("[hbldr.elf] kevent");
    close(kq);
    return -1;
  }

  sceSystemServiceLaunchApp("PPSA01325", argv, &ctx);

  while(1) {
    if(kevent(kq, NULL, 0, &evt, 1, NULL) < 0) {
      perror("[hbldr.elf] kevent");
      break;
    }

    if(evt.fflags & NOTE_CHILD) {
      pid = evt.ident;
      break;
    }
  }

  close(kq);

  return pid;
}


int
hbldr_launch(int stdout, uint8_t *elf, size_t size) {
  int32_t int3instr = 0xCCCCCCCCL;
  intptr_t brkpoint;
  uint32_t user_id;
  int app_id;
  pid_t pid;

  if(sceUserServiceGetForegroundUser(&user_id)) {
    perror("[hbldr.elf] sceUserServiceGetForegroundUser");
    return -1;
  }

  if((app_id=sceSystemServiceGetAppIdOfRunningBigApp()) > 0) {
    if(sceSystemServiceKillApp(app_id, -1, 0, 0)) {
      perror("sceSystemServiceKillApp");
      return -1;
    }
  }

  if((pid=hbldr_launch_bigapp(user_id)) < 0) {
    return -1;
  }

  if(pt_attach(pid) < 0) {
    return -1;
  }

  if(!(brkpoint=kernel_dynlib_entry_addr(pid, 0))) {
    pt_detach(pid);
    return -1;
  }

  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    return -1;
  }

  if(pt_continue(pid)) {
    pt_detach(pid);
    return -1;
  }

  if(waitpid(pid, 0, 0) == -1) {
    pt_detach(pid);
    return -1;
  }

  printf("entry: 0x%lx\n", brkpoint);
  if(hbldr_exec(pid, stdout, elf, size)) {
    pt_detach(pid);
    return -1;
  }
  
  return 0;
}

