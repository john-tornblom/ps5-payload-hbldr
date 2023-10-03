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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <ps5/kernel.h>

#include "pt.h"


static int
sys_ptrace(int request, pid_t pid, caddr_t addr, int data) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  pid_t mypid = getpid();
  uint8_t caps[16];
  uint64_t authid;
  int ret;

  if(!(authid=kernel_get_ucred_authid(mypid))) {
    return -1;
  }
  if(kernel_get_ucred_caps(mypid, caps)) {
    return -1;
  }

  if(kernel_set_ucred_authid(mypid, 0x4800000000010003l)) {
    return -1;
  }
  if(kernel_set_ucred_caps(mypid, privcaps)) {
    return -1;
  }

  ret = (int)syscall(SYS_ptrace, request, pid, addr, data);

  if(kernel_set_ucred_authid(mypid, authid)) {
    return -1;
  }
  if(kernel_set_ucred_caps(mypid, caps)) {
    return -1;
  }

  return ret;
}


int
pt_attach(pid_t pid) {
  if(sys_ptrace(PT_ATTACH, pid, NULL, 0) == -1) {
    perror("[hbldr.elf] PT_ATTACH");
    return -1;
  }

  if(waitpid(pid, NULL, 0) == -1) {
    perror("[hbldr.elf] waitpid");
    return -1;
  }

  return 0;
}


int
pt_detach(pid_t pid) {
  if(sys_ptrace(PT_DETACH, pid, NULL, 0) == -1) {
    perror("[hbldr.elf] PT_DETACH");
    return -1;
  }

  return 0;
}


int
pt_continue(pid_t pid) {
  if(sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, SIGCONT) == -1) {
    perror("[hbldr.elf] PT_CONTINUE");
    return -1;
  }

  return 0;
}


int
pt_follow_fork(pid_t pid) {
  if(sys_ptrace(PT_FOLLOW_FORK, pid, NULL, 1) == -1) {
    perror("[hbldr.elf] PT_FOLLOW_FORK");
    return -1;
  }

  if(sys_ptrace(PT_LWP_EVENTS, pid, NULL, 1) == -1) {
    perror("[hbldr.elf] PT_LWP_EVENTS");
    return -1;
  }

  return 0;
}


int
pt_follow_exec(pid_t pid) {
  if(sys_ptrace(PT_LWP_EVENTS, pid, NULL, 1) == -1) {
    perror("[hbldr.elf] PT_LWP_EVENTS");
    return -1;
  }

  return 0;
}


pid_t
pt_await_child(pid_t pid) {
  struct ptrace_lwpinfo lwpinfo;

  memset(&lwpinfo, 0, sizeof(lwpinfo));
  while(!(lwpinfo.pl_flags & PL_FLAG_FORKED)) {
    if(waitpid(pid, NULL, 0) == -1) {
      perror("[hbldr.elf] waitid");
      return -1;
    }

    if(sys_ptrace(PT_LWPINFO, pid, (caddr_t)&lwpinfo, sizeof(lwpinfo)) == -1) {
      perror("[hbldr.elf] PT_LWPINFO");
      return -1;
    }
  }

  if(waitpid(lwpinfo.pl_child_pid, NULL, 0) == -1) {
    perror("[hbldr.elf] waitpid");
    return -1;
  }

  return lwpinfo.pl_child_pid;
}


int
pt_await_exec(pid_t pid) {
  struct ptrace_lwpinfo lwpinfo;

  memset(&lwpinfo, 0, sizeof(lwpinfo));
  while(!(lwpinfo.pl_flags & PL_FLAG_EXEC)) {
    if(waitpid(pid, NULL, 0) == -1) {
      perror("[hbldr.elf] waitid");
      return -1;
    }

    if(sys_ptrace(PT_LWPINFO, pid, (caddr_t)&lwpinfo, sizeof(lwpinfo)) == -1) {
      perror("[hbldr.elf] PT_LWPINFO");
      return -1;
    }
  }

  return 0;
}


int
pt_getregs(pid_t pid, struct reg *r) {
  return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}


int
pt_setregs(pid_t pid, const struct reg *r) {
  return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}


int
pt_getfsbase(pid_t pid, intptr_t *addr) {
  return sys_ptrace(PT_GETFSBASE, pid, (caddr_t)addr, 0);
}


int
pt_getint(pid_t pid, intptr_t addr) {
  return sys_ptrace(PT_READ_D, pid, (caddr_t)addr, 0);
}


int
pt_setint(pid_t pid, intptr_t addr, int val) {
  return sys_ptrace(PT_WRITE_D, pid, (caddr_t)addr, val);
}


int
pt_copyin(pid_t pid, void* buf, intptr_t addr, size_t len) {
  struct ptrace_io_desc iod = {
    .piod_op = PIOD_WRITE_D,
    .piod_offs = (void*)addr,
    .piod_addr = buf,
    .piod_len = len};
  return sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0);  
}


int
pt_setchar(pid_t pid, intptr_t addr, char val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}


int
pt_setlong(pid_t pid, intptr_t addr, long val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}


int
pt_step(int pid) {
  if(sys_ptrace(PT_STEP, pid, (caddr_t)1, 0)) {
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    return -1;
  }

  return 0;
}


static uint64_t
pt_call(pid_t pid, intptr_t addr,
	uint64_t arg1, uint64_t arg2, uint64_t arg3,
	uint64_t arg4, uint64_t arg5, uint64_t arg6) {
  struct reg jmp_reg;
  struct reg bak_reg;

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;
  jmp_reg.r_rdi = arg1;
  jmp_reg.r_rsi = arg2;
  jmp_reg.r_rdx = arg3;
  jmp_reg.r_rcx = arg4;
  jmp_reg.r_r8  = arg5;
  jmp_reg.r_r9  = arg5;

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}


static uint64_t
pt_syscall(pid_t pid, int sysno,
	   uint64_t arg1, uint64_t arg2, uint64_t arg3,
	   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
  intptr_t addr = kernel_dynlib_resolve(pid, 0x2001, "HoLVWNanBBc");
  struct reg jmp_reg;
  struct reg bak_reg;

  if(!addr) {
    return -1;
  } else {
    addr += 0xa;
  }
  
  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;
  jmp_reg.r_rax = sysno;
  jmp_reg.r_rdi = arg1;
  jmp_reg.r_rsi = arg2;
  jmp_reg.r_rdx = arg3;
  jmp_reg.r_r10 = arg4;
  jmp_reg.r_r8  = arg5;
  jmp_reg.r_r9  = arg6;

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}

int
pt_jitshm_create(pid_t pid, intptr_t name, size_t size, int flags) {
  return (int)pt_syscall(pid, 0x215, name, size, flags, 0, 0, 0);
}


int
pt_jitshm_alias(pid_t pid, int fd, int flags) {
  return (int)pt_syscall(pid, 0x216, fd, flags, 0, 0, 0, 0);
}


intptr_t
pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags,
	int fd, off_t off) {
  return pt_syscall(pid, SYS_mmap, addr, len, prot, flags, fd, off);
}


int
pt_munmap(pid_t pid, intptr_t addr, size_t len) {
  return pt_syscall(pid, SYS_munmap, addr, len, 0, 0, 0, 0);
}


int
pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot) {
  return pt_syscall(pid, SYS_mprotect, addr, len, prot, 0, 0, 0);
}


int
pt_close(pid_t pid, int fd) {
  return (int)pt_syscall(pid, SYS_close, fd, 0, 0, 0, 0, 0);
}


int
pt_socket(pid_t pid, int domain, int type, int protocol) {
  return (int)pt_syscall(pid, SYS_socket, domain, type, protocol, 0, 0, 0);
}


int
pt_setsockopt(pid_t pid, int fd, int level, int optname, intptr_t optval,
	      socklen_t optlen) {
  return (int)pt_syscall(pid, SYS_setsockopt, fd, level, optname, optval,
			 optlen, 0);
}


int
pt_bind(pid_t pid, int sockfd, intptr_t addr, socklen_t addrlen) {
  return (int)pt_syscall(pid, SYS_bind, sockfd, addr, addrlen, 0, 0, 0);
}


ssize_t
pt_recvmsg(pid_t pid, int fd, intptr_t msg, int flags) {
  return (int)pt_syscall(pid, SYS_recvmsg, fd, msg, flags, 0, 0, 0);
}


int
pt_dup2(pid_t pid, int oldfd, int newfd) {
  return (int)pt_syscall(pid, SYS_dup2, oldfd, newfd, 0, 0, 0, 0);
}


int
pt_pipe(pid_t pid, intptr_t pipefd) {
  intptr_t faddr = kernel_dynlib_resolve(pid, 0x2001, "-Jp7F+pXxNg");
  return (int)pt_call(pid, faddr, pipefd, 0, 0, 0, 0, 0);
}


void
pt_perror(pid_t pid, const char *s) {
  intptr_t faddr = kernel_dynlib_resolve(pid, 0x2001, "9BcDykPmo1I"); //__error
  intptr_t addr = pt_call(pid, faddr, 0, 0, 0, 0, 0, 0);
  int err = pt_getint(pid, addr);
  char buf[255];

  strcpy(buf, s);
  strcat(buf, ": ");
  strcat(buf, strerror(err));
  puts(buf);
}
