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
#include <signal.h>


static void
klog(const char *fmt, ...) {
  char buf[0xff];
  va_list args;

  memset(buf, 0, sizeof(buf));
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  syscall(0x259, 7, "<118>[homebrew] ", 0);
  syscall(0x259, 7, buf, 0);
  syscall(0x259, 7, "\n", 0);
}


int
main() {
  klog("Hello, world!");
  kill(getpid(), SIGKILL);
  return 0;
}

