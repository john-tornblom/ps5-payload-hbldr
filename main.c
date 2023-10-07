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

#include <stdio.h>
#include <stdlib.h>

#include "hbldr.h"
#include "test_elf.c"


int sceUserServiceInitialize(void*);
int sceUserServiceTerminate(void);


__attribute__((constructor)) static void
constructor(void) {
  if(sceUserServiceInitialize(0)) {
    perror("[hbldr.elf] sceUserServiceInitialize");
  }
}


__attribute__((destructor)) static void
destructor(void) {
  sceUserServiceTerminate();
}


int
main() {
  return hbldr_launch(-1, test_elf, test_elf_len);
}
