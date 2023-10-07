#   Copyright (C) 2023 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

ifndef PS5_PAYLOAD_SDK
    $(error PS5_PAYLOAD_SDK is undefined)
endif

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ELF := hbldr.elf

CC  := $(PS5_PAYLOAD_SDK)/host/x86_64-ps5-payload-cc
LD  := $(PS5_PAYLOAD_SDK)/host/x86_64-ps5-payload-ld
XXD := xxd

CFLAGS := -O0 -Wall
LDADD  := -lkernel -lSceLibcInternal -lSceSystemService -lSceUserService

all: $(ELF)

main.o: test_elf.c

test_elf.c: test.elf
	$(XXD) -i $^ > $@

test.elf: test.o
	$(LD) -o $@ $^ -lkernel -lSceLibcInternal -lSceVideoOut -lSceSystemService

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

$(ELF): pt.o hbldr.o mdbg.o main.o
	$(LD) -o $@ $^ $(LDADD)

clean:
	rm -f *.o *.elf test_elf.c

test: $(ELF)
	nc -q0 $(PS5_HOST) $(PS5_PORT) < $^
