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

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <machine/param.h>
#include <sys/mman.h>
#include <sys/event.h>


typedef struct vout_buf {
  void *data;
  uint64_t junk0[3];
} vout_buf_t;


typedef struct vout_stat {
  uint32_t res;
  uint32_t junk0;
  uint64_t junk1[5];
} vout_stat_t;


typedef struct vout_attr {
  uint8_t junk0[80];
} vout_attr_t;


typedef struct pixel {
  uint8_t r;
  uint8_t g;
  uint8_t b;
  uint8_t a;
} pixel_t;


int sceKernelAllocateMainDirectMemory(size_t, size_t, int, intptr_t*);
int sceKernelMapDirectMemory(void**, size_t, int, int, intptr_t, size_t);
int sceKernelReleaseDirectMemory(intptr_t, size_t);

int sceKernelCreateEqueue(struct kevent **, const char *);
int sceKernelWaitEqueue(struct kevent*, struct kevent*, int, int*, uint*);

int sceVideoOutOpen(int, int, int, const void*);
int sceVideoOutGetOutputStatus(int, vout_stat_t*);
int sceVideoOutAddFlipEvent(struct kevent*, int, void*);
int sceVideoOutSetFlipRate(int, int);
int sceVideoOutSubmitFlip(int, int, uint, int64_t);
void sceVideoOutSetBufferAttribute2(vout_attr_t*, uint64_t, uint32_t, uint32_t,
				    uint32_t, uint64_t, uint32_t, uint64_t);
int sceVideoOutRegisterBuffers2(int, int, int, vout_buf_t*, int, vout_attr_t*,
				int, void*);

int sceSystemServiceHideSplashScreen(void);


static void
klog(const char *fmt, ...) {
  char buf[0x100];
  char s[0x100];
  va_list list;

  va_start(list, fmt);
  vsnprintf(s, sizeof(s), fmt, list);
  va_end(list);

  snprintf(buf, sizeof(buf), "<118>[homebrew] %s\n", s);
  syscall(0x259, 7, buf, 0);
}


static void
kerror(const char *s) {
  klog("%s: %s", s, strerror(errno));
}


static void
rainbow_draw_frame(uint32_t frame_id, pixel_t *frame, size_t size) {
  float progress = fmodf((float)frame_id / 60.0f, 1.0f);
  pixel_t px = {0, 0, 0, 255};

  if(progress < 0.2f) {
    px.r = 255;
    px.g = (uint8_t)(255 * progress * 5.0f);
  } else if (progress < 0.4f) {
    px.r = (uint8_t)(255 * (0.4f - progress) * 5.0f);
    px.g = 255;
  } else if (progress < 0.6f) {
    px.g = 255;
    px.b = (uint8_t)(255 * (progress - 0.4f) * 5.0f);
  } else if (progress < 0.8f) {
    px.g = (uint8_t)(255 * (0.8f - progress) * 5.0f);
    px.b = 255;
  } else {
    px.r = (uint8_t)(255 * (progress - 0.8f) * 5.0f);
    px.b = 255;
  }

  for(int i=0; i<size; i++) {
    frame[i] = px;
  }
}


static int
rainbow_render(void) {
  vout_buf_t vbuf[2];
  vout_attr_t vattr;
  vout_stat_t vstat;
  int vout;

  int memsize = 0x20000000;
  int memalign = 0x20000;
  intptr_t paddr;
  void* vaddr;

  struct kevent *evt_queue;
  struct kevent evt;

  uint32_t frame_id = 0;
  int height = 1080;
  int width = 1920;

  memset(vbuf, 0, sizeof(vbuf));
  memset(&vattr, 0, sizeof(vattr));
  memset(&vstat, 0, sizeof(vstat));

  if(sceKernelAllocateMainDirectMemory(memsize, memalign, 3, &paddr)) {
    kerror("sceKernelAllocateMainDirectMemory");
    return -1;
  }

  if(sceKernelMapDirectMemory(&vaddr, memsize, 0x33, 0, paddr, memalign)) {
    kerror("sceKernelMapDirectMemory");
    return -1;
  }

  if((vout=sceVideoOutOpen(0xff, 0, 0, NULL)) < 0) {
    kerror("sceVideoOutOpen");
    return -1;
  }

  if(sceVideoOutGetOutputStatus(vout, &vstat)) {
    kerror("sceVideoOutGetOutputStatus");
    return -1;
  }

  if(sceKernelCreateEqueue(&evt_queue, "flip queue")) {
    kerror("sceKernelCreateEqueue");
    return -1;
  }

  if(sceVideoOutAddFlipEvent(evt_queue, vout, NULL)) {
    kerror("sceVideoOutAddFlipEvent");
    return -1;
  }

  if(sceVideoOutSetFlipRate(vout, 0)) {
    kerror("sceVideoOutSetFlipRate");
    return -1;
  }

  if(vstat.res == 2) {
    width *= 2;
    height *= 2;
  }
  sceVideoOutSetBufferAttribute2(&vattr, 0x8000000022000000UL, 0,
				 width, height, 0, 0, 0);

  vbuf[0].data = vaddr;
  vbuf[1].data = vaddr + (memsize / 2);
  if(sceVideoOutRegisterBuffers2(vout, 0, 0, vbuf, 2, &vattr, 0, NULL)) {
    kerror("sceVideoOutRegisterBuffers2");
    return -1;
  }

  width = (width + 0x3f) & ~0x3f;
  height = (height + 0x3f) & ~0x3f;
  klog("frame size: %dx%d", width, height);

  while(1) {
    uint8_t idx = frame_id % 2;
    rainbow_draw_frame(frame_id, (pixel_t*)vbuf[idx].data, width * height);

    if(sceVideoOutSubmitFlip(vout, idx, 1, frame_id)) {
      kerror("sceVideoOutSubmitFlip");
      return -1;
    }
    int junk;
    if(sceKernelWaitEqueue(evt_queue, &evt, 1, &junk, 0)) {
      kerror("sceKernelWaitEqueue");
      return -1;
    }
    frame_id++;
  }

  if(sceKernelReleaseDirectMemory(paddr, memsize)) {
    kerror("sceKernelReleaseDirectMemory");
      return -1;
  }

  return 0;
}


int
main() {
  sceSystemServiceHideSplashScreen();
  rainbow_render();
}
