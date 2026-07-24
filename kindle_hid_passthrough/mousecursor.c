/*
 * kindle_cursor - paint a mouse pointer on the eink screen.
 *
 * The mtk X driver has no cursor plane, so X moves an invisible pointer around.
 * We poll its real position (XQueryPointer), draw a glyph into /dev/fb0 and let
 * fbink refresh the touched rectangle.
 *
 * Build it with
 * [toolchain_path]/arm-kindlehf-linux-gnueabihf-gcc kindle_cursor.c -o kindle_cursor -lX11 -O2
 */

#include <X11/Xlib.h>
#include <linux/fb.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FB_DEV    "/dev/fb0"
#define FBINK     "/var/local/kmc/armhf/bin/fbink"
#define WAVEFORM  "A2"
#define POLL_US   15000
#define SCALE_NORMAL   3
#define SCALE_LOW_RES  2
#define LOW_RES_WIDTH  1000

static int swap_xy = 0, invert_x = 0, invert_y = 0;

/* '#' is fill; the white border is derived from the empty cells next to it.
 * hot_col/hot_row is the cell that sits under the pointer. */
static const char *shape[] = {
	" ###",
	"#####",
	"######",
	"#######",
	"########",
	"#########",
	"##########",
	"###########",
	"############",
	"#############",
	"##############",
	"###############",
	"###############",
	"###############",
	"##############",
	"#############",
	"########",
	"#######",
	" #####",
	"  ###",
};
#define ROWS ((int)(sizeof shape / sizeof *shape))
#define HOT_COL 2
#define HOT_ROW 0

static uint8_t *fb;
static int fb_w, fb_h, ncols;
static long stride, base[2];
static int nbuf;
static int box_w, box_h;
static int scale;

static uint8_t *under;
static int u_x, u_y, u_w, u_h, u_valid;

typedef struct { int x, y, w, h; } rect;

static int fill(int r, int c)
{
	return r >= 0 && r < ROWS && c >= 0 && c < (int)strlen(shape[r])
	    && shape[r][c] == '#';
}

/* 0x00 = fill, 0xFF = outline, -1 = transparent */
static int pixel(int r, int c)
{
	if (fill(r, c))
		return 0x00;
	for (int dr = -1; dr <= 1; dr++)
		for (int dc = -1; dc <= 1; dc++)
			if ((dr || dc) && fill(r + dr, c + dc))
				return 0xFF;
	return -1;
}

static int fb_init(void)
{
	int fd = open(FB_DEV, O_RDWR);
	if (fd < 0) { perror("open fb"); return -1; }

	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	if (ioctl(fd, FBIOGET_VSCREENINFO, &var) ||
	    ioctl(fd, FBIOGET_FSCREENINFO, &fix)) {
		perror("fb ioctl");
		return -1;
	}

	fb_w = var.xres;
	fb_h = var.yres;
	stride = fix.line_length ? fix.line_length : var.xres_virtual;
	base[0] = 0;
	nbuf = 1;
	if (var.yres_virtual >= 2u * var.yres) {   /* double buffered */
		base[1] = var.yres;
		nbuf = 2;
	}

	fb = mmap(NULL, stride * var.yres_virtual, PROT_READ | PROT_WRITE,
	          MAP_SHARED, fd, 0);
	if (fb == MAP_FAILED) { perror("mmap"); return -1; }

	fprintf(stderr, "fb %dx%d stride=%ld buffers=%d\n", fb_w, fb_h, stride, nbuf);
	return 0;
}

static void stash(int x, int y, int w, int h)
{
	for (int r = 0; r < h; r++)
		memcpy(under + r * w, fb + (long)(y + r) * stride + x, w);
	u_x = x; u_y = y; u_w = w; u_h = h; u_valid = 1;
}

static void unstash(void)
{
	if (!u_valid)
		return;
	for (int b = 0; b < nbuf; b++)
		for (int r = 0; r < u_h; r++)
			memcpy(fb + (base[b] + u_y + r) * stride + u_x,
			       under + r * u_w, u_w);
	u_valid = 0;
}

static rect draw(int x, int y)
{
	int ox = x - (HOT_COL + 1) * scale;
	int oy = y - (HOT_ROW + 1) * scale;

	int l = ox < 0 ? 0 : ox;
	int t = oy < 0 ? 0 : oy;
	int r = ox + box_w > fb_w ? fb_w : ox + box_w;
	int d = oy + box_h > fb_h ? fb_h : oy + box_h;
	rect out = { l, t, r - l < 0 ? 0 : r - l, d - t < 0 ? 0 : d - t };

	stash(out.x, out.y, out.w, out.h);

	for (int b = 0; b < nbuf; b++)
		for (int cr = -1; cr <= ROWS; cr++)
			for (int cc = -1; cc <= ncols; cc++) {
				int v = pixel(cr, cc);
				if (v < 0)
					continue;
				for (int sy = 0; sy < scale; sy++) {
					int py = y + (cr - HOT_ROW) * scale + sy;
					if (py < 0 || py >= fb_h)
						continue;
					for (int sx = 0; sx < scale; sx++) {
						int px = x + (cc - HOT_COL) * scale + sx;
						if (px >= 0 && px < fb_w)
							fb[(base[b] + py) * stride + px] = v;
					}
				}
			}
	return out;
}

/* fbink rejects off-screen or sliver regions, so keep it sane. */
static rect fit(rect a)
{
	const int min = 8;
	if (a.x < 0) { a.w += a.x; a.x = 0; }
	if (a.y < 0) { a.h += a.y; a.y = 0; }
	if (a.x + a.w > fb_w) a.w = fb_w - a.x;
	if (a.y + a.h > fb_h) a.h = fb_h - a.y;
	if (a.w < min) {
		a.x -= (min - a.w) / 2; a.w = min;
		if (a.x < 0) a.x = 0;
		if (a.x + a.w > fb_w) a.x = fb_w - a.w;
	}
	if (a.h < min) {
		a.y -= (min - a.h) / 2; a.h = min;
		if (a.y < 0) a.y = 0;
		if (a.y + a.h > fb_h) a.y = fb_h - a.h;
	}
	return a;
}

static void refresh(rect a)
{
	a = fit(a);
	if (a.w <= 0 || a.h <= 0)
		return;

	char reg[128];
	snprintf(reg, sizeof reg, "top=%d,left=%d,width=%d,height=%d",
	         a.y, a.x, a.w, a.h);

	pid_t pid = fork();
	if (pid == 0) {
		execl(FBINK, FBINK, "-q", "-s", reg, "-W", WAVEFORM, (char *)0);
		_exit(127);
	}
	if (pid > 0)
		waitpid(pid, NULL, 0);
}

static rect merge(rect a, rect b)
{
	int l = a.x < b.x ? a.x : b.x;
	int t = a.y < b.y ? a.y : b.y;
	int r = a.x + a.w > b.x + b.w ? a.x + a.w : b.x + b.w;
	int d = a.y + a.h > b.y + b.h ? a.y + a.h : b.y + b.h;
	rect u = { l, t, r - l, d - t };
	return u;
}

int main(void)
{
	if (fb_init())
		return 1;

	scale = fb_w < LOW_RES_WIDTH ? SCALE_LOW_RES : SCALE_NORMAL;

	ncols = 0;
	for (int r = 0; r < ROWS; r++) {
		int l = strlen(shape[r]);
		if (l > ncols)
			ncols = l;
	}
	box_w = (ncols + 2) * scale;
	box_h = (ROWS + 2) * scale;
	under = malloc((size_t)box_w * box_h);
	if (!under) { perror("malloc"); return 1; }

	Display *dpy = XOpenDisplay(NULL);
	if (!dpy)
		dpy = XOpenDisplay(":0");
	if (!dpy) {
		fprintf(stderr, "no X display (set DISPLAY)\n");
		return 1;
	}
	Window root = DefaultRootWindow(dpy);

	Window w1, w2;
	int rx, ry, wx, wy, lx = -1, ly = -1;
	unsigned mask;
	rect old = { 0, 0, 0, 0 };
	int have = 0;

	for (;;) {
		if (XQueryPointer(dpy, root, &w1, &w2, &rx, &ry, &wx, &wy, &mask)) {
			int x = rx, y = ry;
			if (swap_xy) { int t = x; x = y; y = t; }
			if (invert_x) x = fb_w - 1 - x;
			if (invert_y) y = fb_h - 1 - y;

			if (x != lx || y != ly) {
				if (have)
					unstash();
				rect now = draw(x, y);
				refresh(have ? merge(old, now) : now);
				old = now;
				have = 1;
				lx = x;
				ly = y;
			}
		}
		usleep(POLL_US);
	}
}
