// SPDX-License-Identifier: GPL-2.0
/*
 * hidhide_kpm.c - KernelPatch Module (KPM) version of HIDHide.
 *
 * Hook input_register_device() and rewrite the identity of external HID
 * input devices. The current matcher targets USB multi-touch devices and
 * presents them as builtin I2C input devices.
 * As a KPM, symbols are resolved at load time via kallsyms: one binary,
 * no vermagic binding.
 *
 * v1.2: match by device capabilities, not by hard-coded VID/PID.
 *   auto mode (vid=0, default): any input_dev that is BUS_USB and has
 *     BTN_TOUCH + ABS_MT_SLOT is rewritten, regardless of its original
 *     USB identity.
 *   explicit mode (vid=0xXXXX pid=0xYYYY): only that device is touched.
 *
 * Hardened build:
 *   - signature strings (hook target, log formats) are XOR-obfuscated so
 *     `strings` / casual static analysis reveals nothing
 *   - module description is deliberately innocuous
 *   - build with: strip --strip-unneeded (drops local symbol names while
 *     keeping relocations resolvable)
 *
 * Load:   ksud kpm load hidhide.kpm "vid=0 pid=0 name=goodix_ts phys=i2c/1-005d"
 * Reconf: ksud kpm control hidhide "vid=... name=..."
 * Unload: ksud kpm unload hidhide
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <hook.h>

KPM_NAME("hidhide");
KPM_VERSION("1.3.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("HIDHide contributors");
KPM_DESCRIPTION("input device compatibility layer");

/* ------------------------------------------------------------------ *
 * struct input_dev layout (arm64; the head of the struct, up to and
 * including absbit, has been stable for many kernel generations):
 *   +0    const char *name
 *   +8    const char *phys
 *   +16   const char *uniq
 *   +24   struct input_id id { u16 bustype; u16 vendor; u16 product; u16 version; }
 *   +32   unsigned long propbits[1]   (INPUT_PROP_CNT = 0x20)
 *   +40   unsigned long evbit[1]      (EV_CNT = 0x20)
 *   +48   unsigned long keybit[12]    (KEY_CNT = 0x300, 96 bytes)
 *   +144  unsigned long relbit[1]
 *   +152  unsigned long absbit[1]     (ABS_CNT = 0x40)
 * ------------------------------------------------------------------ */
#define OFF_NAME        0
#define OFF_PHYS        8
#define OFF_UNIQ        16
#define OFF_ID_BUSTYPE  24
#define OFF_ID_VENDOR   26
#define OFF_ID_PRODUCT  28
#define OFF_ID_VERSION  30
#define OFF_KEYBIT_W5   (48 + 5 * 8)    /* keybit word holding bit 330 */
#define OFF_ABSBIT      152

#define BTN_TOUCH_BIT   0x14a           /* 330: word 5, bit 10 */
#define BTN_TOUCH_MASK  (1ULL << (BTN_TOUCH_BIT % 64))
#define ABS_MT_SLOT_BIT 0x2f            /* 47 */
#define ABS_MT_SLOT_MASK (1ULL << ABS_MT_SLOT_BIT)

#define BUS_USB_VAL     0x03
#define BUS_I2C_VAL     0x18

/* ---- runtime config (set via load args / ctl0) ---- */
static uint16_t target_vid = 0;         /* 0 = auto: use the built-in HID capability matcher */
static uint16_t target_pid = 0;
static char fake_name[64];              /* defaults XOR-filled at init */
static char fake_phys[64];
static char *(*kernel_kstrdup)(const char *src, unsigned int flags);

/* ---- XOR-obfuscated signature strings (key 0x5A) ---- */
#define XK 0x5A
static const unsigned char enc_sym[] = { 0x33, 0x34, 0x2a, 0x2f, 0x2e, 0x05, 0x28, 0x3f, 0x3d, 0x33, 0x29, 0x2e, 0x3f, 0x28, 0x05, 0x3e, 0x3f, 0x2c, 0x33, 0x39, 0x3f };
static const unsigned char enc_hit[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x2a, 0x3b, 0x2e, 0x39, 0x32, 0x3f, 0x3e, 0x7a, 0x7f, 0x6a, 0x6e, 0x22, 0x60, 0x7f, 0x6a, 0x6e, 0x22, 0x7a, 0x77, 0x64, 0x7a, 0x7f, 0x29, 0x50 };
static const unsigned char enc_init[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x35, 0x34, 0x7a, 0x7f, 0x29, 0x7a, 0x2c, 0x33, 0x3e, 0x67, 0x7f, 0x6a, 0x6e, 0x22, 0x7a, 0x2a, 0x33, 0x3e, 0x67, 0x7f, 0x6a, 0x6e, 0x22, 0x7a, 0x34, 0x3b, 0x37, 0x3f, 0x67, 0x7f, 0x29, 0x7a, 0x2a, 0x32, 0x23, 0x29, 0x67, 0x7f, 0x29, 0x50 };
static const unsigned char enc_ctl[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x39, 0x3c, 0x3d, 0x7a, 0x2c, 0x33, 0x3e, 0x67, 0x7f, 0x6a, 0x6e, 0x22, 0x7a, 0x2a, 0x33, 0x3e, 0x67, 0x7f, 0x6a, 0x6e, 0x22, 0x7a, 0x34, 0x3b, 0x37, 0x3f, 0x67, 0x7f, 0x29, 0x7a, 0x2a, 0x32, 0x23, 0x29, 0x67, 0x7f, 0x29, 0x50 };
static const unsigned char enc_nosym[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x29, 0x23, 0x37, 0x7a, 0x34, 0x35, 0x2e, 0x7a, 0x3c, 0x35, 0x2f, 0x34, 0x3e, 0x50 };
static const unsigned char enc_herr[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x32, 0x35, 0x35, 0x31, 0x7a, 0x3f, 0x28, 0x28, 0x7a, 0x7f, 0x3e, 0x50 };
static const unsigned char enc_exit[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x35, 0x3c, 0x3c, 0x50 };
static const unsigned char enc_fname[] = { 0x3d, 0x35, 0x35, 0x3e, 0x33, 0x22, 0x05, 0x2e, 0x29 };
static const unsigned char enc_fphys[] = { 0x33, 0x68, 0x39, 0x75, 0x6b, 0x77, 0x6a, 0x6a, 0x6f, 0x3e };
static const unsigned char enc_dup[] = { 0x31, 0x29, 0x2e, 0x28, 0x3e, 0x2f, 0x2a };

static void xdec(char *dst, const unsigned char *src, int len)
{
	int i;
	for (i = 0; i < len; i++)
		dst[i] = src[i] ^ XK;
	dst[i] = 0;
}

static unsigned long parse_num(const char *s)
{
	unsigned long v = 0;
	int base = 10;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		base = 16;
		s += 2;
	}
	while (*s) {
		char c = *s;
		int d;
		if (c >= '0' && c <= '9') d = c - '0';
		else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
		else break;
		if (d >= base) break;
		v = v * base + d;
		s++;
	}
	return v;
}

static void copy_val(char *dst, int dstlen, const char *s)
{
	int i = 0;
	while (*s && *s != ' ' && *s != '\n' && i < dstlen - 1)
		dst[i++] = *s++;
	dst[i] = 0;
}

/*
 * input_dev keeps these pointers after registration. KPM executable/data
 * memory is released when the module is unloaded, so pointing at the module's
 * static buffers would leave dangling pointers. Allocate immutable copies
 * outside KPM module storage instead. They deliberately live until reboot;
 * registrations are rare and each pair is at most 128 bytes.
 */
static char *persistent_copy(const char *src)
{
	if (!kernel_kstrdup)
		return 0;
	/* flags=0 requests a non-reclaiming allocation suitable for this hook. */
	return kernel_kstrdup(src, 0);
}

/* args format: "vid=0 pid=0 name=goodix_ts phys=i2c/1-005d" (vid=0 => auto) */
static void parse_args(const char *args)
{
	const char *p = args;
	if (!p) return;
	while (*p) {
		while (*p == ' ') p++;
		if (!*p) break;
		if (!strncmp(p, "vid=", 4))       target_vid = (uint16_t)parse_num(p + 4);
		else if (!strncmp(p, "pid=", 4))  target_pid = (uint16_t)parse_num(p + 4);
		else if (!strncmp(p, "name=", 5)) copy_val(fake_name, sizeof(fake_name), p + 5);
		else if (!strncmp(p, "phys=", 5)) copy_val(fake_phys, sizeof(fake_phys), p + 5);
		while (*p && *p != ' ') p++;
	}
}

/* capability test: is this dev a multi-touch digitizer? */
static int is_mt_touch(uintptr_t dev)
{
	if (is_bad_address((void *)dev) ||
	    is_bad_address((void *)(dev + OFF_ABSBIT)))
		return 0;
	uint64_t keyw5 = *(volatile uint64_t *)(dev + OFF_KEYBIT_W5);
	uint64_t absb  = *(volatile uint64_t *)(dev + OFF_ABSBIT);
	return (keyw5 & BTN_TOUCH_MASK) && (absb & ABS_MT_SLOT_MASK);
}

/* before-callback of hook_wrap1 on input_register_device(dev) */
static void before_input_register(hook_fargs1_t *fargs, void *udata)
{
	uintptr_t dev = (uintptr_t)fargs->args[0];
	uint16_t bustype, vendor, product;
	char fbuf[64];
	char *name_copy, *phys_copy;

	(void)udata;
	if (!dev || (dev & 7) || is_bad_address((void *)dev) ||
	    is_bad_address((void *)(dev + OFF_ABSBIT)))
		return;

	vendor  = *(volatile uint16_t *)(dev + OFF_ID_VENDOR);
	product = *(volatile uint16_t *)(dev + OFF_ID_PRODUCT);

	/* explicit mode: only the configured device */
	if (target_vid && (vendor != target_vid || product != target_pid))
		return;

	/* auto mode (and explicit sanity): must be a multi-touch digitizer */
	if (!target_vid && !is_mt_touch(dev))
		return;

	name_copy = persistent_copy(fake_name);
	if (!name_copy)
		return;
	phys_copy = persistent_copy(fake_phys);
	if (!phys_copy)
		return;

	*(uint16_t *)(dev + OFF_ID_BUSTYPE) = BUS_I2C_VAL;
	*(uint16_t *)(dev + OFF_ID_VENDOR)  = 0;
	*(uint16_t *)(dev + OFF_ID_PRODUCT) = 0;
	*(uint16_t *)(dev + OFF_ID_VERSION) = 0;  /* USB bcdDevice leaks origin; I2C panels are 0 */

	/* name/phys/uniq are pointers: re-point, never write into them */
	*(const char **)(dev + OFF_NAME) = name_copy;
	*(const char **)(dev + OFF_PHYS) = phys_copy;
	*(const char **)(dev + OFF_UNIQ) = 0;

	xdec(fbuf, enc_hit, sizeof(enc_hit));
	printk(fbuf, vendor, product, fake_name);
}

static void *input_register_device_addr = 0;

static long hidhide_init(const char *args, const char *event, void *__user reserved)
{
	hook_err_t err;
	char sym[24];
	char dup_sym[8];
	char fbuf[64];

	(void)reserved;
	/* fill obfuscated defaults before args may override them */
	if (!fake_name[0])
		xdec(fake_name, enc_fname, sizeof(enc_fname));
	if (!fake_phys[0])
		xdec(fake_phys, enc_fphys, sizeof(enc_fphys));

	parse_args(args);
	xdec(dup_sym, enc_dup, sizeof(enc_dup));
	kernel_kstrdup = (void *)kallsyms_lookup_name(dup_sym);
	if (!kernel_kstrdup) {
		xdec(fbuf, enc_nosym, sizeof(enc_nosym));
		printk(fbuf);
		return -1;
	}

	xdec(sym, enc_sym, sizeof(enc_sym));
	input_register_device_addr = (void *)kallsyms_lookup_name(sym);
	if (!input_register_device_addr) {
		xdec(fbuf, enc_nosym, sizeof(enc_nosym));
		printk(fbuf);
		return -1;
	}

	err = hook_wrap1(input_register_device_addr, before_input_register, 0, 0);
	if (err != HOOK_NO_ERR) {
		xdec(fbuf, enc_herr, sizeof(enc_herr));
		printk(fbuf, err);
		return err;
	}

	xdec(fbuf, enc_init, sizeof(enc_init));
	printk(fbuf, event, target_vid, target_pid, fake_name, fake_phys);
	return 0;
}

/* runtime reconfigure: ksud kpm control hidhide "vid=... pid=... name=... phys=..." */
static long hidhide_ctl0(const char *args, char *__user out_msg, int outlen)
{
	char fbuf[64];

	parse_args(args);
	xdec(fbuf, enc_ctl, sizeof(enc_ctl));
	printk(fbuf, target_vid, target_pid, fake_name, fake_phys);
	if (out_msg && outlen >= 3)
		compat_copy_to_user(out_msg, "ok\n", 3);
	return 0;
}

static long hidhide_exit(void *__user reserved)
{
	char fbuf[16];

	(void)reserved;
	if (input_register_device_addr)
		hook_unwrap(input_register_device_addr, before_input_register, 0);
	xdec(fbuf, enc_exit, sizeof(enc_exit));
	printk(fbuf);
	return 0;
}

KPM_INIT(hidhide_init);
KPM_CTL0(hidhide_ctl0);
KPM_EXIT(hidhide_exit);
