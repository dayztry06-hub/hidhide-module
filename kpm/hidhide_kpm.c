// SPDX-License-Identifier: GPL-2.0
/*
 * hidhide_kpm.c - KernelPatch Module (KPM) version of HIDHide.
 *
 * Intended loader: KPM-Manager (Yervant7/KPM-Manager).
 * KPM-Manager loads with empty args; configure via ctl0 (settings dialog).
 *
 * ctl0 commands:
 *   status                       show targets, drop_mode, hit counters
 *   clear                        remove targets, reset counters
 *   vid=<v> pid=<p> | vid=... [drop_mode=skip|mute|spoof]
 *                                full config, replaces previous
 *
 * Compile-time default (so empty-args load auto-applies your rig):
 *   make ... HIDHIDE_DEFAULT_TARGETS='vid=0x1038 pid=0x1892 | vid=0x28e9 pid=0x31ea'
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <hook.h>

/*
 * Deliberately skipping <linux/string.h>: it provides a static inline
 * memset that would collide with the local override below. We declare
 * only strncmp (the sole string op we actually call); gcc inlines
 * constant-length strncmp calls, so no external symbol reference is emitted.
 */
__attribute__((used))
int strncmp(const char *s1, const char *s2, unsigned long n)
{
	const volatile unsigned char *a = (const volatile unsigned char *)s1;
	const volatile unsigned char *b = (const volatile unsigned char *)s2;
	unsigned long i;
	for (i = 0; i < n; i++) {
		unsigned char ca = a[i], cb = b[i];
		if (ca != cb) return (int)ca - (int)cb;
		if (!ca) return 0;
	}
	return 0;
}

/*
 * KernelPatch's module loader resolves undefined symbols only against its
 * own export table (symbol_lookup_name), not against kernel kallsyms.
 * Kernel libc is exported as kfuncmemset / kfuncmemcpy, NOT bare "memset".
 * When gcc emits an implicit mem* call (char x[64] = {0}; loop-idiom
 * recognition; small struct copies) the loader rejects with
 *   "unknown symbol: memset"
 *
 * Fix: provide local implementations. All implicit emissions bind here at
 * link time, no external lookup needed.
 *
 * __attribute__((used)) prevents DCE if gcc sees no explicit callers.
 * volatile accesses suppress loop-idiom recognition from turning the body
 * into a recursive memset/memcpy call.
 */
__attribute__((used))
void *memset(void *dst, int c, unsigned long n)
{
	volatile unsigned char *d = (volatile unsigned char *)dst;
	unsigned long i;
	for (i = 0; i < n; i++) d[i] = (unsigned char)c;
	return dst;
}

__attribute__((used))
void *memcpy(void *dst, const void *src, unsigned long n)
{
	volatile unsigned char *d = (volatile unsigned char *)dst;
	const volatile unsigned char *s = (const volatile unsigned char *)src;
	unsigned long i;
	for (i = 0; i < n; i++) d[i] = s[i];
	return dst;
}

__attribute__((used))
void *memmove(void *dst, const void *src, unsigned long n)
{
	volatile unsigned char *d = (volatile unsigned char *)dst;
	const volatile unsigned char *s = (const volatile unsigned char *)src;
	unsigned long i;
	if (d == s || n == 0) return dst;
	if (d < s) for (i = 0; i < n; i++) d[i] = s[i];
	else       for (i = n; i > 0; i--) d[i - 1] = s[i - 1];
	return dst;
}

KPM_NAME("hidhide");
KPM_VERSION("1.5.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("HIDHide contributors");
KPM_DESCRIPTION("input device compatibility layer");

#ifndef HIDHIDE_DEFAULT_TARGETS
#define HIDHIDE_DEFAULT_TARGETS "vid=0x1038 pid=0x1892 | vid=0x28e9 pid=0x31ea drop_mode=skip"
#endif

/* ---- struct input_dev layout (arm64) ---- */
#define OFF_NAME        0
#define OFF_PHYS        8
#define OFF_UNIQ        16
#define OFF_ID_BUSTYPE  24
#define OFF_ID_VENDOR   26
#define OFF_ID_PRODUCT  28
#define OFF_ID_VERSION  30
#define OFF_PROPBIT     32
#define OFF_EVBIT       40
#define OFF_KEYBIT      48
#define OFF_RELBIT      144
#define OFF_ABSBIT      152

#define EV_CNT          0x20
#define KEY_CNT         0x300
#define REL_CNT         0x10
#define ABS_CNT         0x40

#define EV_KEY          0x01
#define EV_REL          0x02
#define EV_ABS          0x03

#define KEY_ESC         1
#define KEY_VOLUMEUP    115
#define BTN_LEFT        0x110
#define BTN_TOUCH       0x14a
#define ABS_MT_SLOT     0x2f

#define BUS_USB_VAL     0x03
#define BUS_I2C_VAL     0x18

#define MAX_TARGETS 8
static int      target_count = 0;
static uint16_t target_vid[MAX_TARGETS];
static uint16_t target_pid[MAX_TARGETS];
static char     fake_name[MAX_TARGETS][64];
static char     fake_phys[MAX_TARGETS][64];
static uint32_t hit_count[MAX_TARGETS];
static uint32_t drop_count;

#define DROP_SKIP   0
#define DROP_MUTE   1
#define DROP_SPOOF  2
static int drop_mode = DROP_SKIP;

static const char *drop_mode_name(int m)
{
	switch (m) {
	case DROP_SKIP:  return "skip";
	case DROP_MUTE:  return "mute";
	case DROP_SPOOF: return "spoof";
	default:         return "?";
	}
}

static char *(*kernel_kstrdup)(const char *src, unsigned int flags);

#define XK 0x5A
static const unsigned char enc_sym[] = { 0x33, 0x34, 0x2a, 0x2f, 0x2e, 0x05, 0x28, 0x3f, 0x3d, 0x33, 0x29, 0x2e, 0x3f, 0x28, 0x05, 0x3e, 0x3f, 0x2c, 0x33, 0x39, 0x3f };
static const unsigned char enc_hit[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x2a, 0x3b, 0x2e, 0x39, 0x32, 0x3f, 0x3e, 0x7a, 0x7f, 0x6a, 0x6e, 0x22, 0x60, 0x7f, 0x6a, 0x6e, 0x22, 0x7a, 0x77, 0x64, 0x7a, 0x7f, 0x29, 0x50 };
static const unsigned char enc_init[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x35, 0x34, 0x7a, 0x7f, 0x29, 0x7a, 0x2c, 0x3b, 0x2a, 0x3d, 0x3f, 0x2e, 0x29, 0x67, 0x7f, 0x3e, 0x50 };
static const unsigned char enc_nosym[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x29, 0x23, 0x37, 0x7a, 0x34, 0x35, 0x2e, 0x7a, 0x3c, 0x35, 0x2f, 0x34, 0x3e, 0x50 };
static const unsigned char enc_herr[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x32, 0x35, 0x35, 0x31, 0x7a, 0x3f, 0x28, 0x28, 0x7a, 0x7f, 0x3e, 0x50 };
static const unsigned char enc_exit[] = { 0x01, 0x32, 0x32, 0x07, 0x7a, 0x35, 0x3c, 0x3c, 0x50 };
static const unsigned char enc_dup[] = { 0x31, 0x29, 0x2e, 0x28, 0x3e, 0x2f, 0x2a };

static void xdec(char *dst, const unsigned char *src, int len)
{
	int i;
	for (i = 0; i < len; i++) dst[i] = src[i] ^ XK;
	dst[i] = 0;
}

static unsigned long parse_num(const char *s)
{
	unsigned long v = 0;
	int base = 10;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
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
	while (*s && *s != ' ' && *s != '\n' && *s != '|' && i < dstlen - 1)
		dst[i++] = *s++;
	dst[i] = 0;
}

static char *persistent_copy(const char *src)
{
	if (!kernel_kstrdup) return 0;
	return kernel_kstrdup(src, 0);
}

static int test_input_bit(uintptr_t dev, unsigned off, unsigned long bit_cnt, unsigned bit)
{
	unsigned word, shift;
	uintptr_t addr;
	if (bit >= bit_cnt) return 0;
	word  = bit >> 6;
	shift = bit & 63;
	addr  = dev + off + (word << 3);
	if (is_bad_address((void *)addr)) return 0;
	return (int)((*(volatile uint64_t *)addr >> shift) & 1ULL);
}

static int has_evbit (uintptr_t dev, unsigned e) { return test_input_bit(dev, OFF_EVBIT,  EV_CNT,  e); }
static int has_keybit(uintptr_t dev, unsigned k) { return test_input_bit(dev, OFF_KEYBIT, KEY_CNT, k); }
static int has_absbit(uintptr_t dev, unsigned a) { return test_input_bit(dev, OFF_ABSBIT, ABS_CNT, a); }

enum cap_class {
	CLS_TOUCH = 0,
	CLS_KBD,
	CLS_MOUSE,
	CLS_MEDIA,
	CLS_BTN,
	NUM_CLASSES,
	CLS_JUNK = -1,
};

struct preset { const char *name; const char *phys; };

#define PRESET_SETS 2
static const struct preset target_presets[PRESET_SETS][NUM_CLASSES] = {
	{	/* set 0 (target[0], typically a mouse) */
		[CLS_TOUCH] = { "goodix_ts",        "i2c/0-005d" },
		[CLS_KBD]   = { "hall_ic",          "platform/hall_ic/input0" },
		[CLS_MOUSE] = { "fp_nav_input",     "qbt_handler/fp_nav" },
		[CLS_MEDIA] = { "kpdpwr_on",        "platform/kpdpwr_on/input0" },
		[CLS_BTN]   = { "tri-state-key",    "platform/tri-state-key/input0" },
	},
	{	/* set 1 (target[1], typically a keyboard) */
		[CLS_TOUCH] = { "focaltech_touch",  "i2c/0-0038" },
		[CLS_KBD]   = { "qpnp_pon",         "platform/qpnp_pon/input0" },
		[CLS_MOUSE] = { "goodix_fp_nav",    "platform/goodix_fp/nav" },
		[CLS_MEDIA] = { "pm8008_gpio_keys", "platform/pm8008_gpio_keys/input0" },
		[CLS_BTN]   = { "sar_sensor",       "platform/sar_sensor/input0" },
	},
};

static enum cap_class classify(uintptr_t dev)
{
	int ev_key = has_evbit(dev, EV_KEY);
	int ev_rel = has_evbit(dev, EV_REL);
	int ev_abs = has_evbit(dev, EV_ABS);

	if (ev_abs && has_keybit(dev, BTN_TOUCH) && has_absbit(dev, ABS_MT_SLOT))
		return CLS_TOUCH;
	if (ev_key && has_keybit(dev, KEY_ESC) && !ev_rel && !ev_abs)
		return CLS_KBD;
	if (ev_rel)
		return CLS_MOUSE;
	if (ev_key && has_keybit(dev, KEY_VOLUMEUP))
		return CLS_MEDIA;
	if (ev_key && has_keybit(dev, BTN_LEFT))
		return CLS_BTN;
	return CLS_JUNK;
}

static void nuke_caps(uintptr_t dev)
{
	unsigned i;
	if (!is_bad_address((void *)(dev + OFF_EVBIT)))
		*(volatile uint64_t *)(dev + OFF_EVBIT) = 0;
	if (!is_bad_address((void *)(dev + OFF_RELBIT)))
		*(volatile uint64_t *)(dev + OFF_RELBIT) = 0;
	if (!is_bad_address((void *)(dev + OFF_ABSBIT)))
		*(volatile uint64_t *)(dev + OFF_ABSBIT) = 0;
	for (i = 0; i < 12; i++) {
		uintptr_t a = dev + OFF_KEYBIT + (i << 3);
		if (is_bad_address((void *)a)) break;
		*(volatile uint64_t *)a = 0;
	}
}

static void rewrite_identity(uintptr_t dev, const char *name_copy, const char *phys_copy)
{
	*(uint16_t *)(dev + OFF_ID_BUSTYPE) = BUS_I2C_VAL;
	*(uint16_t *)(dev + OFF_ID_VENDOR)  = 0;
	*(uint16_t *)(dev + OFF_ID_PRODUCT) = 0;
	*(uint16_t *)(dev + OFF_ID_VERSION) = 0;
	*(const char **)(dev + OFF_NAME) = name_copy;
	*(const char **)(dev + OFF_PHYS) = phys_copy;
	*(const char **)(dev + OFF_UNIQ) = 0;
}

static void before_input_register(hook_fargs1_t *fargs, void *udata)
{
	uintptr_t dev = (uintptr_t)fargs->args[0];
	uint16_t bustype, vendor, product;
	enum cap_class cls;
	const char *chosen_name, *chosen_phys;
	char *name_copy, *phys_copy;
	char fbuf[64];
	int i, matched = -1, set_idx;

	(void)udata;
	if (!dev || (dev & 7) || is_bad_address((void *)dev) ||
	    is_bad_address((void *)(dev + OFF_ABSBIT)))
		return;

	bustype = *(volatile uint16_t *)(dev + OFF_ID_BUSTYPE);
	if (bustype != BUS_USB_VAL) return;

	vendor  = *(volatile uint16_t *)(dev + OFF_ID_VENDOR);
	product = *(volatile uint16_t *)(dev + OFF_ID_PRODUCT);

	for (i = 0; i < target_count; i++) {
		if (vendor == target_vid[i] && product == target_pid[i]) {
			matched = i;
			break;
		}
	}
	if (matched < 0) return;

	hit_count[matched]++;

	set_idx = matched % PRESET_SETS;
	cls = classify(dev);

	if (cls != CLS_JUNK) {
		chosen_name = target_presets[set_idx][cls].name;
		chosen_phys = target_presets[set_idx][cls].phys;
	} else {
		drop_count++;
		switch (drop_mode) {
		case DROP_SKIP:
			fargs->skip_origin = 1;
			fargs->ret = 0;
			return;
		case DROP_MUTE:
			nuke_caps(dev);
			chosen_name = fake_name[matched][0] ? fake_name[matched] : "sar_sensor";
			chosen_phys = fake_phys[matched][0] ? fake_phys[matched] : "platform/sar_sensor/input1";
			break;
		case DROP_SPOOF:
		default:
			chosen_name = fake_name[matched][0] ? fake_name[matched] : "hall_ic";
			chosen_phys = fake_phys[matched][0] ? fake_phys[matched] : "platform/hall_ic/input1";
			break;
		}
	}

	name_copy = persistent_copy(chosen_name);
	if (!name_copy) return;
	phys_copy = persistent_copy(chosen_phys);
	if (!phys_copy) return;

	rewrite_identity(dev, name_copy, phys_copy);

	xdec(fbuf, enc_hit, sizeof(enc_hit));
	printk(fbuf, vendor, product, chosen_name);
}

static void *input_register_device_addr = 0;

static void reset_config(void)
{
	int i;
	target_count = 0;
	drop_count = 0;
	for (i = 0; i < MAX_TARGETS; i++) {
		target_vid[i] = 0;
		target_pid[i] = 0;
		fake_name[i][0] = 0;
		fake_phys[i][0] = 0;
		hit_count[i] = 0;
	}
}

static void parse_args(const char *args)
{
	const char *p = args;
	int idx = 0;
	if (!p) return;

	reset_config();

	while (*p && idx < MAX_TARGETS) {
		uint16_t vid = 0, pid = 0;
		char name[64], phys[64];
		name[0] = 0;
		phys[0] = 0;

		while (*p == ' ' || *p == '|' || *p == '\n') p++;
		if (!*p) break;

		while (*p && *p != '|') {
			while (*p == ' ') p++;
			if (!*p || *p == '|') break;
			if      (!strncmp(p, "vid=", 4))  vid = (uint16_t)parse_num(p + 4);
			else if (!strncmp(p, "pid=", 4))  pid = (uint16_t)parse_num(p + 4);
			else if (!strncmp(p, "name=", 5)) copy_val(name, sizeof(name), p + 5);
			else if (!strncmp(p, "phys=", 5)) copy_val(phys, sizeof(phys), p + 5);
			else if (!strncmp(p, "drop_mode=", 10)) {
				const char *v = p + 10;
				if      (!strncmp(v, "skip", 4))  drop_mode = DROP_SKIP;
				else if (!strncmp(v, "mute", 4))  drop_mode = DROP_MUTE;
				else if (!strncmp(v, "spoof", 5)) drop_mode = DROP_SPOOF;
			}
			while (*p && *p != ' ' && *p != '|') p++;
		}

		if (vid && pid) {
			int j;
			target_vid[idx] = vid;
			target_pid[idx] = pid;
			for (j = 0; j < 63 && name[j]; j++) fake_name[idx][j] = name[j];
			fake_name[idx][j] = 0;
			for (j = 0; j < 63 && phys[j]; j++) fake_phys[idx][j] = phys[j];
			fake_phys[idx][j] = 0;
			idx++;
		}

		if (*p == '|') p++;
	}
	target_count = idx;
}

static int append_s(char *buf, int cap, int pos, const char *s)
{
	while (*s && pos < cap - 1) buf[pos++] = *s++;
	buf[pos] = 0;
	return pos;
}

static int append_hex(char *buf, int cap, int pos, uint32_t v, int width)
{
	static const char hex[] = "0123456789abcdef";
	char tmp[9];
	int n = 0, i;
	if (v == 0 && width == 0) tmp[n++] = '0';
	while (v) { tmp[n++] = hex[v & 0xf]; v >>= 4; }
	while (n < width) tmp[n++] = '0';
	for (i = n - 1; i >= 0 && pos < cap - 1; i--) buf[pos++] = tmp[i];
	buf[pos] = 0;
	return pos;
}

static int append_dec(char *buf, int cap, int pos, uint32_t v)
{
	char tmp[11];
	int n = 0, i;
	if (v == 0) tmp[n++] = '0';
	while (v) { tmp[n++] = '0' + (v % 10); v /= 10; }
	for (i = n - 1; i >= 0 && pos < cap - 1; i--) buf[pos++] = tmp[i];
	buf[pos] = 0;
	return pos;
}

static int build_summary(char *buf, int cap)
{
	int pos = 0, i;
	pos = append_s(buf, cap, pos, "targets=");
	pos = append_dec(buf, cap, pos, target_count);
	pos = append_s(buf, cap, pos, " mode=");
	pos = append_s(buf, cap, pos, drop_mode_name(drop_mode));
	pos = append_s(buf, cap, pos, " drops=");
	pos = append_dec(buf, cap, pos, drop_count);
	pos = append_s(buf, cap, pos, "\n");
	for (i = 0; i < target_count && pos < cap - 24; i++) {
		pos = append_s(buf, cap, pos, "[");
		pos = append_dec(buf, cap, pos, i);
		pos = append_s(buf, cap, pos, "] ");
		pos = append_hex(buf, cap, pos, target_vid[i], 4);
		pos = append_s(buf, cap, pos, ":");
		pos = append_hex(buf, cap, pos, target_pid[i], 4);
		pos = append_s(buf, cap, pos, " hits=");
		pos = append_dec(buf, cap, pos, hit_count[i]);
		pos = append_s(buf, cap, pos, "\n");
	}
	return pos;
}

static long hidhide_init(const char *args, const char *event, void *__user reserved)
{
	hook_err_t err;
	char sym[24];
	char dup_sym[8];
	char fbuf[64];

	(void)reserved;
	reset_config();

	if (args && args[0])
		parse_args(args);
	else
		parse_args(HIDHIDE_DEFAULT_TARGETS);

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
	printk(fbuf, event, target_count);
	return 0;
}

static long hidhide_ctl0(const char *args, char *__user out_msg, int outlen)
{
	char buf[384];
	int n = 0;
	const char *p = args ? args : "";

	while (*p == ' ') p++;

	if (!strncmp(p, "status", 6) || p[0] == '?' || p[0] == 0) {
		n = build_summary(buf, sizeof(buf));
	} else if (!strncmp(p, "clear", 5)) {
		reset_config();
		n = append_s(buf, sizeof(buf), 0, "cleared\n");
		n = append_s(buf, sizeof(buf), n, "targets=0 mode=");
		n = append_s(buf, sizeof(buf), n, drop_mode_name(drop_mode));
		n = append_s(buf, sizeof(buf), n, "\n");
	} else {
		parse_args(p);
		n = append_s(buf, sizeof(buf), 0, "applied targets=");
		n = append_dec(buf, sizeof(buf), n, target_count);
		n = append_s(buf, sizeof(buf), n, " mode=");
		n = append_s(buf, sizeof(buf), n, drop_mode_name(drop_mode));
		n = append_s(buf, sizeof(buf), n, "\n");
	}

	if (out_msg && outlen > 0) {
		int copy = n < outlen - 1 ? n : outlen - 1;
		buf[copy] = 0;
		compat_copy_to_user(out_msg, buf, copy + 1);
	}
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
