/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2019 Joyent, Inc.
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

/*
 * based on usr/src/uts/common/os/kmem.c r1.64 from 2001/12/18
 *
 * The slab allocator, as described in the following two papers:
 *
 *	Jeff Bonwick,
 *	The Slab Allocator: An Object-Caching Kernel Memory Allocator.
 *	Proceedings of the Summer 1994 Usenix Conference.
 *	Available as /shared/sac/PSARC/1994/028/materials/kmem.pdf.
 *
 *	Jeff Bonwick and Jonathan Adams,
 *	Magazines and vmem: Extending the Slab Allocator to Many CPUs and
 *	Arbitrary Resources.
 *	Proceedings of the 2001 Usenix Conference.
 *	Available as /shared/sac/PSARC/2000/550/materials/vmem.pdf.
 *
 * 1. Overview
 * -----------
 * umem is very close to kmem in implementation.  There are seven major
 * areas of divergence:
 *
 *	* Initialization
 *
 *	* CPU handling
 *
 *	* umem_update()
 *
 *	* KM_SLEEP v.s. UMEM_NOFAIL
 *
 *	* lock ordering
 *
 *	* changing UMEM_MAXBUF
 *
 *	* Per-thread caching for malloc/free
 *
 * 2. Initialization
 * -----------------
 * kmem is initialized early on in boot, and knows that no one will call
 * into it before it is ready.  umem does not have these luxuries. Instead,
 * initialization is divided into two phases:
 *
 *	* library initialization, and
 *
 *	* first use
 *
 * umem's full initialization happens at the time of the first allocation
 * request (via malloc() and friends, umem_alloc(), or umem_zalloc()),
 * or the first call to umem_cache_create().
 *
 * umem_free(), and umem_cache_alloc() do not require special handling,
 * since the only way to get valid arguments for them is to successfully
 * call a function from the first group.
 *
 * 2.1. Library Initialization: umem_startup()
 * -------------------------------------------
 * umem_startup() is libumem.so's .init section.  It calls pthread_atfork()
 * to install the handlers necessary for umem's Fork1-Safety.  Because of
 * race condition issues, all other pre-umem_init() initialization is done
 * statically (i.e. by the dynamic linker).
 *
 * For standalone use, umem_startup() returns everything to its initial
 * state.
 *
 * 2.2. First use: umem_init()
 * ------------------------------
 * The first time any memory allocation function is used, we have to
 * create the backing caches and vmem arenas which are needed for it.
 * umem_init() is the central point for that task.  When it completes,
 * umem_ready is either UMEM_READY (all set) or UMEM_READY_INIT_FAILED (unable
 * to initialize, probably due to lack of memory).
 *
 * There are four different paths from which umem_init() is called:
 *
 *	* from umem_alloc() or umem_zalloc(), with 0 < size < UMEM_MAXBUF,
 *
 *	* from umem_alloc() or umem_zalloc(), with size > UMEM_MAXBUF,
 *
 *	* from umem_cache_create(), and
 *
 *	* from memalign(), with align > UMEM_ALIGN.
 *
 * The last three just check if umem is initialized, and call umem_init()
 * if it is not.  For performance reasons, the first case is more complicated.
 *
 * 2.2.1. umem_alloc()/umem_zalloc(), with 0 < size < UMEM_MAXBUF
 * -----------------------------------------------------------------
 * In this case, umem_cache_alloc(&umem_null_cache, ...) is called.
 * There is special case code in which causes any allocation on
 * &umem_null_cache to fail by returning (NULL), regardless of the
 * flags argument.
 *
 * So umem_cache_alloc() returns NULL, and umem_alloc()/umem_zalloc() call
 * umem_alloc_retry().  umem_alloc_retry() sees that the allocation
 * was agains &umem_null_cache, and calls umem_init().
 *
 * If initialization is successful, umem_alloc_retry() returns 1, which
 * causes umem_alloc()/umem_zalloc() to start over, which causes it to load
 * the (now valid) cache pointer from umem_alloc_table.
 *
 * 2.2.2. Dealing with race conditions
 * -----------------------------------
 * There are a couple race conditions resulting from the initialization
 * code that we have to guard against:
 *
 *	* In umem_cache_create(), there is a special UMC_INTERNAL cflag
 *	that is passed for caches created during initialization.  It
 *	is illegal for a user to try to create a UMC_INTERNAL cache.
 *	This allows initialization to proceed, but any other
 *	umem_cache_create()s will block by calling umem_init().
 *
 *	* Since umem_null_cache has a 1-element cache_cpu, it's cache_cpu_mask
 *	is always zero.  umem_cache_alloc uses cp->cache_cpu_mask to
 *	mask the cpu number.  This prevents a race between grabbing a
 *	cache pointer out of umem_alloc_table and growing the cpu array.
 *
 *
 * 3. CPU handling
 * ---------------
 * kmem uses the CPU's sequence number to determine which "cpu cache" to
 * use for an allocation.  Currently, there is no way to get the sequence
 * number in userspace.
 *
 * umem keeps track of cpu information in umem_cpus, an array of umem_max_ncpus
 * umem_cpu_t structures.  CURCPU() is a a "hint" function, which we then mask
 * with either umem_cpu_mask or cp->cache_cpu_mask to find the actual "cpu" id.
 * The mechanics of this is all in the CPU(mask) macro.
 *
 * Currently, umem uses _lwp_self() as its hint.
 *
 *
 * 4. The update thread
 * --------------------
 * kmem uses a task queue, kmem_taskq, to do periodic maintenance on
 * every kmem cache.  vmem has a periodic timeout for hash table resizing.
 * The kmem_taskq also provides a separate context for kmem_cache_reap()'s
 * to be done in, avoiding issues of the context of kmem_reap() callers.
 *
 * Instead, umem has the concept of "updates", which are asynchronous requests
 * for work attached to single caches.  All caches with pending work are
 * on a doubly linked list rooted at the umem_null_cache.  All update state
 * is protected by the umem_update_lock mutex, and the umem_update_cv is used
 * for notification between threads.
 *
 * 4.1. Cache states with regards to updates
 * -----------------------------------------
 * A given cache is in one of three states:
 *
 * Inactive		cache_uflags is zero, cache_u{next,prev} are NULL
 *
 * Work Requested	cache_uflags is non-zero (but UMU_ACTIVE is not set),
 *			cache_u{next,prev} link the cache onto the global
 *			update list
 *
 * Active		cache_uflags has UMU_ACTIVE set, cache_u{next,prev}
 *			are NULL, and either umem_update_thr or
 *			umem_st_update_thr are actively doing work on the
 *			cache.
 *
 * An update can be added to any cache in any state -- if the cache is
 * Inactive, it transitions to being Work Requested.  If the cache is
 * Active, the worker will notice the new update and act on it before
 * transitioning the cache to the Inactive state.
 *
 * If a cache is in the Active state, UMU_NOTIFY can be set, which asks
 * the worker to broadcast the umem_update_cv when it has finished.
 *
 * 4.2. Update interface
 * ---------------------
 * umem_add_update() adds an update to a particular cache.
 * umem_updateall() adds an update to all caches.
 * umem_remove_updates() returns a cache to the Inactive state.
 *
 * umem_process_updates() process all caches in the Work Requested state.
 *
 * 4.3. Reaping
 * ------------
 * When umem_reap() is called (at the time of heap growth), it schedule
 * UMU_REAP updates on every cache.  It then checks to see if the update
 * thread exists (umem_update_thr != 0).  If it is, it broadcasts
 * the umem_update_cv to wake the update thread up, and returns.
 *
 * If the update thread does not exist (umem_update_thr == 0), and the
 * program currently has multiple threads, umem_reap() attempts to create
 * a new update thread.
 *
 * If the process is not multithreaded, or the creation fails, umem_reap()
 * calls umem_st_update() to do an inline update.
 *
 * 4.4. The update thread
 * ----------------------
 * The update thread spends most of its time in cond_timedwait() on the
 * umem_update_cv.  It wakes up under two conditions:
 *
 *	* The timedwait times out, in which case it needs to run a global
 *	update, or
 *
 *	* someone cond_broadcast(3C)s the umem_update_cv, in which case
 *	it needs to check if there are any caches in the Work Requested
 *	state.
 *
 * When it is time for another global update, umem calls umem_cache_update()
 * on every cache, then calls vmem_update(), which tunes the vmem structures.
 * umem_cache_update() can request further work using umem_add_update().
 *
 * After any work from the global update completes, the update timer is
 * reset to umem_reap_interval seconds in the future.  This makes the
 * updates self-throttling.
 *
 * Reaps are similarly self-throttling.  After a UMU_REAP update has
 * been scheduled on all caches, umem_reap() sets a flag and wakes up the
 * update thread.  The update thread notices the flag, and resets the
 * reap state.
 *
 * 4.5. Inline updates
 * -------------------
 * If the update thread is not running, umem_st_update() is used instead.  It
 * immediately does a global update (as above), then calls
 * umem_process_updates() to process both the reaps that umem_reap() added and
 * any work generated by the global update.  Afterwards, it resets the reap
 * state.
 *
 * While the umem_st_update() is running, umem_st_update_thr holds the thread
 * id of the thread performing the update.
 *
 * 4.6. Updates and fork1()
 * ------------------------
 * umem has fork1() pre- and post-handlers which lock up (and release) every
 * mutex in every cache.  They also lock up the umem_update_lock.  Since
 * fork1() only copies over a single lwp, other threads (including the update
 * thread) could have been actively using a cache in the parent.  This
 * can lead to inconsistencies in the child process.
 *
 * Because we locked all of the mutexes, the only possible inconsistancies are:
 *
 *	* a umem_cache_alloc() could leak its buffer.
 *
 *	* a caller of umem_depot_alloc() could leak a magazine, and all the
 *	buffers contained in it.
 *
 *	* a cache could be in the Active update state.  In the child, there
 *	would be no thread actually working on it.
 *
 *	* a umem_hash_rescale() could leak the new hash table.
 *
 *	* a umem_magazine_resize() could be in progress.
 *
 *	* a umem_reap() could be in progress.
 *
 * The memory leaks we can't do anything about.  umem_release_child() resets
 * the update state, moves any caches in the Active state to the Work Requested
 * state.  This might cause some updates to be re-run, but UMU_REAP and
 * UMU_HASH_RESCALE are effectively idempotent, and the worst that can
 * happen from umem_magazine_resize() is resizing the magazine twice in close
 * succession.
 *
 * Much of the cleanup in umem_release_child() is skipped if
 * umem_st_update_thr == thr_self().  This is so that applications which call
 * fork1() from a cache callback does not break.  Needless to say, any such
 * application is tremendously broken.
 *
 *
 * 5. KM_SLEEP v.s. UMEM_NOFAIL
 * ----------------------------
 * Allocations against kmem and vmem have two basic modes:  SLEEP and
 * NOSLEEP.  A sleeping allocation is will go to sleep (waiting for
 * more memory) instead of failing (returning NULL).
 *
 * SLEEP allocations presume an extremely multithreaded model, with
 * a lot of allocation and deallocation activity.  umem cannot presume
 * that its clients have any particular type of behavior.  Instead,
 * it provides two types of allocations:
 *
 *	* UMEM_DEFAULT, equivalent to KM_NOSLEEP (i.e. return NULL on
 *	failure)
 *
 *	* UMEM_NOFAIL, which, on failure, calls an optional callback
 *	(registered with umem_nofail_callback()).
 *
 * The callback is invoked with no locks held, and can do an arbitrary
 * amount of work.  It then has a choice between:
 *
 *	* Returning UMEM_CALLBACK_RETRY, which will cause the allocation
 *	to be restarted.
 *
 *	* Returning UMEM_CALLBACK_EXIT(status), which will cause exit(2)
 *	to be invoked with status.  If multiple threads attempt to do
 *	this simultaneously, only one will call exit(2).
 *
 *	* Doing some kind of non-local exit (thr_exit(3C), longjmp(3C),
 *	etc.)
 *
 * The default callback returns UMEM_CALLBACK_EXIT(255).
 *
 * To have these callbacks without risk of state corruption (in the case of
 * a non-local exit), we have to ensure that the callbacks get invoked
 * close to the original allocation, with no inconsistent state or held
 * locks.  The following steps are taken:
 *
 *	* All invocations of vmem are VM_NOSLEEP.
 *
 *	* All constructor callbacks (which can themselves to allocations)
 *	are passed UMEM_DEFAULT as their required allocation argument.  This
 *	way, the constructor will fail, allowing the highest-level allocation
 *	invoke the nofail callback.
 *
 *	If a constructor callback _does_ do a UMEM_NOFAIL allocation, and
 *	the nofail callback does a non-local exit, we will leak the
 *	partially-constructed buffer.
 *
 *
 * 6. Lock Ordering
 * ----------------
 * umem has a few more locks than kmem does, mostly in the update path.  The
 * overall lock ordering (earlier locks must be acquired first) is:
 *
 *	umem_init_lock
 *
 *	vmem_list_lock
 *	vmem_nosleep_lock.vmpl_mutex
 *	vmem_t's:
 *		vm_lock
 *	sbrk_lock
 *
 *	umem_cache_lock
 *	umem_update_lock
 *	umem_flags_lock
 *	umem_cache_t's:
 *		cache_cpu[*].cc_lock
 *		cache_depot_lock
 *		cache_lock
 *	umem_log_header_t's:
 *		lh_cpu[*].clh_lock
 *		lh_lock
 *
 * 7. Changing UMEM_MAXBUF
 * -----------------------
 *
 * When changing UMEM_MAXBUF extra care has to be taken. It is not sufficient to
 * simply increase this number. First, one must update the umem_alloc_table to
 * have the appropriate number of entires based upon the new size. If this is
 * not done, this will lead to libumem blowing an assertion.
 *
 * The second place to update, which is not required, is the umem_alloc_sizes.
 * These determine the default cache sizes that we're going to support.
 *
 * 8. Per-thread caching for malloc/free
 * -------------------------------------
 *
 * "Time is an illusion. Lunchtime doubly so." -- Douglas Adams
 *
 * Time may be an illusion, but CPU cycles aren't.  While libumem is designed
 * to be a highly scalable allocator, that scalability comes with a fixed cycle
 * penalty even in the absence of contention: libumem must acquire (and release
 * a per-CPU lock for each allocation.  When contention is low and malloc(3C)
 * frequency is high, this overhead can dominate execution time.  To alleviate
 * this, we allow for per-thread caching, a lock-free means of caching recent
 * deallocations on a per-thread basis for use in satisfying subsequent calls
 *
 * In addition to improving performance, we also want to:
 *	* Minimize fragmentation
 *	* Not add additional memory overhead (no larger malloc tags)
 *
 * In the ulwp_t of each thread there is a private data structure called a
 * umem_t that looks like:
 *
 * typedef struct {
 *	size_t	tm_size;
 *	void	*tm_roots[NTMEMBASE];  (Currently 16)
 * } tmem_t;
 *
 * Each of the roots is treated as the head of a linked list. Each entry in the
 * list can be thought of as a void ** which points to the next entry, until one
 * of them points to NULL. If the head points to NULL, the list is empty.
 *
 * Each head corresponds to a umem_cache. Currently there is a linear mapping
 * where the first root corresponds to the first cache, second root to the
 * second cache, etc. This works because every allocation that malloc makes to
 * umem_alloc that can be satisified by a umem_cache will actually return a
 * number of bytes equal to the size of that cache. Because of this property and
 * a one to one mapping between caches and roots we can guarantee that every
 * entry in a given root's list will be able to satisfy the same requests as the
 * corresponding cache.
 *
 * The choice of sixteen roots is based on where we believe we get the biggest
 * bang for our buck. The per-thread caches will cache up to 256 byte and 448
 * byte allocations on ILP32 and LP64 respectively. Generally applications plan
 * more carefully how they do larger allocations than smaller ones. Therefore
 * sixteen roots is a reasonable compromise between the amount of additional
 * overhead per thread, and the likelihood of a program to benefit from it.
 *
 * The maximum amount of memory that can be cached in each thread is determined
 * by the perthread_cache UMEM_OPTION. It corresponds to the umem_ptc_size
 * value. The default value for this is currently 1 MB. Once umem_init() has
 * finished this cannot be directly tuned without directly modifying the
 * instruction text. If, upon calling free(3C), the amount cached would exceed
 * this maximum, we instead actually return the buffer to the umem_cache instead
 * of holding onto it in the thread.
 *
 * When a thread calls malloc(3C) it first determines which umem_cache it
 * would be serviced by. If the allocation is not covered by ptcumem it goes to
 * the normal malloc instead.  Next, it checks if the tmem_root's list is empty
 * or not. If it is empty, we instead go and allocate the memory from
 * umem_alloc. If it is not empty, we remove the head of the list, set the
 * appropriate malloc tags, and return that buffer.
 *
 * When a thread calls free(3C) it first looks at the malloc tag and if it is
 * invalid or the allocation exceeds the largest cache in ptcumem and sends it
 * off to the original free() to handle and clean up appropriately. Next, it
 * checks if the allocation size is covered by one of the per-thread roots and
 * if it isn't, it passes it off to the original free() to be released. Finally,
 * before it inserts this buffer as the head, it checks if adding this buffer
 * would put the thread over its maximum cache size. If it would, it frees the
 * buffer back to the umem_cache. Otherwise it increments the threads total
 * cached amount and makes the buffer the new head of the appropriate tm_root.
 *
 * When a thread exits, all of the buffers that it has in its per-thread cache
 * will be passed to umem_free() and returned to the appropriate umem_cache.
 *
 * 8.1 Handling addition and removal of umem_caches
 * ------------------------------------------------
 *
 * The set of umem_caches that are used to back calls to umem_alloc() and
 * ultimately malloc() are determined at program execution time. The default set
 * of caches is defined below in umem_alloc_sizes[]. Various umem_options exist
 * that modify the set of caches: size_add, size_clear, and size_remove. Because
 * the set of caches can only be determined once umem_init() has been called and
 * we have the additional goals of minimizing additional fragmentation and
 * metadata space overhead in the malloc tags, this forces our hand to go down a
 * slightly different path: the one tread by fasttrap and trapstat.
 *
 * During umem_init we're going to dynamically construct a new version of
 * malloc(3C) and free(3C) that utilizes the known cache sizes and then ensure
 * that ptcmalloc and ptcfree replace malloc and free as entries in the plt. If
 * ptcmalloc and ptcfree cannot handle a request, they simply jump to the
 * original libumem implementations.
 *
 * After creating all of the umem_caches, but before making them visible,
 * umem_cache_init checks that umem_genasm_supported is non-zero. This value is
 * set by each architecture in $ARCH/umem_genasm.c to indicate whether or not
 * they support this. If the value is zero, then this process is skipped.
 * Similarly, if the cache size has been tuned to zero by UMEM_OPTIONS, then
 * this is also skipped.
 *
 * In umem_genasm.c, each architecture's implementation implements a single
 * function called umem_genasm() that is responsible for generating the
 * appropriate versions of ptcmalloc() and ptcfree(), placing them in the
 * appropriate memory location, and finally doing the switch from malloc() and
 * free() to ptcmalloc() and ptcfree().  Once the change has been made, there is
 * no way to switch back, short of restarting the program or modifying program
 * text with mdb.
 *
 * 8.2 Modifying the Procedure Linkage Table (PLT)
 * -----------------------------------------------
 *
 * The last piece of this puzzle is how we actually jam ptcmalloc() into the
 * PLT.  To handle this, we have defined two functions, _malloc and _free, we
 * use a standard #pragma weak for malloc and free and direct them to those
 * symbols. By default, those symbols have text defined as nops for our
 * generated functions and when they're invoked, they jump to the default
 * malloc and free functions.
 *
 * When umem_genasm() is called, it makes _malloc and _free writeable and goes
 * through and updates the text provided for by _malloc and _free just after
 * the jump. Once both have been successfully generated, umem_genasm() nops
 * over the original jump so that we now call into the genasm versions of
 * these functions, and makes the functions read-only once again.
 *
 * 8.3 umem_genasm()
 * -----------------
 *
 * umem_genasm() is currently implemented for i386 and amd64. This section
 * describes the theory behind the construction. For specific byte code to
 * assembly instructions and niceish C and asm versions of ptcmalloc and
 * ptcfree, see the individual umem_genasm.c files. The layout consists of the
 * following sections:
 *
 *	o. function-specfic prologue
 *	o. function-generic cache-selecting elements
 *	o. function-specific epilogue
 *
 * There are three different generic cache elements that exist:
 *
 *	o. the last or only cache
 *	o. the intermediary caches if more than two
 *	o. the first one if more than one cache
 *
 * The malloc and free prologues and epilogues mimic the necessary portions of
 * libumem's malloc and free. This includes things like checking for size
 * overflow, setting and verifying the malloc tags.
 *
 * It is an important constraint that these functions do not make use of the
 * call instruction. The only jmp outside of the individual functions is to the
 * original libumem malloc and free respectively. Because doing things like
 * setting errno or raising an internal umem error on improper malloc tags would
 * require using calls into the PLT, whenever we encounter one of those cases we
 * just jump to the original malloc and free functions reusing the same stack
 * frame.
 *
 * Each of the above sections, the three caches, and the malloc and free
 * prologue and epilogue are implemented as blocks of machine code with the
 * corresponding assembly in comments. There are known offsets into each block
 * that corresponds to locations of data and addresses that we only know at run
 * time. These blocks are copied as necessary and the blanks filled in
 * appropriately.
 *
 * As mentioned in section 8.2, the trampoline library uses specifically named
 * variables to communicate the buffers and size to use. These variables are:
 *
 *	o. umem_genasm_mptr: The buffer for ptcmalloc
 *	o. umem_genasm_msize: The size in bytes of the above buffer
 *	o. umem_genasm_fptr: The buffer for ptcfree
 *	o. umem_genasm_fsize: The size in bytes of the above buffer
 *
 * Finally, to enable the generated assembly we need to remove the previous jump
 * to the actual malloc that exists at the start of these buffers. On x86, this
 * is a five byte region. We could zero out the jump offset to be a jmp +0, but
 * using nops can be faster. We specifically use a single five byte nop on x86
 * as it is faster. When porting ptcumem to other architectures, the various
 * opcode changes and options should be analyzed.
 *
 * 8.4 Interface with libc.so
 * --------------------------
 *
 * The tmem_t structure as described in the beginning of section 8, is part of a
 * private interface with libc. There are three functions that exist to cover
 * this. They are not documented in man pages or header files. They are in the
 * SUNWprivate part of libc's mapfile.
 *
 *	o. _tmem_get_base(void)
 *
 *	Returns the offset from the ulwp_t (curthread) to the tmem_t structure.
 *	This is a constant for all threads and is effectively a way to to do
 *	::offsetof ulwp_t ul_tmem without having to know the specifics of the
 *	structure outside of libc.
 *
 *	o. _tmem_get_nentries(void)
 *
 *	Returns the number of roots that exist in the tmem_t. This is one part
 *	of the cap on the number of umem_caches that we can back with tmem.
 *
 *	o. _tmem_set_cleanup(void (*)(void *, int))
 *
 *	This sets a clean up handler that gets called back when a thread exits.
 *	There is one call per buffer, the void * is a pointer to the buffer on
 *	the list, the int is the index into the roots array for this buffer.
 *
 * 8.5 Tuning and disabling per-thread caching
 * -------------------------------------------
 *
 * There is only one tunable for per-thread caching:  the amount of memory each
 * thread should be able to cache.  This is specified via the perthread_cache
 * UMEM_OPTION option.  No attempt is made to to sanity check the specified
 * value; the limit is simply the maximum value of a size_t.
 *
 * If the perthread_cache UMEM_OPTION is set to zero, nomagazines was requested,
 * or UMEM_DEBUG has been turned on then we will never call into umem_genasm;
 * however, the trampoline audit library and jump will still be in place.
 *
 * 8.6 Observing efficacy of per-thread caching
 * --------------------------------------------
 *
 * To understand the efficacy of per-thread caching, use the ::umastat dcmd
 * to see the percentage of capacity consumed on a per-thread basis, the
 * degree to which each umem cache contributes to per-thread cache consumption,
 * and the number of buffers in per-thread caches on a per-umem cache basis.
 * If more detail is required, the specific buffers in a per-thread cache can
 * be iterated over with the umem_ptc_* walkers. (These walkers allow an
 * optional ulwp_t to be specified to iterate only over a particular thread's
 * cache.)
 */

#include <umem_impl.h>
#include <sys/vmem_impl_user.h>
#include "umem_base.h"
#include "vmem_base.h"

#include <sys/processor.h>
#include <sys/sysmacros.h>

#include <alloca.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <atomic.h>

#include "misc.h"

#define	UMEM_VMFLAGS(umflag)	(VM_NOSLEEP)

size_t pagesize;

/*
 * The default set of caches to back umem_alloc().
 * These sizes should be reevaluated periodically.
 *
 * We want allocations that are multiples of the coherency granularity
 * (64 bytes) to be satisfied from a cache which is a multiple of 64
 * bytes, so that it will be 64-byte aligned.  For all multiples of 64,
 * the next kmem_cache_size greater than or equal to it must be a
 * multiple of 64.
 *
 * This table must be in sorted order, from smallest to highest.  The
 * highest slot must be UMEM_MAXBUF, and every slot afterwards must be
 * zero.
 */
static int umem_alloc_sizes[] = {
#ifdef _LP64
	1 * 8,
	1 * 16,
	2 * 16,
	3 * 16,
#else
	1 * 8,
	2 * 8,
	3 * 8,
	4 * 8,		5 * 8,		6 * 8,		7 * 8,
#endif
	4 * 16,		5 * 16,		6 * 16,		7 * 16,
	4 * 32,		5 * 32,		6 * 32,		7 * 32,
	4 * 64,		5 * 64,		6 * 64,		7 * 64,
	4 * 128,	5 * 128,	6 * 128,	7 * 128,
	P2ALIGN(8192 / 7, 64),
	P2ALIGN(8192 / 6, 64),
	P2ALIGN(8192 / 5, 64),
	P2ALIGN(8192 / 4, 64), 2304,
	P2ALIGN(8192 / 3, 64),
	P2ALIGN(8192 / 2, 64), 4544,
	P2ALIGN(8192 / 1, 64), 9216,
	4096 * 3,
	8192 * 2,				/* = 8192 * 2 */
	24576, 32768, 40960, 49152, 57344, 65536, 73728, 81920,
	90112, 98304, 106496, 114688, 122880, UMEM_MAXBUF, /* 128k */
	/* 24 slots for user expansion */
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};
#define	NUM_ALLOC_SIZES (sizeof (umem_alloc_sizes) / sizeof (*umem_alloc_sizes))

static umem_magtype_t umem_magtype[] = {
	{ 1,	8,	3200,	65536	},
	{ 3,	16,	256,	32768	},
	{ 7,	32,	64,	16384	},
	{ 15,	64,	0,	8192	},
	{ 31,	64,	0,	4096	},
	{ 47,	64,	0,	2048	},
	{ 63,	64,	0,	1024	},
	{ 95,	64,	0,	512	},
	{ 143,	64,	0,	0	},
};

/*
 * umem tunables
 */
uint32_t umem_max_ncpus;	/* # of CPU caches. */

uint32_t umem_stack_depth = 15; /* # stack frames in a bufctl_audit */
uint32_t umem_reap_interval = 10; /* max reaping rate (seconds) */
uint_t umem_depot_contention = 2; /* max failed trylocks per real interval */
uint_t umem_abort = 1;		/* whether to abort on error */
uint_t umem_output = 0;		/* whether to write to standard error */
uint_t umem_logging = 0;	/* umem_log_enter() override */
uint32_t umem_mtbf = 0;		/* mean time between failures [default: off] */
size_t umem_transaction_log_size; /* size of transaction log */
size_t umem_content_log_size;	/* size of content log */
size_t umem_failure_log_size;	/* failure log [4 pages per CPU] */
size_t umem_slab_log_size;	/* slab create log [4 pages per CPU] */
size_t umem_content_maxsave = 256; /* UMF_CONTENTS max bytes to log */
size_t umem_lite_minsize = 0;	/* minimum buffer size for UMF_LITE */
size_t umem_lite_maxalign = 1024; /* maximum buffer alignment for UMF_LITE */
size_t umem_maxverify;		/* maximum bytes to inspect in debug routines */
size_t umem_minfirewall;	/* hardware-enforced redzone threshold */
size_t umem_ptc_size = 1048576;	/* size of per-thread cache (in bytes) */

uint_t umem_flags = 0;
uintptr_t umem_tmem_off;

mutex_t			umem_init_lock;		/* locks initialization */
cond_t			umem_init_cv;		/* initialization CV */
thread_t		umem_init_thr;		/* thread initializing */
int			umem_init_env_ready;	/* environ pre-initted */
int			umem_ready = UMEM_READY_STARTUP;

int			umem_ptc_enabled;	/* per-thread caching enabled */

static umem_nofail_callback_t *nofail_callback;
static mutex_t		umem_nofail_exit_lock;
static thread_t		umem_nofail_exit_thr;

static umem_cache_t	*umem_slab_cache;
static umem_cache_t	*umem_bufctl_cache;
static umem_cache_t	*umem_bufctl_audit_cache;

mutex_t			umem_flags_lock;

static vmem_t		*heap_arena;
static vmem_alloc_t	*heap_alloc;
static vmem_free_t	*heap_free;

static vmem_t		*umem_internal_arena;
static vmem_t		*umem_cache_arena;
static vmem_t		*umem_hash_arena;
static vmem_t		*umem_log_arena;
static vmem_t		*umem_oversize_arena;
static vmem_t		*umem_va_arena;
static vmem_t		*umem_default_arena;
static vmem_t		*umem_firewall_va_arena;
static vmem_t		*umem_firewall_arena;

vmem_t			*umem_memalign_arena;

umem_log_header_t *umem_transaction_log;
umem_log_header_t *umem_content_log;
umem_log_header_t *umem_failure_log;
umem_log_header_t *umem_slab_log;

#define	CPUHINT()		(thr_self())
#define	CPUHINT_MAX()		INT_MAX

#define	CPU(mask)		(umem_cpus + (CPUHINT() & (mask)))
static umem_cpu_t umem_startup_cpu = {	/* initial, single, cpu */
	UMEM_CACHE_SIZE(0),
	0
};

static uint32_t umem_cpu_mask = 0;			/* global cpu mask */
static umem_cpu_t *umem_cpus = &umem_startup_cpu;	/* cpu list */

volatile uint32_t umem_reaping;

thread_t		umem_update_thr;
struct timeval		umem_update_next;	/* timeofday of next update */
volatile thread_t	umem_st_update_thr;	/* only used when single-thd */

#define	IN_UPDATE()	(thr_self() == umem_update_thr || \
			    thr_self() == umem_st_update_thr)
#define	IN_REAP()	IN_UPDATE()

mutex_t			umem_update_lock;	/* cache_u{next,prev,flags} */
cond_t			umem_update_cv;

volatile hrtime_t umem_reap_next;	/* min hrtime of next reap */

mutex_t			umem_cache_lock;	/* inter-cache linkage only */

#ifdef UMEM_STANDALONE
umem_cache_t		umem_null_cache;
static const umem_cache_t umem_null_cache_template = {
#else
umem_cache_t		umem_null_cache = {
#endif
	0, 0, 0, 0, 0,
	0, 0,
	0, 0,
	0, 0,
	"invalid_cache",
	0, 0,
	NULL, NULL, NULL, NULL,
	NULL,
	0, 0, 0, 0,
	&umem_null_cache, &umem_null_cache,
	&umem_null_cache, &umem_null_cache,
	0,
	DEFAULTMUTEX,				/* start of slab layer */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	&umem_null_cache.cache_nullslab,
	{
		&umem_null_cache,
		NULL,
		&umem_null_cache.cache_nullslab,
		&umem_null_cache.cache_nullslab,
		NULL,
		-1,
		0
	},
	NULL,
	NULL,
	DEFAULTMUTEX,				/* start of depot layer */
	NULL, {
		NULL, 0, 0, 0, 0
	}, {
		NULL, 0, 0, 0, 0
	}, {
		{
			DEFAULTMUTEX,		/* start of CPU cache */
			0, 0, NULL, NULL, -1, -1, 0
		}
	}
};

#define	ALLOC_TABLE_4 \
	&umem_null_cache, &umem_null_cache, &umem_null_cache, &umem_null_cache

#define	ALLOC_TABLE_64 \
	ALLOC_TABLE_4, ALLOC_TABLE_4, ALLOC_TABLE_4, ALLOC_TABLE_4, \
	ALLOC_TABLE_4, ALLOC_TABLE_4, ALLOC_TABLE_4, ALLOC_TABLE_4, \
	ALLOC_TABLE_4, ALLOC_TABLE_4, ALLOC_TABLE_4, ALLOC_TABLE_4, \
	ALLOC_TABLE_4, ALLOC_TABLE_4, ALLOC_TABLE_4, ALLOC_TABLE_4

#define	ALLOC_TABLE_1024 \
	ALLOC_TABLE_64, ALLOC_TABLE_64, ALLOC_TABLE_64, ALLOC_TABLE_64, \
	ALLOC_TABLE_64, ALLOC_TABLE_64, ALLOC_TABLE_64, ALLOC_TABLE_64, \
	ALLOC_TABLE_64, ALLOC_TABLE_64, ALLOC_TABLE_64, ALLOC_TABLE_64, \
	ALLOC_TABLE_64, ALLOC_TABLE_64, ALLOC_TABLE_64, ALLOC_TABLE_64

static umem_cache_t *umem_alloc_table[UMEM_MAXBUF >> UMEM_ALIGN_SHIFT] = {
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024,
	ALLOC_TABLE_1024
};


/* Used to constrain audit-log stack traces */
caddr_t			umem_min_stack;
caddr_t			umem_max_stack;


#define	UMERR_MODIFIED	0	/* buffer modified while on freelist */
#define	UMERR_REDZONE	1	/* redzone violation (write past end of buf) */
#define	UMERR_DUPFREE	2	/* freed a buffer twice */
#define	UMERR_BADADDR	3	/* freed a bad (unallocated) address */
#define	UMERR_BADBUFTAG	4	/* buftag corrupted */
#define	UMERR_BADBUFCTL	5	/* bufctl corrupted */
#define	UMERR_BADCACHE	6	/* freed a buffer to the wrong cache */
#define	UMERR_BADSIZE	7	/* alloc size != free size */
#define	UMERR_BADBASE	8	/* buffer base address wrong */

struct {
	hrtime_t	ump_timestamp;	/* timestamp of error */
	int		ump_error;	/* type of umem error (UMERR_*) */
	void		*ump_buffer;	/* buffer that induced abort */
	void		*ump_realbuf;	/* real start address for buffer */
	umem_cache_t	*ump_cache;	/* buffer's cache according to client */
	umem_cache_t	*ump_realcache;	/* actual cache containing buffer */
	umem_slab_t	*ump_slab;	/* slab accoring to umem_findslab() */
	umem_bufctl_t	*ump_bufctl;	/* bufctl */
} umem_abort_info;

static void
copy_pattern(uint64_t pattern, void *buf_arg, size_t size)
{
	uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
	uint64_t *buf = buf_arg;

	while (buf < bufend)
		*buf++ = pattern;
}

static void *
verify_pattern(uint64_t pattern, void *buf_arg, size_t size)
{
	uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
	uint64_t *buf;

	for (buf = buf_arg; buf < bufend; buf++)
		if (*buf != pattern)
			return (buf);
	return (NULL);
}

static void *
verify_and_copy_pattern(uint64_t old, uint64_t new, void *buf_arg, size_t size)
{
	uint64_t *bufend = (uint64_t *)((char *)buf_arg + size);
	uint64_t *buf;

	for (buf = buf_arg; buf < bufend; buf++) {
		if (*buf != old) {
			copy_pattern(old, buf_arg,
			    (char *)buf - (char *)buf_arg);
			return (buf);
		}
		*buf = new;
	}

	return (NULL);
}

void
umem_cache_applyall(void (*func)(umem_cache_t *))
{
	umem_cache_t *cp;

	(void) mutex_lock(&umem_cache_lock);
	for (cp = umem_null_cache.cache_next; cp != &umem_null_cache;
	    cp = cp->cache_next)
		func(cp);
	(void) mutex_unlock(&umem_cache_lock);
}

static void
umem_add_update_unlocked(umem_cache_t *cp, int flags)
{
	umem_cache_t *cnext, *cprev;

	flags &= ~UMU_ACTIVE;

	if (!flags)
		return;

	if (cp->cache_uflags & UMU_ACTIVE) {
		cp->cache_uflags |= flags;
	} else {
		if (cp->cache_unext != NULL) {
			ASSERT(cp->cache_uflags != 0);
			cp->cache_uflags |= flags;
		} else {
			ASSERT(cp->cache_uflags == 0);
			cp->cache_uflags = flags;
			cp->cache_unext = cnext = &umem_null_cache;
			cp->cache_uprev = cprev = umem_null_cache.cache_uprev;
			cnext->cache_uprev = cp;
			cprev->cache_unext = cp;
		}
	}
}

static void
umem_add_update(umem_cache_t *cp, int flags)
{
	(void) mutex_lock(&umem_update_lock);

	umem_add_update_unlocked(cp, flags);

	if (!IN_UPDATE())
		(void) cond_broadcast(&umem_update_cv);

	(void) mutex_unlock(&umem_update_lock);
}

/*
 * Remove a cache from the update list, waiting for any in-progress work to
 * complete first.
 */
static void
umem_remove_updates(umem_cache_t *cp)
{
	(void) mutex_lock(&umem_update_lock);

	/*
	 * Get it out of the active state
	 */
	while (cp->cache_uflags & UMU_ACTIVE) {
		int cancel_state;

		ASSERT(cp->cache_unext == NULL);

		cp->cache_uflags |= UMU_NOTIFY;

		/*
		 * Make sure the update state is sane, before we wait
		 */
		ASSERT(umem_update_thr != 0 || umem_st_update_thr != 0);
		ASSERT(umem_update_thr != thr_self() &&
		    umem_st_update_thr != thr_self());

		(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
		    &cancel_state);
		(void) cond_wait(&umem_update_cv, &umem_update_lock);
		(void) pthread_setcancelstate(cancel_state, NULL);
	}
	/*
	 * Get it out of the Work Requested state
	 */
	if (cp->cache_unext != NULL) {
		cp->cache_uprev->cache_unext = cp->cache_unext;
		cp->cache_unext->cache_uprev = cp->cache_uprev;
		cp->cache_uprev = cp->cache_unext = NULL;
		cp->cache_uflags = 0;
	}
	/*
	 * Make sure it is in the Inactive state
	 */
	ASSERT(cp->cache_unext == NULL && cp->cache_uflags == 0);
	(void) mutex_unlock(&umem_update_lock);
}

static void
umem_updateall(int flags)
{
	umem_cache_t *cp;

	/*
	 * NOTE:  To prevent deadlock, umem_cache_lock is always acquired first.
	 *
	 * (umem_add_update is called from things run via umem_cache_applyall)
	 */
	(void) mutex_lock(&umem_cache_lock);
	(void) mutex_lock(&umem_update_lock);

	for (cp = umem_null_cache.cache_next; cp != &umem_null_cache;
	    cp = cp->cache_next)
		umem_add_update_unlocked(cp, flags);

	if (!IN_UPDATE())
		(void) cond_broadcast(&umem_update_cv);

	(void) mutex_unlock(&umem_update_lock);
	(void) mutex_unlock(&umem_cache_lock);
}

/*
 * Debugging support.  Given a buffer address, find its slab.
 */
static umem_slab_t *
umem_findslab(umem_cache_t *cp, void *buf)
{
	umem_slab_t *sp;

	(void) mutex_lock(&cp->cache_lock);
	for (sp = cp->cache_nullslab.slab_next;
	    sp != &cp->cache_nullslab; sp = sp->slab_next) {
		if (UMEM_SLAB_MEMBER(sp, buf)) {
			(void) mutex_unlock(&cp->cache_lock);
			return (sp);
		}
	}
	(void) mutex_unlock(&cp->cache_lock);

	return (NULL);
}

static void
umem_error(int error, umem_cache_t *cparg, void *bufarg)
{
	umem_buftag_t *btp = NULL;
	umem_bufctl_t *bcp = NULL;
	umem_cache_t *cp = cparg;
	umem_slab_t *sp;
	uint64_t *off;
	void *buf = bufarg;

	int old_logging = umem_logging;

	umem_logging = 0;	/* stop logging when a bad thing happens */

	umem_abort_info.ump_timestamp = gethrtime();

	sp = umem_findslab(cp, buf);
	if (sp == NULL) {
		for (cp = umem_null_cache.cache_prev; cp != &umem_null_cache;
		    cp = cp->cache_prev) {
			if ((sp = umem_findslab(cp, buf)) != NULL)
				break;
		}
	}

	if (sp == NULL) {
		cp = NULL;
		error = UMERR_BADADDR;
	} else {
		if (cp != cparg)
			error = UMERR_BADCACHE;
		else
			buf = (char *)bufarg - ((uintptr_t)bufarg -
			    (uintptr_t)sp->slab_base) % cp->cache_chunksize;
		if (buf != bufarg)
			error = UMERR_BADBASE;
		if (cp->cache_flags & UMF_BUFTAG)
			btp = UMEM_BUFTAG(cp, buf);
		if (cp->cache_flags & UMF_HASH) {
			(void) mutex_lock(&cp->cache_lock);
			for (bcp = *UMEM_HASH(cp, buf); bcp; bcp = bcp->bc_next)
				if (bcp->bc_addr == buf)
					break;
			(void) mutex_unlock(&cp->cache_lock);
			if (bcp == NULL && btp != NULL)
				bcp = btp->bt_bufctl;
			if (umem_findslab(cp->cache_bufctl_cache, bcp) ==
			    NULL || P2PHASE((uintptr_t)bcp, UMEM_ALIGN) ||
			    bcp->bc_addr != buf) {
				error = UMERR_BADBUFCTL;
				bcp = NULL;
			}
		}
	}

	umem_abort_info.ump_error = error;
	umem_abort_info.ump_buffer = bufarg;
	umem_abort_info.ump_realbuf = buf;
	umem_abort_info.ump_cache = cparg;
	umem_abort_info.ump_realcache = cp;
	umem_abort_info.ump_slab = sp;
	umem_abort_info.ump_bufctl = bcp;

	umem_printf("umem allocator: ");

	switch (error) {

	case UMERR_MODIFIED:
		umem_printf("buffer modified after being freed\n");
		off = verify_pattern(UMEM_FREE_PATTERN, buf, cp->cache_verify);
		if (off == NULL)	/* shouldn't happen */
			off = buf;
		umem_printf("modification occurred at offset 0x%lx "
		    "(0x%llx replaced by 0x%llx)\n",
		    (uintptr_t)off - (uintptr_t)buf,
		    (longlong_t)UMEM_FREE_PATTERN, (longlong_t)*off);
		break;

	case UMERR_REDZONE:
		umem_printf("redzone violation: write past end of buffer\n");
		break;

	case UMERR_BADADDR:
		umem_printf("invalid free: buffer not in cache\n");
		break;

	case UMERR_DUPFREE:
		umem_printf("duplicate free: buffer freed twice\n");
		break;

	case UMERR_BADBUFTAG:
		umem_printf("boundary tag corrupted\n");
		umem_printf("bcp ^ bxstat = %lx, should be %lx\n",
		    (intptr_t)btp->bt_bufctl ^ btp->bt_bxstat,
		    UMEM_BUFTAG_FREE);
		break;

	case UMERR_BADBUFCTL:
		umem_printf("bufctl corrupted\n");
		break;

	case UMERR_BADCACHE:
		umem_printf("buffer freed to wrong cache\n");
		umem_printf("buffer was allocated from %s,\n", cp->cache_name);
		umem_printf("caller attempting free to %s.\n",
		    cparg->cache_name);
		break;

	case UMERR_BADSIZE:
		umem_printf("bad free: free size (%u) != alloc size (%u)\n",
		    UMEM_SIZE_DECODE(((uint32_t *)btp)[0]),
		    UMEM_SIZE_DECODE(((uint32_t *)btp)[1]));
		break;

	case UMERR_BADBASE:
		umem_printf("bad free: free address (%p) != alloc address "
		    "(%p)\n", bufarg, buf);
		break;
	}

	umem_printf("buffer=%p  bufctl=%p  cache: %s\n",
	    bufarg, (void *)bcp, cparg->cache_name);

	if (bcp != NULL && (cp->cache_flags & UMF_AUDIT) &&
	    error != UMERR_BADBUFCTL) {
		int d;
		timespec_t ts;
		hrtime_t diff;
		umem_bufctl_audit_t *bcap = (umem_bufctl_audit_t *)bcp;

		diff = umem_abort_info.ump_timestamp - bcap->bc_timestamp;
		ts.tv_sec = diff / NANOSEC;
		ts.tv_nsec = diff % NANOSEC;

		umem_printf("previous transaction on buffer %p:\n", buf);
		umem_printf("thread=%p  time=T-%ld.%09ld  slab=%p  cache: %s\n",
		    (void *)(intptr_t)bcap->bc_thread, ts.tv_sec, ts.tv_nsec,
		    (void *)sp, cp->cache_name);
		for (d = 0; d < MIN(bcap->bc_depth, umem_stack_depth); d++) {
			(void) print_sym((void *)bcap->bc_stack[d]);
			umem_printf("\n");
		}
	}

	umem_err_recoverable("umem: heap corruption detected");

	umem_logging = old_logging;	/* resume logging */
}

void
umem_nofail_callback(umem_nofail_callback_t *cb)
{
	nofail_callback = cb;
}

static int
umem_alloc_retry(umem_cache_t *cp, int umflag)
{
	if (cp == &umem_null_cache) {
		if (umem_init())
			return (1);				/* retry */
		/*
		 * Initialization failed.  Do normal failure processing.
		 */
	}
	if (umem_flags & UMF_CHECKNULL) {
		umem_err_recoverable("umem: out of heap space");
	}
	if (umflag & UMEM_NOFAIL) {
		int def_result = UMEM_CALLBACK_EXIT(255);
		int result = def_result;
		umem_nofail_callback_t *callback = nofail_callback;

		if (callback != NULL)
			result = callback();

		if (result == UMEM_CALLBACK_RETRY)
			return (1);

		if ((result & ~0xFF) != UMEM_CALLBACK_EXIT(0)) {
			log_message("nofail callback returned %x\n", result);
			result = def_result;
		}

		/*
		 * only one thread will call exit
		 */
		if (umem_nofail_exit_thr == thr_self())
			umem_panic("recursive UMEM_CALLBACK_EXIT()\n");

		(void) mutex_lock(&umem_nofail_exit_lock);
		umem_nofail_exit_thr = thr_self();
		exit(result & 0xFF);
		/*NOTREACHED*/
	}
	return (0);
}

static umem_log_header_t *
umem_log_init(size_t logsize)
{
	umem_log_header_t *lhp;
	int nchunks = 4 * umem_max_ncpus;
	size_t lhsize = offsetof(umem_log_header_t, lh_cpu[umem_max_ncpus]);
	int i;

	if (logsize == 0)
		return (NULL);

	/*
	 * Make sure that lhp->lh_cpu[] is nicely aligned
	 * to prevent false sharing of cache lines.
	 */
	lhsize = P2ROUNDUP(lhsize, UMEM_ALIGN);
	lhp = vmem_xalloc(umem_log_arena, lhsize, 64, P2NPHASE(lhsize, 64), 0,
	    NULL, NULL, VM_NOSLEEP);
	if (lhp == NULL)
		goto fail;

	bzero(lhp, lhsize);

	(void) mutex_init(&lhp->lh_lock, USYNC_THREAD, NULL);
	lhp->lh_nchunks = nchunks;
	lhp->lh_chunksize = P2ROUNDUP(logsize / nchunks, PAGESIZE);
	if (lhp->lh_chunksize == 0)
		lhp->lh_chunksize = PAGESIZE;

	lhp->lh_base = vmem_alloc(umem_log_arena,
	    lhp->lh_chunksize * nchunks, VM_NOSLEEP);
	if (lhp->lh_base == NULL)
		goto fail;

	lhp->lh_free = vmem_alloc(umem_log_arena,
	    nchunks * sizeof (int), VM_NOSLEEP);
	if (lhp->lh_free == NULL)
		goto fail;

	bzero(lhp->lh_base, lhp->lh_chunksize * nchunks);

	for (i = 0; i < umem_max_ncpus; i++) {
		umem_cpu_log_header_t *clhp = &lhp->lh_cpu[i];
		(void) mutex_init(&clhp->clh_lock, USYNC_THREAD, NULL);
		clhp->clh_chunk = i;
	}

	for (i = umem_max_ncpus; i < nchunks; i++)
		lhp->lh_free[i] = i;

	lhp->lh_head = umem_max_ncpus;
	lhp->lh_tail = 0;

	return (lhp);

fail:
	if (lhp != NULL) {
		if (lhp->lh_base != NULL)
			vmem_free(umem_log_arena, lhp->lh_base,
			    lhp->lh_chunksize * nchunks);

		vmem_xfree(umem_log_arena, lhp, lhsize);
	}
	return (NULL);
}

static void *
umem_log_enter(umem_log_header_t *lhp, void *data, size_t size)
{
	void *logspace;
	umem_cpu_log_header_t *clhp;

	if (lhp == NULL || umem_logging == 0)
		return (NULL);

	clhp = &lhp->lh_cpu[CPU(umem_cpu_mask)->cpu_number];

	(void) mutex_lock(&clhp->clh_lock);
	clhp->clh_hits++;
	if (size > clhp->clh_avail) {
		(void) mutex_lock(&lhp->lh_lock);
		lhp->lh_hits++;
		lhp->lh_free[lhp->lh_tail] = clhp->clh_chunk;
		lhp->lh_tail = (lhp->lh_tail + 1) % lhp->lh_nchunks;
		clhp->clh_chunk = lhp->lh_free[lhp->lh_head];
		lhp->lh_head = (lhp->lh_head + 1) % lhp->lh_nchunks;
		clhp->clh_current = lhp->lh_base +
		    clhp->clh_chunk * lhp->lh_chunksize;
		clhp->clh_avail = lhp->lh_chunksize;
		if (size > lhp->lh_chunksize)
			size = lhp->lh_chunksize;
		(void) mutex_unlock(&lhp->lh_lock);
	}
	logspace = clhp->clh_current;
	clhp->clh_current += size;
	clhp->clh_avail -= size;
	bcopy(data, logspace, size);
	(void) mutex_unlock(&clhp->clh_lock);
	return (logspace);
}

#define	UMEM_AUDIT(lp, cp, bcp)						\
{									\
	umem_bufctl_audit_t *_bcp = (umem_bufctl_audit_t *)(bcp);	\
	_bcp->bc_timestamp = gethrtime();				\
	_bcp->bc_thread = thr_self();					\
	_bcp->bc_depth = getpcstack(_bcp->bc_stack, umem_stack_depth,	\
	    (cp != NULL) && (cp->cache_flags & UMF_CHECKSIGNAL));	\
	_bcp->bc_lastlog = umem_log_enter((lp), _bcp,			\
	    UMEM_BUFCTL_AUDIT_SIZE);					\
}

static void
umem_log_event(umem_log_header_t *lp, umem_cache_t *cp,
    umem_slab_t *sp, void *addr)
{
	umem_bufctl_audit_t *bcp;
	UMEM_LOCAL_BUFCTL_AUDIT(&bcp);

	bzero(bcp, UMEM_BUFCTL_AUDIT_SIZE);
	bcp->bc_addr = addr;
	bcp->bc_slab = sp;
	bcp->bc_cache = cp;
	UMEM_AUDIT(lp, cp, bcp);
}

/*
 * Create a new slab for cache cp.
 */
static umem_slab_t *
umem_slab_create(umem_cache_t *cp, int umflag)
{
	size_t slabsize = cp->cache_slabsize;
	size_t chunksize = cp->cache_chunksize;
	int cache_flags = cp->cache_flags;
	size_t color, chunks;
	char *buf, *slab;
	umem_slab_t *sp;
	umem_bufctl_t *bcp;
	vmem_t *vmp = cp->cache_arena;

	color = cp->cache_color + cp->cache_align;
	if (color > cp->cache_maxcolor)
		color = cp->cache_mincolor;
	cp->cache_color = color;

	slab = vmem_alloc(vmp, slabsize, UMEM_VMFLAGS(umflag));

	if (slab == NULL)
		goto vmem_alloc_failure;

	ASSERT(P2PHASE((uintptr_t)slab, vmp->vm_quantum) == 0);

	if (!(cp->cache_cflags & UMC_NOTOUCH) &&
	    (cp->cache_flags & UMF_DEADBEEF))
		copy_pattern(UMEM_UNINITIALIZED_PATTERN, slab, slabsize);

	if (cache_flags & UMF_HASH) {
		if ((sp = _umem_cache_alloc(umem_slab_cache, umflag)) == NULL)
			goto slab_alloc_failure;
		chunks = (slabsize - color) / chunksize;
	} else {
		sp = UMEM_SLAB(cp, slab);
		chunks = (slabsize - sizeof (umem_slab_t) - color) / chunksize;
	}

	sp->slab_cache	= cp;
	sp->slab_head	= NULL;
	sp->slab_refcnt	= 0;
	sp->slab_base	= buf = slab + color;
	sp->slab_chunks	= chunks;

	ASSERT(chunks > 0);
	while (chunks-- != 0) {
		if (cache_flags & UMF_HASH) {
			bcp = _umem_cache_alloc(cp->cache_bufctl_cache, umflag);
			if (bcp == NULL)
				goto bufctl_alloc_failure;
			if (cache_flags & UMF_AUDIT) {
				umem_bufctl_audit_t *bcap =
				    (umem_bufctl_audit_t *)bcp;
				bzero(bcap, UMEM_BUFCTL_AUDIT_SIZE);
				bcap->bc_cache = cp;
			}
			bcp->bc_addr = buf;
			bcp->bc_slab = sp;
		} else {
			bcp = UMEM_BUFCTL(cp, buf);
		}
		if (cache_flags & UMF_BUFTAG) {
			umem_buftag_t *btp = UMEM_BUFTAG(cp, buf);
			btp->bt_redzone = UMEM_REDZONE_PATTERN;
			btp->bt_bufctl = bcp;
			btp->bt_bxstat = (intptr_t)bcp ^ UMEM_BUFTAG_FREE;
			if (cache_flags & UMF_DEADBEEF) {
				copy_pattern(UMEM_FREE_PATTERN, buf,
				    cp->cache_verify);
			}
		}
		bcp->bc_next = sp->slab_head;
		sp->slab_head = bcp;
		buf += chunksize;
	}

	umem_log_event(umem_slab_log, cp, sp, slab);

	return (sp);

bufctl_alloc_failure:

	while ((bcp = sp->slab_head) != NULL) {
		sp->slab_head = bcp->bc_next;
		_umem_cache_free(cp->cache_bufctl_cache, bcp);
	}
	_umem_cache_free(umem_slab_cache, sp);

slab_alloc_failure:

	vmem_free(vmp, slab, slabsize);

vmem_alloc_failure:

	umem_log_event(umem_failure_log, cp, NULL, NULL);
	atomic_add_64(&cp->cache_alloc_fail, 1);

	return (NULL);
}

/*
 * Destroy a slab.
 */
static void
umem_slab_destroy(umem_cache_t *cp, umem_slab_t *sp)
{
	vmem_t *vmp = cp->cache_arena;
	void *slab = (void *)P2ALIGN((uintptr_t)sp->slab_base, vmp->vm_quantum);

	if (cp->cache_flags & UMF_HASH) {
		umem_bufctl_t *bcp;
		while ((bcp = sp->slab_head) != NULL) {
			sp->slab_head = bcp->bc_next;
			_umem_cache_free(cp->cache_bufctl_cache, bcp);
		}
		_umem_cache_free(umem_slab_cache, sp);
	}
	vmem_free(vmp, slab, cp->cache_slabsize);
}

/*
 * Allocate a raw (unconstructed) buffer from cp's slab layer.
 */
static void *
umem_slab_alloc(umem_cache_t *cp, int umflag)
{
	umem_bufctl_t *bcp, **hash_bucket;
	umem_slab_t *sp;
	void *buf;

	(void) mutex_lock(&cp->cache_lock);
	cp->cache_slab_alloc++;
	sp = cp->cache_freelist;
	ASSERT(sp->slab_cache == cp);
	if (sp->slab_head == NULL) {
		/*
		 * The freelist is empty.  Create a new slab.
		 */
		(void) mutex_unlock(&cp->cache_lock);
		if (cp == &umem_null_cache)
			return (NULL);
		if ((sp = umem_slab_create(cp, umflag)) == NULL)
			return (NULL);
		(void) mutex_lock(&cp->cache_lock);
		cp->cache_slab_create++;
		if ((cp->cache_buftotal += sp->slab_chunks) > cp->cache_bufmax)
			cp->cache_bufmax = cp->cache_buftotal;
		sp->slab_next = cp->cache_freelist;
		sp->slab_prev = cp->cache_freelist->slab_prev;
		sp->slab_next->slab_prev = sp;
		sp->slab_prev->slab_next = sp;
		cp->cache_freelist = sp;
	}

	sp->slab_refcnt++;
	ASSERT(sp->slab_refcnt <= sp->slab_chunks);

	/*
	 * If we're taking the last buffer in the slab,
	 * remove the slab from the cache's freelist.
	 */
	bcp = sp->slab_head;
	if ((sp->slab_head = bcp->bc_next) == NULL) {
		cp->cache_freelist = sp->slab_next;
		ASSERT(sp->slab_refcnt == sp->slab_chunks);
	}

	if (cp->cache_flags & UMF_HASH) {
		/*
		 * Add buffer to allocated-address hash table.
		 */
		buf = bcp->bc_addr;
		hash_bucket = UMEM_HASH(cp, buf);
		bcp->bc_next = *hash_bucket;
		*hash_bucket = bcp;
		if ((cp->cache_flags & (UMF_AUDIT | UMF_BUFTAG)) == UMF_AUDIT) {
			UMEM_AUDIT(umem_transaction_log, cp, bcp);
		}
	} else {
		buf = UMEM_BUF(cp, bcp);
	}

	ASSERT(UMEM_SLAB_MEMBER(sp, buf));

	(void) mutex_unlock(&cp->cache_lock);

	return (buf);
}

/*
 * Free a raw (unconstructed) buffer to cp's slab layer.
 */
static void
umem_slab_free(umem_cache_t *cp, void *buf)
{
	umem_slab_t *sp;
	umem_bufctl_t *bcp, **prev_bcpp;

	ASSERT(buf != NULL);

	(void) mutex_lock(&cp->cache_lock);
	cp->cache_slab_free++;

	if (cp->cache_flags & UMF_HASH) {
		/*
		 * Look up buffer in allocated-address hash table.
		 */
		prev_bcpp = UMEM_HASH(cp, buf);
		while ((bcp = *prev_bcpp) != NULL) {
			if (bcp->bc_addr == buf) {
				*prev_bcpp = bcp->bc_next;
				sp = bcp->bc_slab;
				break;
			}
			cp->cache_lookup_depth++;
			prev_bcpp = &bcp->bc_next;
		}
	} else {
		bcp = UMEM_BUFCTL(cp, buf);
		sp = UMEM_SLAB(cp, buf);
	}

	if (bcp == NULL || sp->slab_cache != cp || !UMEM_SLAB_MEMBER(sp, buf)) {
		(void) mutex_unlock(&cp->cache_lock);
		umem_error(UMERR_BADADDR, cp, buf);
		return;
	}

	if ((cp->cache_flags & (UMF_AUDIT | UMF_BUFTAG)) == UMF_AUDIT) {
		if (cp->cache_flags & UMF_CONTENTS)
			((umem_bufctl_audit_t *)bcp)->bc_contents =
			    umem_log_enter(umem_content_log, buf,
			    cp->cache_contents);
		UMEM_AUDIT(umem_transaction_log, cp, bcp);
	}

	/*
	 * If this slab isn't currently on the freelist, put it there.
	 */
	if (sp->slab_head == NULL) {
		ASSERT(sp->slab_refcnt == sp->slab_chunks);
		ASSERT(cp->cache_freelist != sp);
		sp->slab_next->slab_prev = sp->slab_prev;
		sp->slab_prev->slab_next = sp->slab_next;
		sp->slab_next = cp->cache_freelist;
		sp->slab_prev = cp->cache_freelist->slab_prev;
		sp->slab_next->slab_prev = sp;
		sp->slab_prev->slab_next = sp;
		cp->cache_freelist = sp;
	}

	bcp->bc_next = sp->slab_head;
	sp->slab_head = bcp;

	ASSERT(sp->slab_refcnt >= 1);
	if (--sp->slab_refcnt == 0) {
		/*
		 * There are no outstanding allocations from this slab,
		 * so we can reclaim the memory.
		 */
		sp->slab_next->slab_prev = sp->slab_prev;
		sp->slab_prev->slab_next = sp->slab_next;
		if (sp == cp->cache_freelist)
			cp->cache_freelist = sp->slab_next;
		cp->cache_slab_destroy++;
		cp->cache_buftotal -= sp->slab_chunks;
		(void) mutex_unlock(&cp->cache_lock);
		umem_slab_destroy(cp, sp);
		return;
	}
	(void) mutex_unlock(&cp->cache_lock);
}

static int
umem_cache_alloc_debug(umem_cache_t *cp, void *buf, int umflag)
{
	umem_buftag_t *btp = UMEM_BUFTAG(cp, buf);
	umem_bufctl_audit_t *bcp = (umem_bufctl_audit_t *)btp->bt_bufctl;
	uint32_t mtbf;
	int flags_nfatal;

	if (btp->bt_bxstat != ((intptr_t)bcp ^ UMEM_BUFTAG_FREE)) {
		umem_error(UMERR_BADBUFTAG, cp, buf);
		return (-1);
	}

	btp->bt_bxstat = (intptr_t)bcp ^ UMEM_BUFTAG_ALLOC;

	if ((cp->cache_flags & UMF_HASH) && bcp->bc_addr != buf) {
		umem_error(UMERR_BADBUFCTL, cp, buf);
		return (-1);
	}

	btp->bt_redzone = UMEM_REDZONE_PATTERN;

	if (cp->cache_flags & UMF_DEADBEEF) {
		if (verify_and_copy_pattern(UMEM_FREE_PATTERN,
		    UMEM_UNINITIALIZED_PATTERN, buf, cp->cache_verify)) {
			umem_error(UMERR_MODIFIED, cp, buf);
			return (-1);
		}
	}

	if ((mtbf = umem_mtbf | cp->cache_mtbf) != 0 &&
	    gethrtime() % mtbf == 0 &&
	    (umflag & (UMEM_FATAL_FLAGS)) == 0) {
		umem_log_event(umem_failure_log, cp, NULL, NULL);
	} else {
		mtbf = 0;
	}

	/*
	 * We do not pass fatal flags on to the constructor.  This prevents
	 * leaking buffers in the event of a subordinate constructor failing.
	 */
	flags_nfatal = UMEM_DEFAULT;
	if (mtbf || (cp->cache_constructor != NULL &&
	    cp->cache_constructor(buf, cp->cache_private, flags_nfatal) != 0)) {
		atomic_add_64(&cp->cache_alloc_fail, 1);
		btp->bt_bxstat = (intptr_t)bcp ^ UMEM_BUFTAG_FREE;
		copy_pattern(UMEM_FREE_PATTERN, buf, cp->cache_verify);
		umem_slab_free(cp, buf);
		return (-1);
	}

	if (cp->cache_flags & UMF_AUDIT) {
		UMEM_AUDIT(umem_transaction_log, cp, bcp);
	}

	return (0);
}

static int
umem_cache_free_debug(umem_cache_t *cp, void *buf)
{
	umem_buftag_t *btp = UMEM_BUFTAG(cp, buf);
	umem_bufctl_audit_t *bcp = (umem_bufctl_audit_t *)btp->bt_bufctl;
	umem_slab_t *sp;

	if (btp->bt_bxstat != ((intptr_t)bcp ^ UMEM_BUFTAG_ALLOC)) {
		if (btp->bt_bxstat == ((intptr_t)bcp ^ UMEM_BUFTAG_FREE)) {
			umem_error(UMERR_DUPFREE, cp, buf);
			return (-1);
		}
		sp = umem_findslab(cp, buf);
		if (sp == NULL || sp->slab_cache != cp)
			umem_error(UMERR_BADADDR, cp, buf);
		else
			umem_error(UMERR_REDZONE, cp, buf);
		return (-1);
	}

	btp->bt_bxstat = (intptr_t)bcp ^ UMEM_BUFTAG_FREE;

	if ((cp->cache_flags & UMF_HASH) && bcp->bc_addr != buf) {
		umem_error(UMERR_BADBUFCTL, cp, buf);
		return (-1);
	}

	if (btp->bt_redzone != UMEM_REDZONE_PATTERN) {
		umem_error(UMERR_REDZONE, cp, buf);
		return (-1);
	}

	if (cp->cache_flags & UMF_AUDIT) {
		if (cp->cache_flags & UMF_CONTENTS)
			bcp->bc_contents = umem_log_enter(umem_content_log,
			    buf, cp->cache_contents);
		UMEM_AUDIT(umem_transaction_log, cp, bcp);
	}

	if (cp->cache_destructor != NULL)
		cp->cache_destructor(buf, cp->cache_private);

	if (cp->cache_flags & UMF_DEADBEEF)
		copy_pattern(UMEM_FREE_PATTERN, buf, cp->cache_verify);

	return (0);
}

/*
 * Free each object in magazine mp to cp's slab layer, and free mp itself.
 */
static void
umem_magazine_destroy(umem_cache_t *cp, umem_magazine_t *mp, int nrounds)
{
	int round;

	ASSERT(cp->cache_next == NULL || IN_UPDATE());

	for (round = 0; round < nrounds; round++) {
		void *buf = mp->mag_round[round];

		if ((cp->cache_flags & UMF_DEADBEEF) &&
		    verify_pattern(UMEM_FREE_PATTERN, buf,
		    cp->cache_verify) != NULL) {
			umem_error(UMERR_MODIFIED, cp, buf);
			continue;
		}

		if (!(cp->cache_flags & UMF_BUFTAG) &&
		    cp->cache_destructor != NULL)
			cp->cache_destructor(buf, cp->cache_private);

		umem_slab_free(cp, buf);
	}
	ASSERT(UMEM_MAGAZINE_VALID(cp, mp));
	_umem_cache_free(cp->cache_magtype->mt_cache, mp);
}

/*
 * Allocate a magazine from the depot.
 */
static umem_magazine_t *
umem_depot_alloc(umem_cache_t *cp, umem_maglist_t *mlp)
{
	umem_magazine_t *mp;

	/*
	 * If we can't get the depot lock without contention,
	 * update our contention count.  We use the depot
	 * contention rate to determine whether we need to
	 * increase the magazine size for better scalability.
	 */
	if (mutex_trylock(&cp->cache_depot_lock) != 0) {
		(void) mutex_lock(&cp->cache_depot_lock);
		cp->cache_depot_contention++;
	}

	if ((mp = mlp->ml_list) != NULL) {
		ASSERT(UMEM_MAGAZINE_VALID(cp, mp));
		mlp->ml_list = mp->mag_next;
		if (--mlp->ml_total < mlp->ml_min)
			mlp->ml_min = mlp->ml_total;
		mlp->ml_alloc++;
	}

	(void) mutex_unlock(&cp->cache_depot_lock);

	return (mp);
}

/*
 * Free a magazine to the depot.
 */
static void
umem_depot_free(umem_cache_t *cp, umem_maglist_t *mlp, umem_magazine_t *mp)
{
	(void) mutex_lock(&cp->cache_depot_lock);
	ASSERT(UMEM_MAGAZINE_VALID(cp, mp));
	mp->mag_next = mlp->ml_list;
	mlp->ml_list = mp;
	mlp->ml_total++;
	(void) mutex_unlock(&cp->cache_depot_lock);
}

/*
 * Update the working set statistics for cp's depot.
 */
static void
umem_depot_ws_update(umem_cache_t *cp)
{
	(void) mutex_lock(&cp->cache_depot_lock);
	cp->cache_full.ml_reaplimit = cp->cache_full.ml_min;
	cp->cache_full.ml_min = cp->cache_full.ml_total;
	cp->cache_empty.ml_reaplimit = cp->cache_empty.ml_min;
	cp->cache_empty.ml_min = cp->cache_empty.ml_total;
	(void) mutex_unlock(&cp->cache_depot_lock);
}

/*
 * Reap all magazines that have fallen out of the depot's working set.
 */
static void
umem_depot_ws_reap(umem_cache_t *cp)
{
	long reap;
	umem_magazine_t *mp;

	ASSERT(cp->cache_next == NULL || IN_REAP());

	reap = MIN(cp->cache_full.ml_reaplimit, cp->cache_full.ml_min);
	while (reap-- && (mp = umem_depot_alloc(cp, &cp->cache_full)) != NULL)
		umem_magazine_destroy(cp, mp, cp->cache_magtype->mt_magsize);

	reap = MIN(cp->cache_empty.ml_reaplimit, cp->cache_empty.ml_min);
	while (reap-- && (mp = umem_depot_alloc(cp, &cp->cache_empty)) != NULL)
		umem_magazine_destroy(cp, mp, 0);
}

static void
umem_cpu_reload(umem_cpu_cache_t *ccp, umem_magazine_t *mp, int rounds)
{
	ASSERT((ccp->cc_loaded == NULL && ccp->cc_rounds == -1) ||
	    (ccp->cc_loaded && ccp->cc_rounds + rounds == ccp->cc_magsize));
	ASSERT(ccp->cc_magsize > 0);

	ccp->cc_ploaded = ccp->cc_loaded;
	ccp->cc_prounds = ccp->cc_rounds;
	ccp->cc_loaded = mp;
	ccp->cc_rounds = rounds;
}

/*
 * Allocate a constructed object from cache cp.
 */
#pragma weak umem_cache_alloc = _umem_cache_alloc
void *
_umem_cache_alloc(umem_cache_t *cp, int umflag)
{
	umem_cpu_cache_t *ccp;
	umem_magazine_t *fmp;
	void *buf;
	int flags_nfatal;

retry:
	ccp = UMEM_CPU_CACHE(cp, CPU(cp->cache_cpu_mask));
	(void) mutex_lock(&ccp->cc_lock);
	for (;;) {
		/*
		 * If there's an object available in the current CPU's
		 * loaded magazine, just take it and return.
		 */
		if (ccp->cc_rounds > 0) {
			buf = ccp->cc_loaded->mag_round[--ccp->cc_rounds];
			ccp->cc_alloc++;
			(void) mutex_unlock(&ccp->cc_lock);
			if ((ccp->cc_flags & UMF_BUFTAG) &&
			    umem_cache_alloc_debug(cp, buf, umflag) == -1) {
				if (umem_alloc_retry(cp, umflag)) {
					goto retry;
				}

				return (NULL);
			}
			return (buf);
		}

		/*
		 * The loaded magazine is empty.  If the previously loaded
		 * magazine was full, exchange them and try again.
		 */
		if (ccp->cc_prounds > 0) {
			umem_cpu_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
			continue;
		}

		/*
		 * If the magazine layer is disabled, break out now.
		 */
		if (ccp->cc_magsize == 0)
			break;

		/*
		 * Try to get a full magazine from the depot.
		 */
		fmp = umem_depot_alloc(cp, &cp->cache_full);
		if (fmp != NULL) {
			if (ccp->cc_ploaded != NULL)
				umem_depot_free(cp, &cp->cache_empty,
				    ccp->cc_ploaded);
			umem_cpu_reload(ccp, fmp, ccp->cc_magsize);
			continue;
		}

		/*
		 * There are no full magazines in the depot,
		 * so fall through to the slab layer.
		 */
		break;
	}
	(void) mutex_unlock(&ccp->cc_lock);

	/*
	 * We couldn't allocate a constructed object from the magazine layer,
	 * so get a raw buffer from the slab layer and apply its constructor.
	 */
	buf = umem_slab_alloc(cp, umflag);

	if (buf == NULL) {
		if (cp == &umem_null_cache)
			return (NULL);
		if (umem_alloc_retry(cp, umflag)) {
			goto retry;
		}

		return (NULL);
	}

	if (cp->cache_flags & UMF_BUFTAG) {
		/*
		 * Let umem_cache_alloc_debug() apply the constructor for us.
		 */
		if (umem_cache_alloc_debug(cp, buf, umflag) == -1) {
			if (umem_alloc_retry(cp, umflag)) {
				goto retry;
			}
			return (NULL);
		}
		return (buf);
	}

	/*
	 * We do not pass fatal flags on to the constructor.  This prevents
	 * leaking buffers in the event of a subordinate constructor failing.
	 */
	flags_nfatal = UMEM_DEFAULT;
	if (cp->cache_constructor != NULL &&
	    cp->cache_constructor(buf, cp->cache_private, flags_nfatal) != 0) {
		atomic_add_64(&cp->cache_alloc_fail, 1);
		umem_slab_free(cp, buf);

		if (umem_alloc_retry(cp, umflag)) {
			goto retry;
		}
		return (NULL);
	}

	return (buf);
}

/*
 * Free a constructed object to cache cp.
 */
#pragma weak umem_cache_free = _umem_cache_free
void
_umem_cache_free(umem_cache_t *cp, void *buf)
{
	umem_cpu_cache_t *ccp = UMEM_CPU_CACHE(cp, CPU(cp->cache_cpu_mask));
	umem_magazine_t *emp;
	umem_magtype_t *mtp;

	if (ccp->cc_flags & UMF_BUFTAG)
		if (umem_cache_free_debug(cp, buf) == -1)
			return;

	(void) mutex_lock(&ccp->cc_lock);
	for (;;) {
		/*
		 * If there's a slot available in the current CPU's
		 * loaded magazine, just put the object there and return.
		 */
		if ((uint_t)ccp->cc_rounds < ccp->cc_magsize) {
			ccp->cc_loaded->mag_round[ccp->cc_rounds++] = buf;
			ccp->cc_free++;
			(void) mutex_unlock(&ccp->cc_lock);
			return;
		}

		/*
		 * The loaded magazine is full.  If the previously loaded
		 * magazine was empty, exchange them and try again.
		 */
		if (ccp->cc_prounds == 0) {
			umem_cpu_reload(ccp, ccp->cc_ploaded, ccp->cc_prounds);
			continue;
		}

		/*
		 * If the magazine layer is disabled, break out now.
		 */
		if (ccp->cc_magsize == 0)
			break;

		/*
		 * Try to get an empty magazine from the depot.
		 */
		emp = umem_depot_alloc(cp, &cp->cache_empty);
		if (emp != NULL) {
			if (ccp->cc_ploaded != NULL)
				umem_depot_free(cp, &cp->cache_full,
				    ccp->cc_ploaded);
			umem_cpu_reload(ccp, emp, 0);
			continue;
		}

		/*
		 * There are no empty magazines in the depot,
		 * so try to allocate a new one.  We must drop all locks
		 * across umem_cache_alloc() because lower layers may
		 * attempt to allocate from this cache.
		 */
		mtp = cp->cache_magtype;
		(void) mutex_unlock(&ccp->cc_lock);
		emp = _umem_cache_alloc(mtp->mt_cache, UMEM_DEFAULT);
		(void) mutex_lock(&ccp->cc_lock);

		if (emp != NULL) {
			/*
			 * We successfully allocated an empty magazine.
			 * However, we had to drop ccp->cc_lock to do it,
			 * so the cache's magazine size may have changed.
			 * If so, free the magazine and try again.
			 */
			if (ccp->cc_magsize != mtp->mt_magsize) {
				(void) mutex_unlock(&ccp->cc_lock);
				_umem_cache_free(mtp->mt_cache, emp);
				(void) mutex_lock(&ccp->cc_lock);
				continue;
			}

			/*
			 * We got a magazine of the right size.  Add it to
			 * the depot and try the whole dance again.
			 */
			umem_depot_free(cp, &cp->cache_empty, emp);
			continue;
		}

		/*
		 * We couldn't allocate an empty magazine,
		 * so fall through to the slab layer.
		 */
		break;
	}
	(void) mutex_unlock(&ccp->cc_lock);

	/*
	 * We couldn't free our constructed object to the magazine layer,
	 * so apply its destructor and free it to the slab layer.
	 * Note that if UMF_BUFTAG is in effect, umem_cache_free_debug()
	 * will have already applied the destructor.
	 */
	if (!(cp->cache_flags & UMF_BUFTAG) && cp->cache_destructor != NULL)
		cp->cache_destructor(buf, cp->cache_private);

	umem_slab_free(cp, buf);
}

#pragma weak umem_zalloc = _umem_zalloc
void *
_umem_zalloc(size_t size, int umflag)
{
	size_t index = (size - 1) >> UMEM_ALIGN_SHIFT;
	void *buf;

retry:
	if (index < UMEM_MAXBUF >> UMEM_ALIGN_SHIFT) {
		umem_cache_t *cp = umem_alloc_table[index];
		buf = _umem_cache_alloc(cp, umflag);
		if (buf != NULL) {
			if (cp->cache_flags & UMF_BUFTAG) {
				umem_buftag_t *btp = UMEM_BUFTAG(cp, buf);
				((uint8_t *)buf)[size] = UMEM_REDZONE_BYTE;
				((uint32_t *)btp)[1] = UMEM_SIZE_ENCODE(size);
			}
			bzero(buf, size);
		} else if (umem_alloc_retry(cp, umflag))
			goto retry;
	} else {
		buf = _umem_alloc(size, umflag);	/* handles failure */
		if (buf != NULL)
			bzero(buf, size);
	}
	return (buf);
}

#pragma weak umem_alloc = _umem_alloc
void *
_umem_alloc(size_t size, int umflag)
{
	size_t index = (size - 1) >> UMEM_ALIGN_SHIFT;
	void *buf;
umem_alloc_retry:
	if (index < UMEM_MAXBUF >> UMEM_ALIGN_SHIFT) {
		umem_cache_t *cp = umem_alloc_table[index];
		buf = _umem_cache_alloc(cp, umflag);
		if ((cp->cache_flags & UMF_BUFTAG) && buf != NULL) {
			umem_buftag_t *btp = UMEM_BUFTAG(cp, buf);
			((uint8_t *)buf)[size] = UMEM_REDZONE_BYTE;
			((uint32_t *)btp)[1] = UMEM_SIZE_ENCODE(size);
		}
		if (buf == NULL && umem_alloc_retry(cp, umflag))
			goto umem_alloc_retry;
		return (buf);
	}
	if (size == 0)
		return (NULL);
	if (umem_oversize_arena == NULL) {
		if (umem_init())
			ASSERT(umem_oversize_arena != NULL);
		else
			return (NULL);
	}
	buf = vmem_alloc(umem_oversize_arena, size, UMEM_VMFLAGS(umflag));
	if (buf == NULL) {
		umem_log_event(umem_failure_log, NULL, NULL, (void *)size);
		if (umem_alloc_retry(NULL, umflag))
			goto umem_alloc_retry;
	}
	return (buf);
}

#pragma weak umem_alloc_align = _umem_alloc_align
void *
_umem_alloc_align(size_t size, size_t align, int umflag)
{
	void *buf;

	if (size == 0)
		return (NULL);
	if ((align & (align - 1)) != 0)
		return (NULL);
	if (align < UMEM_ALIGN)
		align = UMEM_ALIGN;

umem_alloc_align_retry:
	if (umem_memalign_arena == NULL) {
		if (umem_init())
			ASSERT(umem_oversize_arena != NULL);
		else
			return (NULL);
	}
	buf = vmem_xalloc(umem_memalign_arena, size, align, 0, 0, NULL, NULL,
	    UMEM_VMFLAGS(umflag));
	if (buf == NULL) {
		umem_log_event(umem_failure_log, NULL, NULL, (void *)size);
		if (umem_alloc_retry(NULL, umflag))
			goto umem_alloc_align_retry;
	}
	return (buf);
}

#pragma weak umem_free = _umem_free
void
_umem_free(void *buf, size_t size)
{
	size_t index = (size - 1) >> UMEM_ALIGN_SHIFT;

	if (index < UMEM_MAXBUF >> UMEM_ALIGN_SHIFT) {
		umem_cache_t *cp = umem_alloc_table[index];
		if (cp->cache_flags & UMF_BUFTAG) {
			umem_buftag_t *btp = UMEM_BUFTAG(cp, buf);
			uint32_t *ip = (uint32_t *)btp;
			if (ip[1] != UMEM_SIZE_ENCODE(size)) {
				if (*(uint64_t *)buf == UMEM_FREE_PATTERN) {
					umem_error(UMERR_DUPFREE, cp, buf);
					return;
				}
				if (UMEM_SIZE_VALID(ip[1])) {
					ip[0] = UMEM_SIZE_ENCODE(size);
					umem_error(UMERR_BADSIZE, cp, buf);
				} else {
					umem_error(UMERR_REDZONE, cp, buf);
				}
				return;
			}
			if (((uint8_t *)buf)[size] != UMEM_REDZONE_BYTE) {
				umem_error(UMERR_REDZONE, cp, buf);
				return;
			}
			btp->bt_redzone = UMEM_REDZONE_PATTERN;
		}
		_umem_cache_free(cp, buf);
	} else {
		if (buf == NULL && size == 0)
			return;
		vmem_free(umem_oversize_arena, buf, size);
	}
}

#pragma weak umem_free_align = _umem_free_align
void
_umem_free_align(void *buf, size_t size)
{
	if (buf == NULL && size == 0)
		return;
	vmem_xfree(umem_memalign_arena, buf, size);
}

static void *
umem_firewall_va_alloc(vmem_t *vmp, size_t size, int vmflag)
{
	size_t realsize = size + vmp->vm_quantum;

	/*
	 * Annoying edge case: if 'size' is just shy of ULONG_MAX, adding
	 * vm_quantum will cause integer wraparound.  Check for this, and
	 * blow off the firewall page in this case.  Note that such a
	 * giant allocation (the entire address space) can never be
	 * satisfied, so it will either fail immediately (VM_NOSLEEP)
	 * or sleep forever (VM_SLEEP).  Thus, there is no need for a
	 * corresponding check in umem_firewall_va_free().
	 */
	if (realsize < size)
		realsize = size;

	return (vmem_alloc(vmp, realsize, vmflag | VM_NEXTFIT));
}

static void
umem_firewall_va_free(vmem_t *vmp, void *addr, size_t size)
{
	vmem_free(vmp, addr, size + vmp->vm_quantum);
}

/*
 * Reclaim all unused memory from a cache.
 */
static void
umem_cache_reap(umem_cache_t *cp)
{
	/*
	 * Ask the cache's owner to free some memory if possible.
	 * The idea is to handle things like the inode cache, which
	 * typically sits on a bunch of memory that it doesn't truly
	 * *need*.  Reclaim policy is entirely up to the owner; this
	 * callback is just an advisory plea for help.
	 */
	if (cp->cache_reclaim != NULL)
		cp->cache_reclaim(cp->cache_private);

	umem_depot_ws_reap(cp);
}

/*
 * Purge all magazines from a cache and set its magazine limit to zero.
 * All calls are serialized by being done by the update thread, except for
 * the final call from umem_cache_destroy().
 */
static void
umem_cache_magazine_purge(umem_cache_t *cp)
{
	umem_cpu_cache_t *ccp;
	umem_magazine_t *mp, *pmp;
	int rounds, prounds, cpu_seqid;

	ASSERT(cp->cache_next == NULL || IN_UPDATE());

	for (cpu_seqid = 0; cpu_seqid < umem_max_ncpus; cpu_seqid++) {
		ccp = &cp->cache_cpu[cpu_seqid];

		(void) mutex_lock(&ccp->cc_lock);
		mp = ccp->cc_loaded;
		pmp = ccp->cc_ploaded;
		rounds = ccp->cc_rounds;
		prounds = ccp->cc_prounds;
		ccp->cc_loaded = NULL;
		ccp->cc_ploaded = NULL;
		ccp->cc_rounds = -1;
		ccp->cc_prounds = -1;
		ccp->cc_magsize = 0;
		(void) mutex_unlock(&ccp->cc_lock);

		if (mp)
			umem_magazine_destroy(cp, mp, rounds);
		if (pmp)
			umem_magazine_destroy(cp, pmp, prounds);
	}

	/*
	 * Updating the working set statistics twice in a row has the
	 * effect of setting the working set size to zero, so everything
	 * is eligible for reaping.
	 */
	umem_depot_ws_update(cp);
	umem_depot_ws_update(cp);

	umem_depot_ws_reap(cp);
}

/*
 * Enable per-cpu magazines on a cache.
 */
static void
umem_cache_magazine_enable(umem_cache_t *cp)
{
	int cpu_seqid;

	if (cp->cache_flags & UMF_NOMAGAZINE)
		return;

	for (cpu_seqid = 0; cpu_seqid < umem_max_ncpus; cpu_seqid++) {
		umem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];
		(void) mutex_lock(&ccp->cc_lock);
		ccp->cc_magsize = cp->cache_magtype->mt_magsize;
		(void) mutex_unlock(&ccp->cc_lock);
	}

}

/*
 * Recompute a cache's magazine size.  The trade-off is that larger magazines
 * provide a higher transfer rate with the depot, while smaller magazines
 * reduce memory consumption.  Magazine resizing is an expensive operation;
 * it should not be done frequently.
 *
 * Changes to the magazine size are serialized by only having one thread
 * doing updates. (the update thread)
 *
 * Note: at present this only grows the magazine size.  It might be useful
 * to allow shrinkage too.
 */
static void
umem_cache_magazine_resize(umem_cache_t *cp)
{
	umem_magtype_t *mtp = cp->cache_magtype;

	ASSERT(IN_UPDATE());

	if (cp->cache_chunksize < mtp->mt_maxbuf) {
		umem_cache_magazine_purge(cp);
		(void) mutex_lock(&cp->cache_depot_lock);
		cp->cache_magtype = ++mtp;
		cp->cache_depot_contention_prev =
		    cp->cache_depot_contention + INT_MAX;
		(void) mutex_unlock(&cp->cache_depot_lock);
		umem_cache_magazine_enable(cp);
	}
}

/*
 * Rescale a cache's hash table, so that the table size is roughly the
 * cache size.  We want the average lookup time to be extremely small.
 */
static void
umem_hash_rescale(umem_cache_t *cp)
{
	umem_bufctl_t **old_table, **new_table, *bcp;
	size_t old_size, new_size, h;

	ASSERT(IN_UPDATE());

	new_size = MAX(UMEM_HASH_INITIAL,
	    1 << (highbit(3 * cp->cache_buftotal + 4) - 2));
	old_size = cp->cache_hash_mask + 1;

	if ((old_size >> 1) <= new_size && new_size <= (old_size << 1))
		return;

	new_table = vmem_alloc(umem_hash_arena, new_size * sizeof (void *),
	    VM_NOSLEEP);
	if (new_table == NULL)
		return;
	bzero(new_table, new_size * sizeof (void *));

	(void) mutex_lock(&cp->cache_lock);

	old_size = cp->cache_hash_mask + 1;
	old_table = cp->cache_hash_table;

	cp->cache_hash_mask = new_size - 1;
	cp->cache_hash_table = new_table;
	cp->cache_rescale++;

	for (h = 0; h < old_size; h++) {
		bcp = old_table[h];
		while (bcp != NULL) {
			void *addr = bcp->bc_addr;
			umem_bufctl_t *next_bcp = bcp->bc_next;
			umem_bufctl_t **hash_bucket = UMEM_HASH(cp, addr);
			bcp->bc_next = *hash_bucket;
			*hash_bucket = bcp;
			bcp = next_bcp;
		}
	}

	(void) mutex_unlock(&cp->cache_lock);

	vmem_free(umem_hash_arena, old_table, old_size * sizeof (void *));
}

/*
 * Perform periodic maintenance on a cache: hash rescaling,
 * depot working-set update, and magazine resizing.
 */
void
umem_cache_update(umem_cache_t *cp)
{
	int update_flags = 0;

	ASSERT(MUTEX_HELD(&umem_cache_lock));

	/*
	 * If the cache has become much larger or smaller than its hash table,
	 * fire off a request to rescale the hash table.
	 */
	(void) mutex_lock(&cp->cache_lock);

	if ((cp->cache_flags & UMF_HASH) &&
	    (cp->cache_buftotal > (cp->cache_hash_mask << 1) ||
	    (cp->cache_buftotal < (cp->cache_hash_mask >> 1) &&
	    cp->cache_hash_mask > UMEM_HASH_INITIAL)))
		update_flags |= UMU_HASH_RESCALE;

	(void) mutex_unlock(&cp->cache_lock);

	/*
	 * Update the depot working set statistics.
	 */
	umem_depot_ws_update(cp);

	/*
	 * If there's a lot of contention in the depot,
	 * increase the magazine size.
	 */
	(void) mutex_lock(&cp->cache_depot_lock);

	if (cp->cache_chunksize < cp->cache_magtype->mt_maxbuf &&
	    (int)(cp->cache_depot_contention -
	    cp->cache_depot_contention_prev) > umem_depot_contention)
		update_flags |= UMU_MAGAZINE_RESIZE;

	cp->cache_depot_contention_prev = cp->cache_depot_contention;

	(void) mutex_unlock(&cp->cache_depot_lock);

	if (update_flags)
		umem_add_update(cp, update_flags);
}

/*
 * Runs all pending updates.
 *
 * The update lock must be held on entrance, and will be held on exit.
 */
void
umem_process_updates(void)
{
	ASSERT(MUTEX_HELD(&umem_update_lock));

	while (umem_null_cache.cache_unext != &umem_null_cache) {
		int notify = 0;
		umem_cache_t *cp = umem_null_cache.cache_unext;

		cp->cache_uprev->cache_unext = cp->cache_unext;
		cp->cache_unext->cache_uprev = cp->cache_uprev;
		cp->cache_uprev = cp->cache_unext = NULL;

		ASSERT(!(cp->cache_uflags & UMU_ACTIVE));

		while (cp->cache_uflags) {
			int uflags = (cp->cache_uflags |= UMU_ACTIVE);
			(void) mutex_unlock(&umem_update_lock);

			/*
			 * The order here is important.  Each step can speed up
			 * later steps.
			 */

			if (uflags & UMU_HASH_RESCALE)
				umem_hash_rescale(cp);

			if (uflags & UMU_MAGAZINE_RESIZE)
				umem_cache_magazine_resize(cp);

			if (uflags & UMU_REAP)
				umem_cache_reap(cp);

			(void) mutex_lock(&umem_update_lock);

			/*
			 * check if anyone has requested notification
			 */
			if (cp->cache_uflags & UMU_NOTIFY) {
				uflags |= UMU_NOTIFY;
				notify = 1;
			}
			cp->cache_uflags &= ~uflags;
		}
		if (notify)
			(void) cond_broadcast(&umem_update_cv);
	}
}

#ifndef UMEM_STANDALONE
static void
umem_st_update(void)
{
	ASSERT(MUTEX_HELD(&umem_update_lock));
	ASSERT(umem_update_thr == 0 && umem_st_update_thr == 0);

	umem_st_update_thr = thr_self();

	(void) mutex_unlock(&umem_update_lock);

	vmem_update(NULL);
	umem_cache_applyall(umem_cache_update);

	(void) mutex_lock(&umem_update_lock);

	umem_process_updates();	/* does all of the requested work */

	umem_reap_next = gethrtime() +
	    (hrtime_t)umem_reap_interval * NANOSEC;

	umem_reaping = UMEM_REAP_DONE;

	umem_st_update_thr = 0;
}
#endif

/*
 * Reclaim all unused memory from all caches.  Called from vmem when memory
 * gets tight.  Must be called with no locks held.
 *
 * This just requests a reap on all caches, and notifies the update thread.
 */
void
umem_reap(void)
{
#ifndef UMEM_STANDALONE
	extern int __nthreads(void);
#endif

	if (umem_ready != UMEM_READY || umem_reaping != UMEM_REAP_DONE ||
	    gethrtime() < umem_reap_next)
		return;

	(void) mutex_lock(&umem_update_lock);

	if (umem_reaping != UMEM_REAP_DONE || gethrtime() < umem_reap_next) {
		(void) mutex_unlock(&umem_update_lock);
		return;
	}
	umem_reaping = UMEM_REAP_ADDING;	/* lock out other reaps */

	(void) mutex_unlock(&umem_update_lock);

	umem_updateall(UMU_REAP);

	(void) mutex_lock(&umem_update_lock);

	umem_reaping = UMEM_REAP_ACTIVE;

	/* Standalone is single-threaded */
#ifndef UMEM_STANDALONE
	if (umem_update_thr == 0) {
		/*
		 * The update thread does not exist.  If the process is
		 * multi-threaded, create it.  If not, or the creation fails,
		 * do the update processing inline.
		 */
		ASSERT(umem_st_update_thr == 0);

		if (__nthreads() <= 1 || umem_create_update_thread() == 0)
			umem_st_update();
	}

	(void) cond_broadcast(&umem_update_cv);	/* wake up the update thread */
#endif

	(void) mutex_unlock(&umem_update_lock);
}

umem_cache_t *
umem_cache_create(
	char *name,		/* descriptive name for this cache */
	size_t bufsize,		/* size of the objects it manages */
	size_t align,		/* required object alignment */
	umem_constructor_t *constructor, /* object constructor */
	umem_destructor_t *destructor, /* object destructor */
	umem_reclaim_t *reclaim, /* memory reclaim callback */
	void *private,		/* pass-thru arg for constr/destr/reclaim */
	vmem_t *vmp,		/* vmem source for slab allocation */
	int cflags)		/* cache creation flags */
{
	int cpu_seqid;
	size_t chunksize;
	umem_cache_t *cp, *cnext, *cprev;
	umem_magtype_t *mtp;
	size_t csize;
	size_t phase;

	/*
	 * The init thread is allowed to create internal and quantum caches.
	 *
	 * Other threads must wait until until initialization is complete.
	 */
	if (umem_init_thr == thr_self())
		ASSERT((cflags & (UMC_INTERNAL | UMC_QCACHE)) != 0);
	else {
		ASSERT(!(cflags & UMC_INTERNAL));
		if (umem_ready != UMEM_READY && umem_init() == 0) {
			errno = EAGAIN;
			return (NULL);
		}
	}

	csize = UMEM_CACHE_SIZE(umem_max_ncpus);
	phase = P2NPHASE(csize, UMEM_CPU_CACHE_SIZE);

	if (vmp == NULL)
		vmp = umem_default_arena;

	ASSERT(P2PHASE(phase, UMEM_ALIGN) == 0);

	/*
	 * Check that the arguments are reasonable
	 */
	if ((align & (align - 1)) != 0 || align > vmp->vm_quantum ||
	    ((cflags & UMC_NOHASH) && (cflags & UMC_NOTOUCH)) ||
	    name == NULL || bufsize == 0) {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * If align == 0, we set it to the minimum required alignment.
	 *
	 * If align < UMEM_ALIGN, we round it up to UMEM_ALIGN, unless
	 * UMC_NOTOUCH was passed.
	 */
	if (align == 0) {
		if (P2ROUNDUP(bufsize, UMEM_ALIGN) >= UMEM_SECOND_ALIGN)
			align = UMEM_SECOND_ALIGN;
		else
			align = UMEM_ALIGN;
	} else if (align < UMEM_ALIGN && (cflags & UMC_NOTOUCH) == 0)
		align = UMEM_ALIGN;


	/*
	 * Get a umem_cache structure.  We arrange that cp->cache_cpu[]
	 * is aligned on a UMEM_CPU_CACHE_SIZE boundary to prevent
	 * false sharing of per-CPU data.
	 */
	cp = vmem_xalloc(umem_cache_arena, csize, UMEM_CPU_CACHE_SIZE, phase,
	    0, NULL, NULL, VM_NOSLEEP);

	if (cp == NULL) {
		errno = EAGAIN;
		return (NULL);
	}

	bzero(cp, csize);

	(void) mutex_lock(&umem_flags_lock);
	if (umem_flags & UMF_RANDOMIZE)
		umem_flags = (((umem_flags | ~UMF_RANDOM) + 1) & UMF_RANDOM) |
		    UMF_RANDOMIZE;
	cp->cache_flags = umem_flags | (cflags & UMF_DEBUG);
	(void) mutex_unlock(&umem_flags_lock);

	/*
	 * Make sure all the various flags are reasonable.
	 */
	if (cp->cache_flags & UMF_LITE) {
		if (bufsize >= umem_lite_minsize &&
		    align <= umem_lite_maxalign &&
		    P2PHASE(bufsize, umem_lite_maxalign) != 0) {
			cp->cache_flags |= UMF_BUFTAG;
			cp->cache_flags &= ~(UMF_AUDIT | UMF_FIREWALL);
		} else {
			cp->cache_flags &= ~UMF_DEBUG;
		}
	}

	if ((cflags & UMC_QCACHE) && (cp->cache_flags & UMF_AUDIT))
		cp->cache_flags |= UMF_NOMAGAZINE;

	if (cflags & UMC_NODEBUG)
		cp->cache_flags &= ~UMF_DEBUG;

	if (cflags & UMC_NOTOUCH)
		cp->cache_flags &= ~UMF_TOUCH;

	if (cflags & UMC_NOHASH)
		cp->cache_flags &= ~(UMF_AUDIT | UMF_FIREWALL);

	if (cflags & UMC_NOMAGAZINE)
		cp->cache_flags |= UMF_NOMAGAZINE;

	if ((cp->cache_flags & UMF_AUDIT) && !(cflags & UMC_NOTOUCH))
		cp->cache_flags |= UMF_REDZONE;

	if ((cp->cache_flags & UMF_BUFTAG) && bufsize >= umem_minfirewall &&
	    !(cp->cache_flags & UMF_LITE) && !(cflags & UMC_NOHASH))
		cp->cache_flags |= UMF_FIREWALL;

	if (vmp != umem_default_arena || umem_firewall_arena == NULL)
		cp->cache_flags &= ~UMF_FIREWALL;

	if (cp->cache_flags & UMF_FIREWALL) {
		cp->cache_flags &= ~UMF_BUFTAG;
		cp->cache_flags |= UMF_NOMAGAZINE;
		ASSERT(vmp == umem_default_arena);
		vmp = umem_firewall_arena;
	}

	/*
	 * Set cache properties.
	 */
	(void) strncpy(cp->cache_name, name, sizeof (cp->cache_name) - 1);
	cp->cache_bufsize = bufsize;
	cp->cache_align = align;
	cp->cache_constructor = constructor;
	cp->cache_destructor = destructor;
	cp->cache_reclaim = reclaim;
	cp->cache_private = private;
	cp->cache_arena = vmp;
	cp->cache_cflags = cflags;
	cp->cache_cpu_mask = umem_cpu_mask;

	/*
	 * Determine the chunk size.
	 */
	chunksize = bufsize;

	if (align >= UMEM_ALIGN) {
		chunksize = P2ROUNDUP(chunksize, UMEM_ALIGN);
		cp->cache_bufctl = chunksize - UMEM_ALIGN;
	}

	if (cp->cache_flags & UMF_BUFTAG) {
		cp->cache_bufctl = chunksize;
		cp->cache_buftag = chunksize;
		chunksize += sizeof (umem_buftag_t);
	}

	if (cp->cache_flags & UMF_DEADBEEF) {
		cp->cache_verify = MIN(cp->cache_buftag, umem_maxverify);
		if (cp->cache_flags & UMF_LITE)
			cp->cache_verify = MIN(cp->cache_verify, UMEM_ALIGN);
	}

	cp->cache_contents = MIN(cp->cache_bufctl, umem_content_maxsave);

	cp->cache_chunksize = chunksize = P2ROUNDUP(chunksize, align);

	if (chunksize < bufsize) {
		errno = ENOMEM;
		goto fail;
	}

	/*
	 * Now that we know the chunk size, determine the optimal slab size.
	 */
	if (vmp == umem_firewall_arena) {
		cp->cache_slabsize = P2ROUNDUP(chunksize, vmp->vm_quantum);
		cp->cache_mincolor = cp->cache_slabsize - chunksize;
		cp->cache_maxcolor = cp->cache_mincolor;
		cp->cache_flags |= UMF_HASH;
		ASSERT(!(cp->cache_flags & UMF_BUFTAG));
	} else if ((cflags & UMC_NOHASH) || (!(cflags & UMC_NOTOUCH) &&
	    !(cp->cache_flags & UMF_AUDIT) &&
	    chunksize < vmp->vm_quantum / UMEM_VOID_FRACTION)) {
		cp->cache_slabsize = vmp->vm_quantum;
		cp->cache_mincolor = 0;
		cp->cache_maxcolor =
		    (cp->cache_slabsize - sizeof (umem_slab_t)) % chunksize;

		if (chunksize + sizeof (umem_slab_t) > cp->cache_slabsize) {
			errno = EINVAL;
			goto fail;
		}
		ASSERT(!(cp->cache_flags & UMF_AUDIT));
	} else {
		size_t chunks, waste, slabsize;
		size_t minwaste = LONG_MAX;
		size_t bestfit = SIZE_MAX;

		for (chunks = 1; chunks <= UMEM_VOID_FRACTION; chunks++) {
			slabsize = P2ROUNDUP(chunksize * chunks,
			    vmp->vm_quantum);
			/*
			 * check for overflow
			 */
			if ((slabsize / chunks) < chunksize) {
				errno = ENOMEM;
				goto fail;
			}
			chunks = slabsize / chunksize;
			waste = (slabsize % chunksize) / chunks;
			if (waste < minwaste) {
				minwaste = waste;
				bestfit = slabsize;
			}
		}
		if (cflags & UMC_QCACHE)
			bestfit = MAX(1 << highbit(3 * vmp->vm_qcache_max), 64);
		if (bestfit == SIZE_MAX) {
			errno = ENOMEM;
			goto fail;
		}
		cp->cache_slabsize = bestfit;
		cp->cache_mincolor = 0;
		cp->cache_maxcolor = bestfit % chunksize;
		cp->cache_flags |= UMF_HASH;
	}

	if (cp->cache_flags & UMF_HASH) {
		ASSERT(!(cflags & UMC_NOHASH));
		cp->cache_bufctl_cache = (cp->cache_flags & UMF_AUDIT) ?
		    umem_bufctl_audit_cache : umem_bufctl_cache;
	}

	if (cp->cache_maxcolor >= vmp->vm_quantum)
		cp->cache_maxcolor = vmp->vm_quantum - 1;

	cp->cache_color = cp->cache_mincolor;

	/*
	 * Initialize the rest of the slab layer.
	 */
	(void) mutex_init(&cp->cache_lock, USYNC_THREAD, NULL);

	cp->cache_freelist = &cp->cache_nullslab;
	cp->cache_nullslab.slab_cache = cp;
	cp->cache_nullslab.slab_refcnt = -1;
	cp->cache_nullslab.slab_next = &cp->cache_nullslab;
	cp->cache_nullslab.slab_prev = &cp->cache_nullslab;

	if (cp->cache_flags & UMF_HASH) {
		cp->cache_hash_table = vmem_alloc(umem_hash_arena,
		    UMEM_HASH_INITIAL * sizeof (void *), VM_NOSLEEP);
		if (cp->cache_hash_table == NULL) {
			errno = EAGAIN;
			goto fail_lock;
		}
		bzero(cp->cache_hash_table,
		    UMEM_HASH_INITIAL * sizeof (void *));
		cp->cache_hash_mask = UMEM_HASH_INITIAL - 1;
		cp->cache_hash_shift = highbit((ulong_t)chunksize) - 1;
	}

	/*
	 * Initialize the depot.
	 */
	(void) mutex_init(&cp->cache_depot_lock, USYNC_THREAD, NULL);

	for (mtp = umem_magtype; chunksize <= mtp->mt_minbuf; mtp++)
		continue;

	cp->cache_magtype = mtp;

	/*
	 * Initialize the CPU layer.
	 */
	for (cpu_seqid = 0; cpu_seqid < umem_max_ncpus; cpu_seqid++) {
		umem_cpu_cache_t *ccp = &cp->cache_cpu[cpu_seqid];
		(void) mutex_init(&ccp->cc_lock, USYNC_THREAD, NULL);
		ccp->cc_flags = cp->cache_flags;
		ccp->cc_rounds = -1;
		ccp->cc_prounds = -1;
	}

	/*
	 * Add the cache to the global list.  This makes it visible
	 * to umem_update(), so the cache must be ready for business.
	 */
	(void) mutex_lock(&umem_cache_lock);
	cp->cache_next = cnext = &umem_null_cache;
	cp->cache_prev = cprev = umem_null_cache.cache_prev;
	cnext->cache_prev = cp;
	cprev->cache_next = cp;
	(void) mutex_unlock(&umem_cache_lock);

	if (umem_ready == UMEM_READY)
		umem_cache_magazine_enable(cp);

	return (cp);

fail_lock:
	(void) mutex_destroy(&cp->cache_lock);
fail:
	vmem_xfree(umem_cache_arena, cp, csize);
	return (NULL);
}

void
umem_cache_destroy(umem_cache_t *cp)
{
	int cpu_seqid;

	/*
	 * Remove the cache from the global cache list so that no new updates
	 * will be scheduled on its behalf, wait for any pending tasks to
	 * complete, purge the cache, and then destroy it.
	 */
	(void) mutex_lock(&umem_cache_lock);
	cp->cache_prev->cache_next = cp->cache_next;
	cp->cache_next->cache_prev = cp->cache_prev;
	cp->cache_prev = cp->cache_next = NULL;
	(void) mutex_unlock(&umem_cache_lock);

	umem_remove_updates(cp);

	umem_cache_magazine_purge(cp);

	(void) mutex_lock(&cp->cache_lock);
	if (cp->cache_buftotal != 0)
		log_message("umem_cache_destroy: '%s' (%p) not empty\n",
		    cp->cache_name, (void *)cp);
	cp->cache_reclaim = NULL;
	/*
	 * The cache is now dead.  There should be no further activity.
	 * We enforce this by setting land mines in the constructor and
	 * destructor routines that induce a segmentation fault if invoked.
	 */
	cp->cache_constructor = (umem_constructor_t *)1;
	cp->cache_destructor = (umem_destructor_t *)2;
	(void) mutex_unlock(&cp->cache_lock);

	if (cp->cache_hash_table != NULL)
		vmem_free(umem_hash_arena, cp->cache_hash_table,
		    (cp->cache_hash_mask + 1) * sizeof (void *));

	for (cpu_seqid = 0; cpu_seqid < umem_max_ncpus; cpu_seqid++)
		(void) mutex_destroy(&cp->cache_cpu[cpu_seqid].cc_lock);

	(void) mutex_destroy(&cp->cache_depot_lock);
	(void) mutex_destroy(&cp->cache_lock);

	vmem_free(umem_cache_arena, cp, UMEM_CACHE_SIZE(umem_max_ncpus));
}

void
umem_alloc_sizes_clear(void)
{
	int i;

	umem_alloc_sizes[0] = UMEM_MAXBUF;
	for (i = 1; i < NUM_ALLOC_SIZES; i++)
		umem_alloc_sizes[i] = 0;
}

void
umem_alloc_sizes_add(size_t size_arg)
{
	int i, j;
	size_t size = size_arg;

	if (size == 0) {
		log_message("size_add: cannot add zero-sized cache\n",
		    size, UMEM_MAXBUF);
		return;
	}

	if (size > UMEM_MAXBUF) {
		log_message("size_add: %ld > %d, cannot add\n", size,
		    UMEM_MAXBUF);
		return;
	}

	if (umem_alloc_sizes[NUM_ALLOC_SIZES - 1] != 0) {
		log_message("size_add: no space in alloc_table for %d\n",
		    size);
		return;
	}

	if (P2PHASE(size, UMEM_ALIGN) != 0) {
		size = P2ROUNDUP(size, UMEM_ALIGN);
		log_message("size_add: rounding %d up to %d\n", size_arg,
		    size);
	}

	for (i = 0; i < NUM_ALLOC_SIZES; i++) {
		int cur = umem_alloc_sizes[i];
		if (cur == size) {
			log_message("size_add: %ld already in table\n",
			    size);
			return;
		}
		if (cur > size)
			break;
	}

	for (j = NUM_ALLOC_SIZES - 1; j > i; j--)
		umem_alloc_sizes[j] = umem_alloc_sizes[j-1];
	umem_alloc_sizes[i] = size;
}

void
umem_alloc_sizes_remove(size_t size)
{
	int i;

	if (size == UMEM_MAXBUF) {
		log_message("size_remove: cannot remove %ld\n", size);
		return;
	}

	for (i = 0; i < NUM_ALLOC_SIZES; i++) {
		int cur = umem_alloc_sizes[i];
		if (cur == size)
			break;
		else if (cur > size || cur == 0) {
			log_message("size_remove: %ld not found in table\n",
			    size);
			return;
		}
	}

	for (; i + 1 < NUM_ALLOC_SIZES; i++)
		umem_alloc_sizes[i] = umem_alloc_sizes[i+1];
	umem_alloc_sizes[i] = 0;
}

/*
 * We've been called back from libc to indicate that thread is terminating and
 * that it needs to release the per-thread memory that it has. We get to know
 * which entry in the thread's tmem array the allocation came from. Currently
 * this refers to first n umem_caches which makes this a pretty simple indexing
 * job.
 */
static void
umem_cache_tmem_cleanup(void *buf, int entry)
{
	size_t size;
	umem_cache_t *cp;

	size = umem_alloc_sizes[entry];
	cp = umem_alloc_table[(size - 1) >> UMEM_ALIGN_SHIFT];
	_umem_cache_free(cp, buf);
}

static int
umem_cache_init(void)
{
	int i;
	size_t size, max_size;
	umem_cache_t *cp;
	umem_magtype_t *mtp;
	char name[UMEM_CACHE_NAMELEN + 1];
	umem_cache_t *umem_alloc_caches[NUM_ALLOC_SIZES];

	for (i = 0; i < sizeof (umem_magtype) / sizeof (*mtp); i++) {
		mtp = &umem_magtype[i];
		(void) snprintf(name, sizeof (name), "umem_magazine_%d",
		    mtp->mt_magsize);
		mtp->mt_cache = umem_cache_create(name,
		    (mtp->mt_magsize + 1) * sizeof (void *),
		    mtp->mt_align, NULL, NULL, NULL, NULL,
		    umem_internal_arena, UMC_NOHASH | UMC_INTERNAL);
		if (mtp->mt_cache == NULL)
			return (0);
	}

	umem_slab_cache = umem_cache_create("umem_slab_cache",
	    sizeof (umem_slab_t), 0, NULL, NULL, NULL, NULL,
	    umem_internal_arena, UMC_NOHASH | UMC_INTERNAL);

	if (umem_slab_cache == NULL)
		return (0);

	umem_bufctl_cache = umem_cache_create("umem_bufctl_cache",
	    sizeof (umem_bufctl_t), 0, NULL, NULL, NULL, NULL,
	    umem_internal_arena, UMC_NOHASH | UMC_INTERNAL);

	if (umem_bufctl_cache == NULL)
		return (0);

	/*
	 * The size of the umem_bufctl_audit structure depends upon
	 * umem_stack_depth.   See umem_impl.h for details on the size
	 * restrictions.
	 */

	size = UMEM_BUFCTL_AUDIT_SIZE_DEPTH(umem_stack_depth);
	max_size = UMEM_BUFCTL_AUDIT_MAX_SIZE;

	if (size > max_size) {			/* too large -- truncate */
		int max_frames = UMEM_MAX_STACK_DEPTH;

		ASSERT(UMEM_BUFCTL_AUDIT_SIZE_DEPTH(max_frames) <= max_size);

		umem_stack_depth = max_frames;
		size = UMEM_BUFCTL_AUDIT_SIZE_DEPTH(umem_stack_depth);
	}

	umem_bufctl_audit_cache = umem_cache_create("umem_bufctl_audit_cache",
	    size, 0, NULL, NULL, NULL, NULL, umem_internal_arena,
	    UMC_NOHASH | UMC_INTERNAL);

	if (umem_bufctl_audit_cache == NULL)
		return (0);

	if (vmem_backend & VMEM_BACKEND_MMAP)
		umem_va_arena = vmem_create("umem_va",
		    NULL, 0, pagesize,
		    vmem_alloc, vmem_free, heap_arena,
		    8 * pagesize, VM_NOSLEEP);
	else
		umem_va_arena = heap_arena;

	if (umem_va_arena == NULL)
		return (0);

	umem_default_arena = vmem_create("umem_default",
	    NULL, 0, pagesize,
	    heap_alloc, heap_free, umem_va_arena,
	    0, VM_NOSLEEP);

	if (umem_default_arena == NULL)
		return (0);

	/*
	 * make sure the umem_alloc table initializer is correct
	 */
	i = sizeof (umem_alloc_table) / sizeof (*umem_alloc_table);
	ASSERT(umem_alloc_table[i - 1] == &umem_null_cache);

	/*
	 * Create the default caches to back umem_alloc()
	 */
	for (i = 0; i < NUM_ALLOC_SIZES; i++) {
		size_t cache_size = umem_alloc_sizes[i];
		size_t align = 0;

		if (cache_size == 0)
			break;		/* 0 terminates the list */

		/*
		 * If they allocate a multiple of the coherency granularity,
		 * they get a coherency-granularity-aligned address.
		 */
		if (IS_P2ALIGNED(cache_size, 64))
			align = 64;
		if (IS_P2ALIGNED(cache_size, pagesize))
			align = pagesize;
		(void) snprintf(name, sizeof (name), "umem_alloc_%lu",
		    (long)cache_size);

		cp = umem_cache_create(name, cache_size, align,
		    NULL, NULL, NULL, NULL, NULL, UMC_INTERNAL);
		if (cp == NULL)
			return (0);

		umem_alloc_caches[i] = cp;
	}

	umem_tmem_off = _tmem_get_base();
	_tmem_set_cleanup(umem_cache_tmem_cleanup);

#ifndef	UMEM_STANDALONE
	if (umem_genasm_supported && !(umem_flags & UMF_DEBUG) &&
	    !(umem_flags & UMF_NOMAGAZINE) &&
	    umem_ptc_size > 0) {
		umem_ptc_enabled = umem_genasm(umem_alloc_sizes,
		    umem_alloc_caches, i) ? 1 : 0;
	}
#else
	umem_ptc_enabled = 0;
#endif

	/*
	 * Initialization cannot fail at this point.  Make the caches
	 * visible to umem_alloc() and friends.
	 */
	size = UMEM_ALIGN;
	for (i = 0; i < NUM_ALLOC_SIZES; i++) {
		size_t cache_size = umem_alloc_sizes[i];

		if (cache_size == 0)
			break;		/* 0 terminates the list */

		cp = umem_alloc_caches[i];

		while (size <= cache_size) {
			umem_alloc_table[(size - 1) >> UMEM_ALIGN_SHIFT] = cp;
			size += UMEM_ALIGN;
		}
	}
	ASSERT(size - UMEM_ALIGN == UMEM_MAXBUF);
	return (1);
}

/*
 * umem_startup() is called early on, and must be called explicitly if we're
 * the standalone version.
 */
#ifdef UMEM_STANDALONE
void
#else
#pragma init(umem_startup)
static void
#endif
umem_startup(caddr_t start, size_t len, size_t pagesize, caddr_t minstack,
    caddr_t maxstack)
{
#ifdef UMEM_STANDALONE
	int idx;
	/* Standalone doesn't fork */
#else
	umem_forkhandler_init(); /* register the fork handler */
#endif

#ifdef __lint
	/* make lint happy */
	minstack = maxstack;
#endif

#ifdef UMEM_STANDALONE
	umem_ready = UMEM_READY_STARTUP;
	umem_init_env_ready = 0;

	umem_min_stack = minstack;
	umem_max_stack = maxstack;

	nofail_callback = NULL;
	umem_slab_cache = NULL;
	umem_bufctl_cache = NULL;
	umem_bufctl_audit_cache = NULL;
	heap_arena = NULL;
	heap_alloc = NULL;
	heap_free = NULL;
	umem_internal_arena = NULL;
	umem_cache_arena = NULL;
	umem_hash_arena = NULL;
	umem_log_arena = NULL;
	umem_oversize_arena = NULL;
	umem_va_arena = NULL;
	umem_default_arena = NULL;
	umem_firewall_va_arena = NULL;
	umem_firewall_arena = NULL;
	umem_memalign_arena = NULL;
	umem_transaction_log = NULL;
	umem_content_log = NULL;
	umem_failure_log = NULL;
	umem_slab_log = NULL;
	umem_cpu_mask = 0;

	umem_cpus = &umem_startup_cpu;
	umem_startup_cpu.cpu_cache_offset = UMEM_CACHE_SIZE(0);
	umem_startup_cpu.cpu_number = 0;

	bcopy(&umem_null_cache_template, &umem_null_cache,
	    sizeof (umem_cache_t));

	for (idx = 0; idx < (UMEM_MAXBUF >> UMEM_ALIGN_SHIFT); idx++)
		umem_alloc_table[idx] = &umem_null_cache;
#endif

	/*
	 * Perform initialization specific to the way we've been compiled
	 * (library or standalone)
	 */
	umem_type_init(start, len, pagesize);

	vmem_startup();
}

int
umem_init(void)
{
	size_t maxverify, minfirewall;
	size_t size;
	int idx;
	umem_cpu_t *new_cpus;

	vmem_t *memalign_arena, *oversize_arena;

	if (thr_self() != umem_init_thr) {
		/*
		 * The usual case -- non-recursive invocation of umem_init().
		 */
		(void) mutex_lock(&umem_init_lock);
		if (umem_ready != UMEM_READY_STARTUP) {
			/*
			 * someone else beat us to initializing umem.  Wait
			 * for them to complete, then return.
			 */
			while (umem_ready == UMEM_READY_INITING) {
				int cancel_state;

				(void) pthread_setcancelstate(
				    PTHREAD_CANCEL_DISABLE, &cancel_state);
				(void) cond_wait(&umem_init_cv,
				    &umem_init_lock);
				(void) pthread_setcancelstate(
				    cancel_state, NULL);
			}
			ASSERT(umem_ready == UMEM_READY ||
			    umem_ready == UMEM_READY_INIT_FAILED);
			(void) mutex_unlock(&umem_init_lock);
			return (umem_ready == UMEM_READY);
		}

		ASSERT(umem_ready == UMEM_READY_STARTUP);
		ASSERT(umem_init_env_ready == 0);

		umem_ready = UMEM_READY_INITING;
		umem_init_thr = thr_self();

		(void) mutex_unlock(&umem_init_lock);
		umem_setup_envvars(0);		/* can recurse -- see below */
		if (umem_init_env_ready) {
			/*
			 * initialization was completed already
			 */
			ASSERT(umem_ready == UMEM_READY ||
			    umem_ready == UMEM_READY_INIT_FAILED);
			ASSERT(umem_init_thr == 0);
			return (umem_ready == UMEM_READY);
		}
	} else if (!umem_init_env_ready) {
		/*
		 * The umem_setup_envvars() call (above) makes calls into
		 * the dynamic linker and directly into user-supplied code.
		 * Since we cannot know what that code will do, we could be
		 * recursively invoked (by, say, a malloc() call in the code
		 * itself, or in a (C++) _init section it causes to be fired).
		 *
		 * This code is where we end up if such recursion occurs.  We
		 * first clean up any partial results in the envvar code, then
		 * proceed to finish initialization processing in the recursive
		 * call.  The original call will notice this, and return
		 * immediately.
		 */
		umem_setup_envvars(1);		/* clean up any partial state */
	} else {
		umem_panic(
		    "recursive allocation while initializing umem\n");
	}
	umem_init_env_ready = 1;

	/*
	 * From this point until we finish, recursion into umem_init() will
	 * cause a umem_panic().
	 */
	maxverify = minfirewall = ULONG_MAX;

	/* LINTED constant condition */
	if (sizeof (umem_cpu_cache_t) != UMEM_CPU_CACHE_SIZE) {
		umem_panic("sizeof (umem_cpu_cache_t) = %d, should be %d\n",
		    sizeof (umem_cpu_cache_t), UMEM_CPU_CACHE_SIZE);
	}

	umem_max_ncpus = umem_get_max_ncpus();

	/*
	 * load tunables from environment
	 */
	umem_process_envvars();

	if (issetugid())
		umem_mtbf = 0;

	/*
	 * set up vmem
	 */
	if (!(umem_flags & UMF_AUDIT))
		vmem_no_debug();

	heap_arena = vmem_heap_arena(&heap_alloc, &heap_free);

	pagesize = heap_arena->vm_quantum;

	umem_internal_arena = vmem_create("umem_internal", NULL, 0, pagesize,
	    heap_alloc, heap_free, heap_arena, 0, VM_NOSLEEP);

	umem_default_arena = umem_internal_arena;

	if (umem_internal_arena == NULL)
		goto fail;

	umem_cache_arena = vmem_create("umem_cache", NULL, 0, UMEM_ALIGN,
	    vmem_alloc, vmem_free, umem_internal_arena, 0, VM_NOSLEEP);

	umem_hash_arena = vmem_create("umem_hash", NULL, 0, UMEM_ALIGN,
	    vmem_alloc, vmem_free, umem_internal_arena, 0, VM_NOSLEEP);

	umem_log_arena = vmem_create("umem_log", NULL, 0, UMEM_ALIGN,
	    heap_alloc, heap_free, heap_arena, 0, VM_NOSLEEP);

	umem_firewall_va_arena = vmem_create("umem_firewall_va",
	    NULL, 0, pagesize,
	    umem_firewall_va_alloc, umem_firewall_va_free, heap_arena,
	    0, VM_NOSLEEP);

	if (umem_cache_arena == NULL || umem_hash_arena == NULL ||
	    umem_log_arena == NULL || umem_firewall_va_arena == NULL)
		goto fail;

	umem_firewall_arena = vmem_create("umem_firewall", NULL, 0, pagesize,
	    heap_alloc, heap_free, umem_firewall_va_arena, 0,
	    VM_NOSLEEP);

	if (umem_firewall_arena == NULL)
		goto fail;

	oversize_arena = vmem_create("umem_oversize", NULL, 0, pagesize,
	    heap_alloc, heap_free, minfirewall < ULONG_MAX ?
	    umem_firewall_va_arena : heap_arena, 0, VM_NOSLEEP);

	memalign_arena = vmem_create("umem_memalign", NULL, 0, UMEM_ALIGN,
	    heap_alloc, heap_free, minfirewall < ULONG_MAX ?
	    umem_firewall_va_arena : heap_arena, 0, VM_NOSLEEP);

	if (oversize_arena == NULL || memalign_arena == NULL)
		goto fail;

	if (umem_max_ncpus > CPUHINT_MAX())
		umem_max_ncpus = CPUHINT_MAX();

	while ((umem_max_ncpus & (umem_max_ncpus - 1)) != 0)
		umem_max_ncpus++;

	if (umem_max_ncpus == 0)
		umem_max_ncpus = 1;

	size = umem_max_ncpus * sizeof (umem_cpu_t);
	new_cpus = vmem_alloc(umem_internal_arena, size, VM_NOSLEEP);
	if (new_cpus == NULL)
		goto fail;

	bzero(new_cpus, size);
	for (idx = 0; idx < umem_max_ncpus; idx++) {
		new_cpus[idx].cpu_number = idx;
		new_cpus[idx].cpu_cache_offset = UMEM_CACHE_SIZE(idx);
	}
	umem_cpus = new_cpus;
	umem_cpu_mask = (umem_max_ncpus - 1);

	if (umem_maxverify == 0)
		umem_maxverify = maxverify;

	if (umem_minfirewall == 0)
		umem_minfirewall = minfirewall;

	/*
	 * Set up updating and reaping
	 */
	umem_reap_next = gethrtime() + NANOSEC;

#ifndef UMEM_STANDALONE
	(void) gettimeofday(&umem_update_next, NULL);
#endif

	/*
	 * Set up logging -- failure here is okay, since it will just disable
	 * the logs
	 */
	if (umem_logging) {
		umem_transaction_log = umem_log_init(umem_transaction_log_size);
		umem_content_log = umem_log_init(umem_content_log_size);
		umem_failure_log = umem_log_init(umem_failure_log_size);
		umem_slab_log = umem_log_init(umem_slab_log_size);
	}

	/*
	 * Set up caches -- if successful, initialization cannot fail, since
	 * allocations from other threads can now succeed.
	 */
	if (umem_cache_init() == 0) {
		log_message("unable to create initial caches\n");
		goto fail;
	}
	umem_oversize_arena = oversize_arena;
	umem_memalign_arena = memalign_arena;

	umem_cache_applyall(umem_cache_magazine_enable);

	/*
	 * initialization done, ready to go
	 */
	(void) mutex_lock(&umem_init_lock);
	umem_ready = UMEM_READY;
	umem_init_thr = 0;
	(void) cond_broadcast(&umem_init_cv);
	(void) mutex_unlock(&umem_init_lock);
	return (1);

fail:
	log_message("umem initialization failed\n");

	(void) mutex_lock(&umem_init_lock);
	umem_ready = UMEM_READY_INIT_FAILED;
	umem_init_thr = 0;
	(void) cond_broadcast(&umem_init_cv);
	(void) mutex_unlock(&umem_init_lock);
	return (0);
}

void
umem_setmtbf(uint32_t mtbf)
{
	extern uint32_t vmem_mtbf;

	umem_mtbf = mtbf;
	vmem_mtbf = mtbf;
}
