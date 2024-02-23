//===-- sanitizer_stoptheworld_netbsd_libcdep.cpp -------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// See sanitizer_stoptheworld.h for details.
// This implementation was inspired by Markus Gutschke's linuxthreads.cc.
//
// This is a NetBSD variation of Linux stoptheworld implementation
// See sanitizer_stoptheworld_linux_libcdep.cpp for code comments.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_FREEBSD

#include "sanitizer_stoptheworld.h"

#include <errno.h>
#include <sys/types.h> // for pid_t
#include <sys/ptrace.h> // for PTRACE_* definitions
#include <sys/wait.h>
#include <link.h>
#include <unistd.h> // for rfork

#include "sanitizer_common.h"
#include "sanitizer_flags.h"
#include "sanitizer_libc.h"
#include "sanitizer_linux.h"

// This module works by forking a tracer process that shares the address space
// with the caller process, which subsequently attaches to the caller process
// with ptrace and suspends all threads within. PTRACE_GETREGS can then be used
// to obtain their register state. The callback supplied to StopTheWorld() is
// run in the tracer process while the threads are suspended.

namespace __sanitizer {

class SuspendedThreadsListFreeBSD : public SuspendedThreadsList {
 public:
  SuspendedThreadsListFreeBSD(pid_t ppid) : parent_pid_(ppid), stopped_(false)
    { lwp_ids_.reserve(1024); }
  ~SuspendedThreadsListFreeBSD();
  bool Suspend() { dl_iterate_phdr(Callback, this); return stopped_; }
  void SuspendLocked();
  static int Callback(struct dl_phdr_info *, size_t, void *);

  tid_t GetThreadID(uptr index) const;
  uptr ThreadCount() const;
  bool ContainsTid(tid_t thread_id) const;

  PtraceRegistersStatus GetRegistersAndSP(uptr index, InternalMmapVector<uptr> *buffer,
                                          uptr *sp) const;
  uptr RegisterCount() const;

 private:
  InternalMmapVector<lwpid_t> lwp_ids_;
  pid_t parent_pid_;
  bool stopped_;
};

// Structure for passing arguments into the tracer thread.
struct TracerThreadArgument {
  StopTheWorldCallback callback;
  void *callback_argument;
  uptr parent_pid;
};

// Size of alternative stack for signal handlers in the tracer thread.
static const int kHandlerStackSize = 8192;

// This function will be run as a rfork'd process.
static int TracerThread(void* argument) {
  TracerThreadArgument *tracer_thread_argument =
      (TracerThreadArgument *)argument;

  pid_t ppid = tracer_thread_argument->parent_pid;
  SuspendedThreadsListFreeBSD suspended_threads_list(ppid);

  if (suspended_threads_list.Suspend())
    tracer_thread_argument->callback(suspended_threads_list,
                                     tracer_thread_argument->callback_argument);

  return 0;
}

class ScopedStackSpaceWithGuard {
 public:
  explicit ScopedStackSpaceWithGuard(uptr stack_size) {
    stack_size_ = stack_size;
    guard_size_ = GetPageSizeCached();
    guard_start_ = (uptr)MmapOrDie(stack_size_ + guard_size_,
                                   "ScopedStackWithGuard");
    CHECK(MprotectNoAccess((uptr)guard_start_, guard_size_));
  }
  ~ScopedStackSpaceWithGuard() {
    UnmapOrDie((void *)guard_start_, stack_size_ + guard_size_);
  }
  void *Bottom() const {
    return (void *)(guard_start_ + stack_size_ + guard_size_);
  }

 private:
  uptr stack_size_;
  uptr guard_size_;
  uptr guard_start_;
};

void StopTheWorld(StopTheWorldCallback callback, void *argument) {
  // Prepare the arguments for TracerThread.
  struct TracerThreadArgument tracer_thread_argument;
  tracer_thread_argument.callback = callback;
  tracer_thread_argument.callback_argument = argument;
  tracer_thread_argument.parent_pid = internal_getpid();
#if defined(__amd64__) || defined(__i386__)
  const uptr kTracerStackSize = 2 * 1024 * 1024;
  ScopedStackSpaceWithGuard tracer_stack(kTracerStackSize);

  uptr tracer_pid = rfork_thread(RFPROC | RFMEM, tracer_stack.Bottom(),
                                 TracerThread, &tracer_thread_argument);
#else
  uptr tracer_pid = rfork(RFPROC | RFMEM);
  if (tracer_pid == 0)
    _exit(TracerThread(&tracer_thread_argument));
#endif

  int local_errno = 0;
  if (internal_iserror(tracer_pid, &local_errno)) {
    VReport(1, "Failed spawning a tracer thread (errno %d).\n", local_errno);
  } else {
    for (;;) {
      int status;
      uptr waitpid_status = internal_waitpid(tracer_pid, &status, 0);
      if (internal_iserror(waitpid_status, &local_errno)) {
        if (local_errno == EINTR)
          continue;
        VReport(1, "Waiting on the tracer thread failed (errno %d).\n",
                local_errno);
        break;
      }
      if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
        internal__exit(WEXITSTATUS(status));
      if (WIFEXITED(status))
        break;
    }
  }
}

// Platform-specific methods from SuspendedThreadsList.
#if defined(__amd64__)
#define	PTRACE_REG_SP(regs)	((regs)->r_rsp)
#elif defined(__i386__)
#define PTRACE_REG_SP(regs)	((regs)->r_esp)
#elif defined(__aarch64__) || defined(__riscv)
#define PTRACE_REG_SP(regs)	((regs)->sp)
#elif defined(__arm__)
#define PTRACE_REG_SP(regs)	((regs)->r_sp)
#elif defined(__powerpc__)
#define PTRACE_REG_SP(regs)	((regs)->fixreg[1])
#else
#error "Unsupported architecture"
#endif

SuspendedThreadsListFreeBSD::~SuspendedThreadsListFreeBSD() {
  stoptheworld_tracer_pid = 0;
  stoptheworld_tracer_ppid = 0;

  if (!stopped_)
    return;

  int local_errno = 0;
  if (internal_iserror(internal_ptrace(PT_DETACH, parent_pid_, 0, 0),
                       &local_errno)) {
    VReport(1, "Failed to detach the parent.\n");
  }
}

void SuspendedThreadsListFreeBSD::SuspendLocked() {
  stoptheworld_tracer_pid = internal_getpid();
  stoptheworld_tracer_ppid = parent_pid_;

  int local_errno = 0;
  if (internal_iserror(internal_ptrace(PT_ATTACH, parent_pid_, 0, 0),
                       &local_errno)) {
    VReport(1, "Failed to attach the parent.\n");
    return;
  }

  // wait for the parent process to stop
  for (;;) {
    int status;
    if (internal_iserror(internal_waitpid(parent_pid_, &status, 0),
                         &local_errno)) {
      if (local_errno == EINTR)
        continue;
      VReport(1, "Failed to stop the parent (errno %d).\n", local_errno);
      return;
    }
    if (WIFSTOPPED(status))
      break;
  }

  uptr lwp_count = internal_ptrace(PT_GETNUMLWPS, parent_pid_, 0, 0);
  if (internal_iserror(lwp_count, &local_errno)) {
      VReport(1, "Failed to get LWP count (errno %d).\n", local_errno);
      return;
  }

  lwp_ids_.resize(lwp_count);
  if (internal_iserror(internal_ptrace(PT_GETLWPLIST, parent_pid_,
                       lwp_ids_.data(), lwp_ids_.size()),
                       &local_errno)) {
      lwp_ids_.clear();
      VReport(1, "Failed to get LWP list (errno %d).\n", local_errno);
      return;
  }

  stopped_ = true;
}

int SuspendedThreadsListFreeBSD::Callback(struct dl_phdr_info *info,
                                          size_t size, void *data)
{
  SuspendedThreadsListFreeBSD* self = (SuspendedThreadsListFreeBSD*)data;
  self->SuspendLocked();
  return 1;
}

tid_t SuspendedThreadsListFreeBSD::GetThreadID(uptr index) const {
  CHECK_LT(index, lwp_ids_.size());
  return lwp_ids_[index];
}

uptr SuspendedThreadsListFreeBSD::ThreadCount() const {
  return lwp_ids_.size();
}

bool SuspendedThreadsListFreeBSD::ContainsTid(tid_t thread_id) const {
  lwpid_t lwp_id = (lwpid_t)thread_id;
  for (uptr i = 0; i < lwp_ids_.size(); i++) {
    if (lwp_ids_[i] == lwp_id) return true;
  }
  return false;
}

PtraceRegistersStatus SuspendedThreadsListFreeBSD::GetRegistersAndSP(
    uptr index, InternalMmapVector<uptr> *buffer, uptr *sp) const {
  int tid = GetThreadID(index);
  struct reg regs;
  int pterrno;
  bool isErr = internal_iserror(internal_ptrace(PT_GETREGS, tid,
                                (caddr_t)&regs, 0), &pterrno);
  if (isErr) {
    VReport(1, "Could not get registers from thread %d (errno %d).\n", tid,
            pterrno);
    // ESRCH means that the given thread is not suspended or already dead.
    // Therefore it's unsafe to inspect its data (e.g. walk through stack) and
    // we should notify caller about this.
    return pterrno == ESRCH ? REGISTERS_UNAVAILABLE_FATAL
                            : REGISTERS_UNAVAILABLE;
  }

  *sp = PTRACE_REG_SP(&regs);
  buffer->resize(RoundUpTo(sizeof(regs), sizeof(uptr)) / sizeof(uptr));
  internal_memcpy(buffer->data(), &regs, sizeof(regs));
  return REGISTERS_AVAILABLE;
}

uptr SuspendedThreadsListFreeBSD::RegisterCount() const {
  return sizeof(struct reg) / sizeof(uptr);
}
} // namespace __sanitizer

#endif
