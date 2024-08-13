// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implements a simple framework for scoping TSS values.
// Based on chrome's base/memory/scoped_ptr_malloc implementation.
//
// Example usage:
//  ScopedTssContext context_handle;
//  TSS_RESULT result;
//  if (!OpenAndConnectTpm(context_handle.ptr(), &result))
//    ...
//  ScopedTssKey srk(context_handle);
//  if (!LoadSrk(context_handle, srk_handle.ptr(), &result))
//    ...
//
// See the bottom of this file for common typedefs.
#ifndef TROUSERS_SCOPED_TSS_TYPE_H_
#define TROUSERS_SCOPED_TSS_TYPE_H_

#ifdef __cplusplus

#include <trousers/tss.h>
#include <trousers/trousers.h>  // NOLINT(build/include_alpha) - needs tss.h
#include <vector>

#include <base/logging.h>
#include <base/notreached.h>

namespace trousers {

class ScopedTssContextRelease {
 public:
  inline void operator()(TSS_HCONTEXT unused, TSS_HCONTEXT context) const {
    // Usually, only |context| is used, but if the ScopedTssContext is
    // used slightly differently, it may end up with a context in |unused|.
    // For now, treat that as a bug.
    if (unused) {
      NOTREACHED_IN_MIGRATION()
          << "Unexpected data in the unused argument - a misuse of "
             "ScopedTssContext. Please report to crbug.com/821825";
      return;
    }
    if (context)
      Tspi_Context_Close(context);
  }
};

class ScopedTssMemoryRelease {
 public:
  inline void operator()(TSS_HCONTEXT context, BYTE* memory) const {
    if (!memory)
      return;
    if (!context) {
      NOTREACHED_IN_MIGRATION()
          << "Leaking Trousers memory due to null context. Please "
             "report to crbug.com/821825";
      return;
    }
    Tspi_Context_FreeMemory(context, memory);
  }
};

class ScopedTssObjectRelease {
 public:
  inline void operator()(TSS_HCONTEXT context, TSS_HOBJECT handle) const {
    if (!handle)
      return;
    if (!context) {
      NOTREACHED_IN_MIGRATION()
          << "Leaking Trousers handle due to null context. Please "
             "report to crbug.com/821825";
      return;
    }
    Tspi_Context_CloseObject(context, handle);
  }
};

// Provide a basic scoped container for TSS managed objects.
template<class TssType, class ReleaseProc = ScopedTssObjectRelease>
class ScopedTssType {
 public:
  explicit ScopedTssType(TSS_HCONTEXT c = 0, TssType t = 0) :
     context_(c),
     type_(t) {}

  ScopedTssType(const ScopedTssType &) = delete;
  ScopedTssType &operator=(const ScopedTssType &) = delete;

  explicit ScopedTssType(ScopedTssType &&other)
      : context_(other.context_), type_(other.type_) {
    other.context_ = 0;
    other.type_ = 0;
  }

  ScopedTssType &operator=(ScopedTssType &&other) {
    release_(context_, type_);
    context_ = other.context_;
    type_ = other.type_;
    other.context_ = 0;
    other.type_ = 0;
    return *this;
  }

  virtual ~ScopedTssType() {
    release_(context_, type_);
  }

  // Provide a means to access the value without conversion.
  virtual TssType value() {
    return type_;
  }

  // Allow direct referencing of the wrapped value.
  virtual TssType* ptr() {
    return &type_;
  }

  // Returns the assigned context.
  virtual TSS_HCONTEXT context() {
    return context_;
  }

  virtual TssType release() __attribute__((warn_unused_result)) {
    TssType tmp = type_;
    type_ = 0;
    context_ = 0;
    return tmp;
  }

  virtual void reset(TSS_HCONTEXT c = 0, TssType t = 0) {
    release_(context_, type_);
    context_ = c;
    type_ = t;
  }

 private:
  ReleaseProc release_;
  TSS_HCONTEXT context_;
  TssType type_;
};

// Wrap ScopedTssObject to allow implicit conversion only when safe.
template<class TssType = TSS_HOBJECT,
         class ReleaseProc = ScopedTssObjectRelease>
class ScopedTssObject : public ScopedTssType<TssType, ReleaseProc> {
 public:
  // Enforce a context for scoped objects.
  explicit ScopedTssObject(TSS_HCONTEXT c, TssType t = 0)
    : ScopedTssType<TssType, ReleaseProc>(c, t) {}

  // Allow implicit conversion to anything TSS_HOBJECT based.
  virtual operator TssType() {
    return this->value();
  }
};

class ScopedTssContext
   : public ScopedTssObject<TSS_HCONTEXT, ScopedTssContextRelease> {
 public:
  // Enforce a context for scoped objects.
  explicit ScopedTssContext(TSS_HCONTEXT t = 0)
    : ScopedTssObject<TSS_HCONTEXT,ScopedTssContextRelease>(0, t) {}
};

// Provide clear-cut typedefs for the common cases.
typedef ScopedTssType<BYTE*, ScopedTssMemoryRelease> ScopedTssMemory;

typedef ScopedTssObject<TSS_HKEY> ScopedTssKey;
typedef ScopedTssObject<TSS_HPOLICY> ScopedTssPolicy;
typedef ScopedTssObject<TSS_HPCRS> ScopedTssPcrs;
typedef ScopedTssObject<TSS_HNVSTORE> ScopedTssNvStore;

}  // namespace trousers

#endif  // __cplusplus
#endif  // TROUSERS_SCOPED_TSS_TYPE_H_
