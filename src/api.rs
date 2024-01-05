use std::{
    ffi::CStr,
    os::unix::{
        net::UnixStream,
        prelude::{FromRawFd, RawFd},
    },
};

use crate::jni::{
    strings::JNIStr,
    sys::{jint, JNINativeMethod},
    JNIEnv,
};
use crate::libc::{dev_t, ino_t};

use crate::binding::{RawApiTable, StateFlags, ZygiskOption};

/// A handle to API functions provided by the Zygisk runtime. Use this to call utility functions
/// or to interface with Zygisk.
///
/// ## Safety
///
/// All API functions will stop working after `post[XXX]Specialize` as Zygisk will be unloaded
/// from the specialized process afterwards. Therefore, it is required that you stop using any
/// instances of this object after that point.
///
/// In order to prevent the handle from unexpected use, the handle has a lifetime parameter `'a`
/// that defaults to the lifetime of each function call in [ZygiskModule](crate::ZygiskModule).
/// To retain this handle across function calls in some rare cases, call the unsafe function
/// [Self::retain()].
pub struct ZygiskApi<'a> {
    inner: &'a RawApiTable,
}

impl<'a> ZygiskApi<'a> {
    /// Connect to a root companion process and get a Unix domain socket for IPC.
    ///
    /// This API only works in the `pre[XXX]Specialize` functions due to SELinux restrictions.
    ///
    /// The `pre[XXX]Specialize` functions run with the same privilege of zygote.
    /// If you would like to do some operations with superuser permissions, register a handler
    /// function that would be called in the root process with `zygisk_companion!(handler_func)`.
    /// Another good use case for a companion process is that if you want to share some resources
    /// across multiple processes, hold the resources in the companion process and pass it over.
    ///
    /// The root companion process is ABI aware; that is, when calling this function from a 32-bit
    /// process, you will be connected to a 32-bit companion process, and vice versa for 64-bit.
    ///
    /// Returns a [UnixStream] that is connected to the socket passed to your module's companion
    /// request handler. Returns `Err` if the connection attempt failed.
    pub fn connect_companion(&self) -> Result<UnixStream, crate::ZygiskError> {
        let fd = self
            .inner
            .connect_companion
            .map(|func| func(self.inner.this))
            .unwrap_or(-1);

        if fd >= 0 {
            Ok(unsafe { UnixStream::from_raw_fd(fd) })
        } else {
            Err(crate::ZygiskError)
        }
    }

    /// Get the file descriptor of the root folder of the current module.
    ///
    /// This API only works in the `pre[XXX]Specialize` functions.
    /// Accessing the directory returned is only possible in the `pre[XXX]Specialize` functions
    /// or in the root companion process (assuming that you sent the fd over the socket).
    /// Both restrictions are due to SELinux and UID.
    ///
    /// Returns -1 if errors occurred.
    pub fn get_module_dir(&self) -> RawFd {
        self.inner
            .get_module_dir
            .map(|func| func(self.inner.this))
            .unwrap_or(-1)
    }

    /// Set various options for your module.
    /// Please note that this function accepts one single option at a time.
    /// Check [ZygiskOption] for the full list of options available.
    pub fn set_option(&self, option: ZygiskOption) {
        if let Some(func) = self.inner.set_option {
            func(self.inner.this, option);
        }
    }

    /// Get information about the current process.
    /// Returns bitwise-or'd [StateFlags] values.
    pub fn get_flags(&self) -> StateFlags {
        self.inner
            .get_flags
            .map(|func| func(self.inner.this))
            .map(|raw| StateFlags::from_bits(raw).expect("unsupported flag returned by Magisk"))
            .unwrap_or(StateFlags::empty())
    }

    /// Exempt the provided file descriptor from being automatically closed.
    ///
    /// This API only make sense in [`pre_app_specialize`](crate::ZygiskModule::pre_app_specialize);\
    /// calling this method in any other situation is either a no-op (returns true) or an
    /// error (returns false).
    ///
    /// When false is returned, the provided file descriptor will eventually be closed by zygote.
    pub fn exempt_fd(&self, fd: RawFd) {
        if let Some(func) = self.inner.exempt_fd {
            func(fd);
        }
    }

    /// Hook JNI native methods for a Java class.
    ///
    /// This looks up all registered JNI native methods and replaces them with your own functions.
    /// The original function pointer will be saved in each `JNINativeMethod`'s `fnPtr` (thus the
    /// `&mut` requirement in the function signature).
    ///
    /// If no matching class, method name, or signature is found, that specific `JNINativeMethod.fnPtr`
    /// will be set to [std::ptr::null_mut()].
    ///
    /// ## Safety
    ///
    /// This function is unsafe, since a badly designed hook or misuse of raw pointers may lead to
    /// memory unsafety.
    pub unsafe fn hook_jni_native_methods(
        &self,
        env: JNIEnv,
        class_name: &JNIStr,
        methods: &mut [JNINativeMethod],
    ) {
        if let Some(func) = self.inner.hook_jni_native_methods {
            func(
                env.get_native_interface(),
                class_name.as_ptr(),
                methods.as_mut_ptr(),
                methods.len() as jint,
            );
        }
    }

    /// Hook functions in the PLT (Procedure Linkage Table) of ELFs loaded in memory.
    ///
    /// Parsing `/proc/[PID]/maps` will give you the memory map of a process. As an example:
    ///
    /// ```text
    ///       <address>       <perms>  <offset>   <dev>  <inode>           <pathname>
    /// 56b4346000-56b4347000  r-xp    00002000   fe:00    235       /system/bin/app_process64
    /// ```
    /// (More details: https://man7.org/linux/man-pages/man5/proc.5.html)
    ///
    /// The `dev` and `inode` pair uniquely identifies a file being mapped into memory.
    /// For matching ELFs loaded in memory, replace function `symbol` with `new_func`.
    /// If `old_func` is not [`None`], the original function pointer will be saved to `old_func`.
    ///
    /// ## Safety
    ///
    /// This function is unsafe, since a badly designed hook or misuse of raw pointers may lead to
    /// memory unsafety.
    pub unsafe fn plt_hook_register(
        &self,
        device: dev_t,
        inode: ino_t,
        symbol: &CStr,
        new_func: *mut (),
        old_func: Option<&mut *mut ()>,
    ) {
        if let Some(func) = self.inner.plt_hook_register {
            func(
                device,
                inode,
                symbol.as_ptr(),
                new_func,
                old_func
                    .map(|r| r as *mut *mut ())
                    .unwrap_or(std::ptr::null_mut()),
            );
        }
    }

    /// Commit all the hooks that was previously registered.
    ///
    /// Returns `false` if any error occurs.
    pub fn plt_hook_commit(&self) -> bool {
        self.inner
            .plt_hook_commit
            .map(|func| func())
            .unwrap_or(false)
    }
}

impl<'a> ZygiskApi<'a> {
    pub(crate) fn from_raw(inner: &'a RawApiTable) -> ZygiskApi {
        ZygiskApi { inner }
    }

    /// Retain the API handle to be used across function calls to [ZygiskModule](crate::ZygiskModule)
    /// by giving it a `'static` lifetime.
    ///
    /// ## Safety
    ///
    /// This is an unsafe function, since the API functions will be unloaded after `post[XXX]Specialize`,
    /// and calling any of the API functions after that point will result in undefined behavior.
    /// This function merely exists for working around Rust's limitations.
    ///
    /// This function should rarely be necessary, since an API handle will be passed to
    /// every function in [ZygiskModule](crate::ZygiskModule) as an argument.
    pub unsafe fn retain(self) -> ZygiskApi<'static> {
        // We only need to extend the lifetime, so a simple transmute is sufficient for this case.
        std::mem::transmute(self)
    }
}
