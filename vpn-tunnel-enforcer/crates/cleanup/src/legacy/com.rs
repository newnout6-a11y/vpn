//! COM on the current thread for the scope of a guard (winnet keeps its own helper private).
use std::marker::PhantomData;

use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, COINIT_MULTITHREADED, CoInitializeEx,
    CoUninitialize,
};

/// Joined apartment; dropping it undoes a successful initialisation on the same thread.
pub(crate) struct Com {
    uninit: bool,
    /// `CoUninitialize` must run on the initialising thread.
    _thread: PhantomData<*const ()>,
}

impl Com {
    /// MTA for the in-proc automation objects (firewall policy), STA for INetCfg, which
    /// documents apartment-threaded use. A thread already in the other apartment keeps it.
    pub(crate) fn enter(sta: bool) -> Self {
        let flags = match sta {
            true => COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
            false => COINIT_MULTITHREADED,
        };
        // SAFETY: per-thread initialisation, balanced in `drop` when it succeeded (S_FALSE
        // included); RPC_E_CHANGED_MODE leaves the apartment untouched and is not balanced.
        let hr = unsafe { CoInitializeEx(None, flags) };
        Self {
            uninit: hr.is_ok(),
            _thread: PhantomData,
        }
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        if self.uninit {
            // SAFETY: balances the successful CoInitializeEx of `enter` on this thread.
            unsafe { CoUninitialize() };
        }
    }
}
