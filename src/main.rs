use {
    anyhow::Error as AnyhowError,
    env_logger::{init_from_env, Env},
    log::info,
};

pub(crate) mod util {
    use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

    #[derive(Clone)]
    pub struct DebugAs<F>(pub F)
    where
        F: Fn(&mut Formatter<'_>) -> FmtResult;

    impl<F> Debug for DebugAs<F>
    where
        F: Fn(&mut Formatter<'_>) -> FmtResult,
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            let Self(d) = self;
            d(f)
        }
    }

    #[derive(Clone)]
    pub struct DisplayAs<F>(pub F)
    where
        F: Fn(&mut Formatter<'_>) -> FmtResult;

    impl<F> Display for DisplayAs<F>
    where
        F: Fn(&mut Formatter<'_>) -> FmtResult,
    {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            let Self(d) = self;
            d(f)
        }
    }
}

mod devices {
    use {
        crate::util::{DebugAs, DisplayAs},
        log::error,
        std::{
            convert::TryFrom,
            fmt::{Debug, Display, Formatter, Result as FmtResult},
            io::Error as IoError,
            mem::{size_of, MaybeUninit},
            ptr::{null, null_mut},
        },
        wide_str::wide_str,
        winapi::{
            shared::{
                guiddef::GUID,
                minwindef::{DWORD, FALSE, TRUE},
                winerror::ERROR_NO_MORE_ITEMS,
            },
            um::{
                handleapi::INVALID_HANDLE_VALUE,
                setupapi::{
                    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
                    DIGCF_ALLCLASSES, DIGCF_PRESENT, HDEVINFO, SP_DEVINFO_DATA,
                },
            },
        },
    };

    #[derive(Debug)]
    pub struct DeviceInfoSet(pub HDEVINFO);

    impl Drop for DeviceInfoSet {
        fn drop(&mut self) {
            let Self(handle) = self;
            unsafe {
                match SetupDiDestroyDeviceInfoList(*handle) {
                    TRUE => (),
                    FALSE => error!("`DeviceInfoSet::drop` failed: {}", IoError::last_os_error()),
                    _ => unreachable!(),
                }
            }
        }
    }

    #[derive(Clone)]
    pub struct Guid(pub GUID);

    impl Debug for Guid {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            #[allow(non_snake_case)]
            let Self(GUID {
                Data1,
                Data2,
                Data3,
                Data4,
            }) = self;

            write!(
                f,
                "{{{:08X}-{:04X}-{:04X}-{}}}",
                Data1,
                Data2,
                Data3,
                DisplayAs(|f| { Data4.iter().try_for_each(|d| write!(f, "{:02X}", d)) }),
            )
        }
    }

    impl Display for Guid {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            <Self as Debug>::fmt(self, f)
        }
    }

    #[derive(Clone, Debug)]
    pub struct DeviceClassFilter<'a> {
        guid: Option<Guid>,
        enumerator: Option<PlugNPlayEnumeratorIdentifier<'a>>,
        flags: DWORD,
    }

    impl DeviceClassFilter<'static> {
        pub fn all() -> Self {
            Self {
                enumerator: None,
                guid: None,
                flags: DIGCF_ALLCLASSES,
            }
        }
    }

    impl<'a> DeviceClassFilter<'a> {
        pub fn enumerator<'b: 'a>(
            self,
            pnp_enum_id: Option<PlugNPlayEnumeratorIdentifier<'b>>,
        ) -> DeviceClassFilter<'b> {
            let Self {
                guid,
                enumerator: _,
                flags,
            } = self;

            DeviceClassFilter {
                enumerator: pnp_enum_id,
                guid,
                flags,
            }
        }

        pub fn present_devices(mut self, yes: bool) -> Self {
            if yes {
                self.flags |= DIGCF_PRESENT;
            } else {
                self.flags &= !DIGCF_PRESENT;
            }
            self
        }
    }

    #[derive(Clone, Debug)]
    pub enum PlugNPlayEnumeratorIdentifier<'a> {
        // TODO: Add easy handling of a `Guid` instance
        Pci,
        Usb,
        Custom(&'a [u16]),
    }

    impl PlugNPlayEnumeratorIdentifier<'_> {
        /// The `_guid_write_buf` is here for forwards compatibility for when the `Guid` case is
        /// added to this enum.
        fn as_pcwstr(&self, _guid_write_buf: &mut [u16; 101]) -> &[u16] {
            match self {
                Self::Pci => &wide_str!("PCI"),
                Self::Usb => &wide_str!("USB"),
                Self::Custom(buf) => buf,
            }
        }
    }

    impl DeviceInfoSet {
        /// TODO: Prove that this is a safe interface!
        pub unsafe fn get_devices_of_class(filter: DeviceClassFilter) -> Result<Self, IoError> {
            let DeviceClassFilter {
                guid,
                enumerator,
                flags,
            } = filter;
            let mut small_enum_name_buf = [0; 101];
            match SetupDiGetClassDevsW(
                guid.as_ref()
                    .map(|Guid(g)| -> *const GUID { &*g })
                    .unwrap_or(null()),
                enumerator
                    .as_ref()
                    .map(|e| -> *const u16 { e.as_pcwstr(&mut small_enum_name_buf).as_ptr() })
                    .unwrap_or(null()),
                null_mut(),
                flags,
            ) {
                INVALID_HANDLE_VALUE => Err(IoError::last_os_error()),
                handle => Ok(Self(handle)),
            }
        }

        pub fn iter(&self) -> DeviceInfoIter<'_> {
            DeviceInfoIter {
                set_handle: self,
                idx: 0,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct DeviceInfoIter<'a> {
        set_handle: &'a DeviceInfoSet,
        idx: u32,
    }

    #[derive(Clone)]
    pub struct DeviceInfo(SP_DEVINFO_DATA);

    impl Debug for DeviceInfo {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            #[allow(non_snake_case)]
            let Self(SP_DEVINFO_DATA {
                cbSize,
                ClassGuid,
                DevInst,
                Reserved,
            }) = self;

            f.debug_struct("DeviceInfo")
                .field("cbSize", cbSize)
                .field("ClassGuid", &Guid(ClassGuid.clone()))
                .field("DevInst", &DebugAs(|f| write!(f, "{:08X}", DevInst)))
                .field("Reserved", &DebugAs(|f| write!(f, "{:p}", Reserved)))
                .finish()
        }
    }

    impl DeviceInfoIter<'_> {
        /// TODO: Verify safety, at which point this can implement `Iterator`.
        pub unsafe fn next(&mut self) -> Option<Result<DeviceInfo, IoError>> {
            let Self {
                idx,
                set_handle: DeviceInfoSet(ref handle),
            } = self;
            let mut device_info = {
                let mut device_info = MaybeUninit::<SP_DEVINFO_DATA>::zeroed();
                (*device_info.as_mut_ptr()).cbSize =
                    u32::try_from(size_of::<SP_DEVINFO_DATA>()).unwrap();
                device_info
            };
            match SetupDiEnumDeviceInfo(*handle, *idx, device_info.as_mut_ptr()) {
                TRUE => {
                    *idx = idx.checked_add(1).unwrap();
                    Some(Ok(DeviceInfo(device_info.assume_init())))
                }
                FALSE => {
                    let e = IoError::last_os_error();
                    if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                        None
                    } else {
                        Some(Err(e))
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}
use devices::*;

fn main() -> Result<(), AnyhowError> {
    init_from_env(Env::new().default_filter_or("nzxt_interview=info"));

    info!("Checking out present USB devices...");
    let device_info_set = unsafe {
        DeviceInfoSet::get_devices_of_class(
            DeviceClassFilter::all()
                .enumerator(Some(PlugNPlayEnumeratorIdentifier::Usb))
                .present_devices(true),
        )?
    };

    let mut iter = device_info_set.iter();
    while let Some(device_info) = unsafe { iter.next() } {
        let device_info = device_info?;
        println!("{:?}", device_info);
    }
    info!("Device enumeration ended.");
    Ok(())
}
