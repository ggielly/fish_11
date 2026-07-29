use windows::Win32::Foundation::{FARPROC, HMODULE};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Validate a function pointer
///
/// Checks:
/// 1. Is not NULL
/// 2. Is within the address space of the given module (if module handle provided)
///
/// Note: Address-range validation is sufficient here because the pointers being validated
/// are resolved from the module's export table via `GetProcAddress`. A pointer that falls
/// within the module's address range was either exported by that module or points to data
/// within it : both are valid targets for hooking. We cannot meaningfully verify that the
/// pointer points to executable code without disassembling the instruction stream, which
/// would add complexity without security benefit in this context (the functions are loaded
/// from known, trusted OpenSSL libraries).
pub unsafe fn validate_function_pointer(
    ptr: FARPROC,
    module: Option<HMODULE>,
) -> Result<(), String> {
    if ptr.is_none() {
        return Err("Function pointer is NULL".to_string());
    }

    if let Some(h_module) = module {
        let mut mod_info = MODULEINFO::default();
        let result = GetModuleInformation(
            GetCurrentProcess(),
            h_module,
            &mut mod_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        );

        if result.is_err() {
            return Err("Failed to retrieve module information for validation".to_string());
        }

        let base_addr = mod_info.lpBaseOfDll as usize;
        let end_addr = base_addr + mod_info.SizeOfImage as usize;

        // Transmute FARPROC (Option<fn>) to address
        // SAFETY: ptr is guaranteed non-null by the is_none() check above.
        // FARPROC is repr(Option<fn()>); transmute extracts the raw address for range comparison.
        let func_addr: usize = std::mem::transmute(ptr.unwrap());

        if func_addr < base_addr || func_addr >= end_addr {
            return Err(format!(
                "Function pointer {:p} is outside module address range [{:x} - {:x}]",
                func_addr as *const (), base_addr, end_addr
            ));
        }
    }

    Ok(())
}

/// Transmute a validated `FARPROC` into a concrete function type `T`.
///
/// The caller must provide the concrete type `T` at the call site.
/// The actual ABI/signature correctness is the caller's responsibility :
/// this function only guarantees non-null and in-module-range.
///
/// # Safety
/// Caller must ensure:
/// - `T` is a function pointer type whose ABI and signature match the symbol
/// - `module` matches the DLL where the function resides
pub unsafe fn unsafe_transmute_validated<T: Copy>(
    ptr: FARPROC,
    module: Option<HMODULE>,
) -> Result<T, String> {
    // 1. Validate the pointer
    validate_function_pointer(ptr, module)?;

    // 2. Transmute : the caller chose T, so we trust it matches the symbol.
    //    FARPROC is repr(Option<fn()>); unwrap is safe because validate
    //    already rejected None.
    //    `transmute_copy` is required here because `T` is generic and `transmute`
    //    cannot be used with unsized or generic types. `T: Copy` ensures the
    //    source (fn pointer, pointer-sized) can be safely bit-copied into T.
    let raw = ptr.unwrap();
    let func: T = std::mem::transmute_copy(&raw);
    Ok(func)
}
