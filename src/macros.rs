// !!!! CAUTION !!!!
// !---------------!
// !  DANGER ZONE  !
// !---------------!
// ! HIGH RISK  OF !
// ! BRAIN DAMAGE  !
// !---------------!
// !   KEEP OUT    !
// !!!!!!!!!!!!!!!!!

macro_rules! impl_arch_operands {
    ($(#[$attr:meta])* $vis:vis enum $name:ident {
        $($op:ident = $n:expr),+ $(,)?
    }) => (
        #[repr(u64)]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        $(#[$attr])*
        $vis enum $name {
            $($op = $n),+
        }

        impl From<$name> for u64 {
            fn from(value: $name) -> u64 {
                value as u64
            }
        }

        impl $name {
            fn from_u64(value: u64) -> Option<Self> {
                Some(match value {
                    $($n => Self::$op,)+
                    _ => return None,
                })
            }
        }
    );
}
pub(super) use impl_arch_operands;

macro_rules! impl_opcode_check {
    ($($mask:expr, $opcode:expr, $name:ident;)*) => ($(
        #[inline]
        fn $name(&self) -> bool {
            self.raw() & $mask == $opcode
        }
    )*);
}
pub(super) use impl_opcode_check;

macro_rules! impl_field {
    ($($name:ident =
        $pos:expr,
        $len:expr,
        $ret:tt $(: $cast:ty)?
        $(,$map:expr $(, $arg:ident: $arg_ty:ty)*)?
    ;)*) => ($(
        impl_field!(impl $name, $ret $(: $cast)?, $pos, $len $(,$map $(, $arg: $arg_ty)*)?);
    )*);
    (impl
         $name:ident,
         bool $(: $cast:ty)?,
         $pos:expr,
         $len:expr
         $(,$map:expr $(, $arg:ident: $arg_ty:ty)*)?
    ) => (
        fn $name(&self $($(, $arg: $arg_ty)*)?) -> bool {
            let ret = zextract(self.raw(), $pos, $len) $(as $cast)?;
            $(let ret = $map(ret $(, $arg)?);)?
            ret != 0
        }
    );
    (impl
        $name:ident,
        $ret:ty,
        $pos:expr,
        $len:expr
        $(,$map:expr $(, $arg:ident: $arg_ty:ty)*)?
    ) => (
        fn $name(&self $($(, $arg: $arg_ty)*)?) -> $ret {
            let ret = zextract(self.raw(), $pos, $len);
            $(let ret = $map(ret $(, $arg)?);)?
            ret as $ret
        }
    );
    (impl
        $name:ident,
        $ret:ty: $cast:ty,
        $pos:expr,
        $len:expr
        $(,$map:expr $(, $arg:ident: $arg_ty:ty)*)?
    ) => (
        fn $name(&self $($(, $arg: $arg_ty)*)?) -> $ret {
            let ret = zextract(self.raw(), $pos, $len) as $cast;
            $(let ret = $map(ret $(, $arg)?);)?
            ret
        }
    );
}
pub(super) use impl_field;
