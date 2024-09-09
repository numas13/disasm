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
