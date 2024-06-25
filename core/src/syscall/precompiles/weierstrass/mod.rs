mod weierstrass_add;
mod weierstrass_double;

use crate::air::Polynomial;
use sphinx_derive::AlignedBorrow;
pub use weierstrass_add::*;
pub use weierstrass_double::*;

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct PointCols<T> {
    pub x: Polynomial<T>,
    pub y: Polynomial<T>,
}
