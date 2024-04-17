use wp1_recursion_derive::DslVariable;

use super::{Ext, Felt, Var};
use crate::ir::{Array, Builder, Config, MemIndex, MemVariable, Ptr, Variable};

#[derive(DslVariable, Debug, Clone)]
pub struct FriFoldInput<C: Config> {
    pub z: Ext<C::F, C::EF>,
    pub alpha: Ext<C::F, C::EF>,
    pub x: Felt<C::F>,
    pub log_height: Var<C::N>,
    pub mat_opening: Array<C, Ext<C::F, C::EF>>,
    pub ps_at_z: Array<C, Ext<C::F, C::EF>>,
    pub alpha_pow: Array<C, Ext<C::F, C::EF>>,
    pub ro: Array<C, Ext<C::F, C::EF>>,
}
