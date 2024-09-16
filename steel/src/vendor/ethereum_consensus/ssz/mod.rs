mod byte_list;
mod byte_vector;

pub mod prelude {
    pub use super::{byte_list::ByteList, byte_vector::ByteVector};
    pub use ssz_rs::prelude::*;
}
