extern crate crypto;
extern crate byteorder;

use self::crypto::sha3::Sha3;
use self::crypto::digest::Digest;


/// Stores one of the supported hash values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hash {
    None,
    Sha3([u8; 32])
}

fn half_byte_to_string(byte: u8) -> String {
    match byte {
        0 => "0",
        1 => "1",
        2 => "2",
        3 => "3",
        4 => "4",
        5 => "5",
        6 => "6",
        7 => "7",
        8 => "8",
        9 => "9",
        10 => "a",
        11 => "b",
        12 => "c",
        13 => "d",
        14 => "e",
        15 => "f",
        _ => "?"
    }.to_string()
}



fn byte_to_string(byte: u8) -> String {
    let mut res = String::new();
    res.push_str(&half_byte_to_string(byte / 16));
    res.push_str(&half_byte_to_string(byte % 16));
    res
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let mut res = String::new();
    for byte in bytes {
        res.push_str(&byte_to_string(*byte));
    }
    res
}


impl Hash {
    /// Get the hash as byte array.
    pub fn get_bytes(&self) -> Box<[u8]>{
        match self {
            &Hash::None => Box::new([0u8;0]),
            &Hash::Sha3(x) => Box::new(x)
        }
    }

    /// Returns the bytes of the hash as hex String.
    pub fn as_string(&self) -> String {
        bytes_to_string(&*self.get_bytes())
    }

    /// Returns a sha3-256 hash of the byte array.
    pub fn hash_bytes(bytes: &[u8]) -> Hash {
        let mut sha3 = Sha3::sha3_256();
        sha3.input(bytes);
        let mut res = [0u8; 32];
        sha3.result(&mut res);
        Hash::Sha3(res)
    }

    /// Generate a new hash by compining this hash with another one.
    pub fn hash_with(&self, o: Hash) -> Hash {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(&*self.get_bytes());
        vec.extend_from_slice(&*o.get_bytes());
        Hash::hash_bytes(vec.as_slice())
    }
}

/// Can generate a hash type which represents the current type.
pub trait Hashable {
    fn as_hash(&self) -> Hash;
}

impl Hashable for Hash {
    fn as_hash(&self) -> Hash {
        Hash::hash_bytes(&*self.get_bytes())
    }
}

/// Implement Hashable for any Debug
///
/// This macro generates a valid Hashable implementation
/// for any Debug type.  This can be handy since Debug can automatically
/// implemented by the compiler.
///
/// # Examples
/// ```
/// #[macro_use] extern crate tbd;
///
/// use tbd::hash::*;
///
/// #[derive(Debug)]
/// struct A {
///    x: u8
/// }
/// hashable_for_debug!(A);
///
/// fn main() {
///     let a = A {x: 42u8};
///     // Can generate a hash now
///     let hash: Hash = a.as_hash();
///     assert_eq!("dbd0820fbce3804d3edc974e8e31cdee04172029528ea50b25db44356911fac1",
///                   hash.as_string());
/// }
/// ```
#[macro_export]
macro_rules! hashable_for_debug {
    ($debug_type:path) => {
        impl Hashable for $debug_type {
            fn as_hash(&self) -> Hash {
                let string_value = format!("{:?}", self);
                Hash::hash_bytes(string_value.as_bytes())
            }
        }
    }
}



