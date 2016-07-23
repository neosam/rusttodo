extern crate crypto;
extern crate byteorder;

use std::io::{Read, Write};
use self::crypto::sha3::Sha3;
use self::crypto::digest::Digest;
use self::byteorder::{BigEndian, ByteOrder};
use std::io;

use hash::*;

pub fn write_u8(i: u8, write: &mut Write) -> Result<usize, io::Error> {
    let mut bytes = [0u8; 1];
    bytes[0] = i;
    write.write(&bytes)
}

pub fn read_u8(read: &mut Read) -> Result<u8, io::Error> {
    let mut bytes = [0u8; 1];
    try!(read.read(&mut bytes));
    Ok(bytes[0])
}



pub fn write_u32(i: u32, write: &mut Write) -> Result<usize, io::Error> {
    let mut bytes = [0u8; 4];
    BigEndian::write_u32(&mut bytes, i);
    write.write(&bytes)
}

pub fn read_u32(read: &mut Read) -> Result<u32, io::Error> {
    let mut bytes = [0u8; 4];
    try!(read.read(&mut bytes));
    Ok(BigEndian::read_u32(&bytes))
}

pub fn write_f32(f: f32, write: &mut Write) -> Result<usize, io::Error> {
    let mut bytes = [0u8; 4];
    BigEndian::write_f32(&mut bytes, f);
    write.write(&bytes)
}

pub fn read_f32(read: &mut Read) -> Result<f32, io::Error> {
    let mut bytes = [0u8; 4];
    try!(read.read(&mut bytes));
    Ok(BigEndian::read_f32(&bytes))
}


/// Write itself to any write trait.
///
/// It also implements the Hashable type by default and generates
/// a sha3 representation of its output.
pub trait Writable {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error>;
    fn writable_to_hash(&self) -> Hash {
        let mut write: Vec<u8> = Vec::new();
        self.write_to(&mut write)
            .expect("Writing to a vec should not cause any issues");
        let data = write.as_slice();
        let mut hasher = Sha3::sha3_256();
        let mut hash_bytes = [0u8; 32];
        hasher.input(data);
        hasher.result(&mut hash_bytes);
        let hash = Hash::Sha3(hash_bytes);
        hash
    }
}


/// Implement Hashable for any Writable
///
/// This macro generates a valid Hashable implementation
/// for any Writable type.
///
/// # Examples
/// ```
/// #[macro_use] extern crate tbd;
///
/// use tbd::hash::*;
/// use tbd::io::*;
/// use std::io::Write;
/// use std::io;
///
/// struct A {
///    x: u8
/// }
///
/// impl Writable for A {
///     fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
///         let byte = [self.x];
///         try!(write.write(&byte));
///         Ok(1)
///     }
/// }
///
/// hashable_for_writable!(A);
///
/// fn main() {
///     let a = A {x: 42u8};
///     // Can generate a hash now
///     let hash: Hash = a.as_hash();
///     assert_eq!("82283b4b030589a7aa0ca28b8e933ac0bd89738a0df509806c864366deec31d7",
///                   hash.as_string());
/// }
/// ```
#[macro_export]
macro_rules! hashable_for_writable {
    ($writable_type:path) => {
        impl Hashable for $writable_type {
            fn as_hash(&self) -> Hash {
                self.writable_to_hash()
            }
        }
    }
}


pub fn usize_to_u32_bytes(x: usize) -> [u8; 4] {
    let as_u32 = x as u32;
    let mut res = [0u8; 4];
    BigEndian::write_u32(&mut res, as_u32);
    res
}

pub fn read_bytes(reader: &mut Read, n: usize) -> Result<Vec<u8>, io::Error> {
    let mut buffer: [u8; 1] = [0; 1];
    let mut res: Vec<u8> = Vec::with_capacity(n);
    for _ in 0..n {
        try!(reader.read(&mut buffer));
        res.push(buffer[0]);
    }
    Ok(res)
}

pub fn write_hash<W>(hash: &Hash, write: &mut W) -> Result<usize, io::Error> where W: Write {
    let bytes = hash.get_bytes();
    try!(write_u8(match hash {
        &Hash::None => 0,
        &Hash::Sha3(_) => 1
    }, write));
    write.write(&*bytes)
}

pub fn read_hash<R>(read: &mut R) -> Result<Hash, io::Error> where R: Read {
    let identifier = try!(read_u8(read));
    match identifier {
        1 => {
            let mut bytes = [0u8; 32];
            try!(read.read(&mut bytes));
            Ok(Hash::Sha3(bytes))
        }
        _ => Ok(Hash::None)
    }
}
