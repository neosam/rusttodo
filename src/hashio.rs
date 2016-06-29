//! Cryptographic hashes including IO
//!
//! # Usage
//! This module provides functionality to let a struct
//! represent itself as a cryptographic hash value.
//! It also provides the Writable trait which can be used
//! to save the struct.  Via a macro, a Hashable trait can
//! be implemented if it implements the Writable trait.
//!
//! If a trait implements Writable, Readable and Hashable,
//! it can also implement the HashIO trait which allows
//! the values to be cashed.
//!
//! # Examples
//! ```
//! #[macro_use] extern crate tbd;
//! use tbd::hashio::*;
//! use std::io::{Read, Write};
//! use std::io;
//! use std::rc::Rc;
//!
//! // This is a simple struct we want to work with.
//! struct A {x: u32}
//!
//! // Implement the Writable trait for our struct
//! // so we can store it somewhere.
//! impl Writable for A {
//!     fn write_to(&self, write: &mut Write) -> Result<usize, io::Error> {
//!         write_u32(self.x, write)
//!     }
//! }
//!
//! // Implement the Readablet trait for our struct
//! // so we can read it again.
//! impl Readable for A {
//!     fn read_from(read: &mut Read, _: &mut HashIOCache) -> Result<A, HashIOError> {
//!         Ok(A {x: try!(read_u32(read))})
//!     }
//! }
//!
//! // Define it as fully serializable.
//! impl ReadWrite for A {}
//!
//! // Let a macro implement the hashing algorithm
//! hashable_for_writable!(A);
//!
//! // Make a full HashIO out of it
//! impl HashIO for A {
//!     // Return the childs
//!     fn childs(&self) -> Vec<&HashIO> {
//!         Vec::new()
//!     }
//! }
//!
//! fn main() {
//!     // Create and initialize the cashe and store some structs.
//!     // The insert function returns a hash value which is used to
//!     // access the values.
//!     let mut cache = HashIOCache::new();
//!     let hash1 = cache.put(A{x: 0});
//!     let hash2 = cache.put(A{x: 1});
//!     let hash3 = cache.put(A{x: 2});
//!
//!     // Lets return these values again.
//!     let a1: Rc<A> = cache.get(hash1).unwrap();
//!     let a2: Rc<A> = cache.get(hash2).unwrap();
//!     let a3: Rc<A> = cache.get(hash3).unwrap();
//!
//!     // Verify if we actually got the right values.
//!     assert_eq!(0, a1.x);
//!     assert_eq!(1, a2.x);
//!     assert_eq!(2, a3.x);
//! }
//! ```


extern crate crypto;
extern crate byteorder;

use std::io::{Read, Write};
use self::crypto::sha3::Sha3;
use self::crypto::digest::Digest;
use self::byteorder::{BigEndian, ByteOrder};
use std::{io, error, fmt};
use std::fs::{File, create_dir_all};
use std::collections::BTreeMap;
use std::time::SystemTime;
use std::rc::Rc;


#[derive(Debug)]
pub enum HashIOError {
    IOError(io::Error),
    ParseError(Box<error::Error>)
}

impl fmt::Display for HashIOError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashIOError::IOError(ref err) => err.fmt(f),
            HashIOError::ParseError(ref err) => write!(f, "Parse error: {}", err)
        }
    }
}

impl error::Error for HashIOError {
    fn description(&self) -> &str {
        match *self {
            HashIOError::IOError(ref err) => err.description(),
            HashIOError::ParseError(ref err) => err.description()
        }
    }
}

impl From<io::Error> for HashIOError {
    fn from(err: io::Error) -> HashIOError {
        HashIOError::IOError(err)
    }
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

/// Stores one of the supported hash values.
///
/// # Examples
/// ```
/// use tbd::hashio::*;
///
/// // Generate a hash using hash_bytes which generates a sha3-256 hash.
/// let hash = Hash::hash_bytes(&"foo".to_string().as_bytes());
///
/// // Can generate a string representation
/// assert_eq!("76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01",
///                  hash.as_string());
/// ```
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



/// Write itself to any write trait.
///
/// It also implements the Hashable type by default and generates
/// a sha3 representation of its output.
pub trait Writable {
    fn write_to(&self, write: &mut Write) -> Result<usize, io::Error>;
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
/// use tbd::hashio::*;
/// use std::io::Write;
/// use std::io;
///
/// struct A {
///    x: u8
/// }
///
/// impl Writable for A {
///     fn write_to(&self, write: &mut Write) -> Result<usize, io::Error> {
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
/// use tbd::hashio::*;
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


fn usize_to_u32_bytes(x: usize) -> [u8; 4] {
    let as_u32 = x as u32;
    let mut res = [0u8; 4];
    BigEndian::write_u32(&mut res, as_u32);
    res
}




/// Read from a Read trait.
pub trait Readable {
    fn read_from(read: &mut Read, cache: &mut HashIOCache) -> Result<Self, HashIOError>
        where Self: Sized;
}

/// Type which can be written and loaded.
pub trait ReadWrite: Readable + Writable {
}



/// Type which can be written and loaded and contain hashes as references to
/// other objects.
///
/// The read and write function should not deeply save the whole data set.
/// Instead it should store just store the hashes of any child objects which also
/// implement the HashIO trait.
///
/// Save functions then can store each HashIO object in a separate file and so
/// updates can be saved much faster and rendundance is avoided.
pub trait HashIO: ReadWrite + Hashable {
    fn childs(&self) -> Vec<&HashIO>;
}

impl Writable for String {
    fn write_to(&self, write: &mut Write) -> Result<usize, io::Error> {
        let str_bytes = self.as_bytes();
        let len = usize_to_u32_bytes(str_bytes.len());
        let mut size: usize = 0;
        size += try!(write.write(&len));
        size += try!(write.write(&str_bytes));
        Ok(size)
    }
}
impl ReadWrite for String {}
impl HashIO for String {
    fn childs(&self) -> Vec<&HashIO> {
        Vec::new()
    }
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

impl Readable for String {
    fn read_from(read: &mut Read, _: &mut HashIOCache) -> Result<String, HashIOError> {
        let len = try!(read_u32(read));
        let bytes = try!(read_bytes(read, len as usize));
        let res = try!(String::from_utf8(bytes).map_err(|x| HashIOError::ParseError(Box::new(x))));
        Ok(res)
    }
}
hashable_for_writable!(String);

/// Store a HashIO to HD and all its childs.
pub fn save_hash_io(root_path: &str, version: u32,
                    hash_io: &HashIO) -> Result<(), io::Error> {
    // First make sure to save the childs
    for child in hash_io.childs() {
        try!(save_hash_io(root_path, version, &*child));
    }

    save_single_hash_io(root_path, version, hash_io)
}

pub fn save_single_hash_io(root_path: &str, version: u32, hash_io: &HashIO)
                           -> Result<(), io::Error> {
    let string_hash = hash_io.as_hash().as_string();
    let dest_dir = format!("{}/{}", root_path.to_string(), string_hash[0..2].to_string());
    let filename = format!("{}/{}/{}", root_path.to_string(), string_hash[0..2].to_string(),
                           string_hash[2..].to_string());
    try!(create_dir_all(dest_dir));
    let mut f = try!(File::create(filename));
    try!(f.write("TBDE".as_bytes()));
    try!(write_u32(version, &mut f));
    try!(hash_io.write_to(&mut f));
    f.flush()
}



/// Hold cached data in this structure
///
/// ```
/// #[macro_use] extern crate tbd;
/// use tbd::hashio::*;
/// use std::io::{Read, Write};
/// use std::io;
/// use std::rc::Rc;
///
/// struct A {x: u32}
/// impl Writable for A {
///     fn write_to(&self, write: &mut Write) -> Result<usize, io::Error> {
///         write_u32(self.x, write)
///     }
/// }
///
/// impl Readable for A {
///     fn read_from(read: &mut Read, _: &mut HashIOCache) -> Result<A, HashIOError> {
///         Ok(A {x: try!(read_u32(read))})
///     }
/// }
///
/// impl ReadWrite for A {}
///
/// hashable_for_writable!(A);
///
/// impl HashIO for A {
///     fn childs(&self) -> Vec<&HashIO> {
///         Vec::new()
///     }
/// }
///
/// fn main() {
///     let mut cache = HashIOCache::new();
///     let hash1 = cache.put(A{x: 0});
///     let hash2 = cache.put(A{x: 1});
///     let hash3 = cache.put(A{x: 2});
///
///     let a1: Rc<A> = cache.get(hash1).unwrap();
///     let a2: Rc<A> = cache.get(hash2).unwrap();
///     let a3: Rc<A> = cache.get(hash3).unwrap();
///
///     assert_eq!(0, a1.x);
///     assert_eq!(1, a2.x);
///     assert_eq!(2, a3.x);
/// }
/// ```
pub struct HashIOCache {
    pub map: BTreeMap<Hash, HashIOCacheItem>
}

pub struct HashIOCacheItem {
    pub saved_to_fs: bool,
    pub last_usage: SystemTime,
    pub item: *mut HashIO
}

impl HashIOCacheItem {
    fn new<T: 'static + HashIO>(item: T) -> HashIOCacheItem {
        HashIOCacheItem {
            saved_to_fs: false,
            last_usage: SystemTime::now(),
            item: Box::into_raw(Box::new(item))
        }
    }
}

impl<'a> HashIOCache {
    pub fn new() -> Self {
        HashIOCache {
            map: BTreeMap::new()
        }
    }

    pub fn get<T: HashIO>(&self, hash: Hash) -> Option<Rc<T>> {
        match self.map.get(&hash) {
            None => None,
            Some(cache_item) => {
                unsafe {
                    Some(Rc::new(*Box::from_raw(cache_item.item as *mut T)))
                }
            }
        }
    }

    pub fn put<T: 'static + HashIO>(&mut self, item: T) -> Hash {
        let hash = item.as_hash();
        let item = HashIOCacheItem::new(item);
        self.map.insert(hash, item);
        hash
    }
}
