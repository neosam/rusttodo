//! Logging library.
//!
//!

extern crate time;
extern crate crypto;
extern crate byteorder;

use self::time::{Tm, Timespec, at_utc};
use self::byteorder::{BigEndian, ByteOrder};
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use std::io::{Write, Read};
use std::fs::{File, create_dir_all};
use std::io::Error;

/// Stores one of the supported hash values.
#[derive(Clone, Copy)]
pub enum Hash {
    Sha3([u8; 32])
}

impl PartialEq for Hash {
    fn eq(&self, other: &Hash) -> bool {
        match self {
            &Hash::Sha3(ref arr) => {
                let &Hash::Sha3(ref o_arr) = other;
                for i in 0..32 {
                    if arr[i] != o_arr[i] {
                        return false
                    }
                }
                true
            }
        }
    }
}


impl Hash {
    /// Get the hash as byte array.
    pub fn get_bytes(&self) -> Box<[u8]>{
        match self {
            &Hash::Sha3(x) => Box::new(x)
        }
    }
}

/// Defines if a type is able to generate a crypto hash which represents its
/// content.
///
/// This is required for the entries in the log to calculate the overall
/// checksum.
pub trait Hashable {
    fn to_hash(&self) -> Hash;
}

/// Refers to a precending entry or to the root.
pub enum ParentEntry<T: Hashable> {
    Init,
    ParentEntry(LogEntry<T>),
    ParentHash(Hash)
}


impl<T: Hashable> ParentEntry<T> {
    /// Calcalate the hash value for a ParentEntry.
    ///
    /// This will return the hash entry of the parent or a dummy value if
    /// it's the head.
    pub fn parent_hash(&self) -> Hash {
        match *self {
            ParentEntry::Init => Hash::Sha3([0; 32]),
            ParentEntry::ParentEntry(ref x) => x.hash,
            ParentEntry::ParentHash(ref hash) => hash.clone()
        }
    }
}


/// An single entry plus timestamp, its hash and its parent.
///
/// Its hash value is a sumary of the entry value, the timestamp and its parent
/// hash.
pub struct LogEntry<T: Hashable> {
    pub hash: Hash,
    pub dttm: Tm,
    pub entry: T,
    pub parent: Box<ParentEntry<T>>
}

/// Main log structure which points to the latest entry.
pub struct Log<T: Hashable> {
    pub head: Box<ParentEntry<T>>
}

/// Functions a Log must provide to count as a log.
pub trait LogTrait<T: Hashable> {
    fn add_entry(&mut self, entry: T, tm: Tm);
    fn verify(&self) -> bool;
}

/// Convert a Tm time structure to a byte array.
///
/// This is used to feed it to a hashing algorithm.
pub fn tm_to_bytes(tm: &Tm) -> [u8; 8] {
    let mut res : [u8; 8] = [0; 8];
    let timespec = tm.to_timespec();
    println!("Sec: {}", timespec.sec);
    BigEndian::write_i64(&mut res, timespec.sec);
    return res;
}

pub fn tm_from_i64(i: i64) -> Tm {
    let timespec = Timespec::new(i, 0);
    at_utc(timespec)
}

fn load_nothing<T: Hashable>(hash: Hash) -> Option<LogEntry<T>>{
    None
}

impl<T: Hashable> Log<T> {
    /// Create a new and empty log
    pub fn new() -> Self {
        Log {
            head: Box::new(ParentEntry::Init)
        }
    }

    pub fn iter(&self) -> LogIterator<T> {
        LogIterator {
            value: &self.head
        }
    }
}

impl<T: Hashable> LogEntry<T> {
    pub fn entry_hash(&self) -> Hash {
        let mut msg_vec: Vec<u8> = Vec::new();

        // Generate hash input:  Add the parent hash
        msg_vec.extend_from_slice(&*self.parent.parent_hash().get_bytes());

        // Generate hash input:  Add the timestamp
        msg_vec.extend_from_slice(&tm_to_bytes(&self.dttm));

        // Generate hash input:  Add the entry hash
        msg_vec.extend_from_slice(&self.entry.to_hash().get_bytes());

        // Generate slice as input for hash algorithm
        let msg: &[u8] = msg_vec.as_slice();

        // Hash and return
        let mut hasher = Sha3::sha3_256();
        hasher.input(msg);
        let mut hash_val: [u8; 32] = [0; 32];
        hasher.result(&mut hash_val);
        let hash = Hash::Sha3(hash_val);
        hash
    }

}

impl<T: Hashable> LogTrait<T> for Log<T> {
    fn add_entry(&mut self, entry: T, tm: Tm) {
        use std::mem;

        let new_parent = Box::new(ParentEntry::Init);
        let head = mem::replace(&mut self.head, new_parent);
        let mut new_log_entry = LogEntry {
            hash: Hash::Sha3([0; 32]),
            dttm: tm,
            entry: entry,
            parent: Box::new(*head)
        };
        new_log_entry.hash = new_log_entry.entry_hash();
        self.head = Box::new(ParentEntry::ParentEntry(new_log_entry));
    }

    fn verify(&self) -> bool {
        let mut parent = &self.head;
        let mut verified = false;
        loop {
            match **parent {
                ParentEntry::Init => {verified = true; break},
                ParentEntry::ParentEntry(ref x) => parent = &x.parent,
                ParentEntry::ParentHash(ref hash) => {verified = true; break}

            }
        }
        verified
    }
}

pub struct LogIterator<'a, T: 'a + Hashable> {
    value: &'a ParentEntry<T>
}

impl<'a, T: 'a + Hashable> Iterator for LogIterator<'a, T> {
    type Item = &'a LogEntry<T>;

    fn next(&mut self) -> Option<&'a LogEntry<T>> {
        match self.value {
            &ParentEntry::Init => None,
            &ParentEntry::ParentEntry(ref entry) => {
                self.value = &*entry.parent;
                Some(entry)
            }
            &ParentEntry::ParentHash(ref hash) => None
        }
    }
}

pub trait Writable {
    fn write(&self, writer: &mut Write);
}

pub trait Readable {
    fn read(reader: &mut Read) -> Self;
}

impl Writable for Hash {
    fn write(&self, writer: &mut Write) {
        match self {
            &Hash::Sha3(bytes) => {
                let hash_type: [u8; 4] = [0, 0, 0, 0x01];
                writer.write(&hash_type);
                writer.write(&bytes);
            }
        }
    }
}

impl Readable for Hash {
    fn read(reader: &mut Read) -> Hash {
        let hash_type = read_u32(reader);
        match hash_type {
            1 => {
                let mut bytes: [u8; 32] = [0; 32];
                reader.read(&mut bytes);
                Hash::Sha3(bytes)
            }
            _ => {
                let mut bytes: [u8; 32] = [0; 32];
                Hash::Sha3(bytes)
            }
        }
    }
}


fn read_u32(reader: &mut Read) -> u32 {
    let mut bytes: [u8; 4] = [0; 4];
    reader.read(&mut bytes);
    BigEndian::read_u32(&bytes)
}

fn read_i64(reader: &mut Read) -> i64 {
    let mut bytes: [u8; 8] = [0; 8];
    reader.read(&mut bytes);
    BigEndian::read_i64(&bytes)
}

impl<T: Hashable + Writable> Writable for LogEntry<T> {
    fn write(&self, writer: &mut Write) {
        let parent_hash: Hash = self.parent.parent_hash();
        self.hash.write(writer);
        writer.write(&tm_to_bytes(&self.dttm));
        parent_hash.write(writer);
        self.entry.write(writer);
    }
}

/*impl<T: Hashable + Readable> Readable for LogEntry<T> {
    fn read(reader: &mut Read) -> LogEntry<T> {
        let hash = Hash::read(reader);
        let dttm = tm_from_i64(read_i64(reader));

    }
}*/

fn half_byte_to_hex(b: u8) -> char {
    match b {
        0x00 => '0',
        0x01 => '1',
        0x02 => '2',
        0x03 => '3',
        0x04 => '4',
        0x05 => '5',
        0x06 => '6',
        0x07 => '7',
        0x08 => '8',
        0x09 => '9',
        0x0A => 'A',
        0x0B => 'B',
        0x0C => 'C',
        0x0D => 'D',
        0x0E => 'E',
        0x0F => 'F',
        _ => '?'
    }
}

fn byte_to_hex(b: u8) -> String {
    let mut res = String::new();
    res.push(half_byte_to_hex(b / 16));
    res.push(half_byte_to_hex(b % 16));
    res
}

pub fn bin_slice_to_hex(slice: &[u8]) -> String {
    let mut res = String::new();
    for b in slice {
        res.push_str(&byte_to_hex(*b));
    }
    res
}

pub fn save_to_fs<T: Hashable + Writable>(dest_dir: &str, log: &Log<T>)
                                            -> Result<(), Error>{
    for entry in log.iter() {
        let hex_hash = bin_slice_to_hex(&*entry.hash.get_bytes());
        let save_dir = dest_dir.to_string() + "/" + &hex_hash[0..2] + "/";
        let filename = save_dir.clone() + &hex_hash[2..];
        create_dir_all(&save_dir);
        let mut f = try!(File::create(filename));
        f.write("TBDE".as_bytes());
        write_u32(&mut f, 1);
        entry.write(&mut f);
        f.flush().expect("Could not flush file");
    }
    save_head_to_fs(dest_dir, log)
}

fn write_u32(writer: &mut Write, u: u32) {
    let mut bytes: [u8; 4] = [0; 4];
    BigEndian::write_u32(&mut bytes, u);
    writer.write(&bytes);
}

pub fn save_head_to_fs<T: Hashable + Writable>(dest_dir: &str, log: &Log<T>)
                                               -> Result<(), Error> {
    try!(create_dir_all(&dest_dir));
    let filename = dest_dir.to_string() + "head";
    let mut f = try!(File::create(filename));
    f.write("TBDH".as_bytes());
    write_u32(&mut f, 1);
    log.head.parent_hash().write(&mut f);
    f.flush()
}
