//! Logging library.
//!
//!

extern crate time;
extern crate crypto;
extern crate byteorder;

use self::time::Tm;
use self::byteorder::{BigEndian, ByteOrder};
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;

/// Stores one of the supported hash values.
#[derive(Clone, Copy)]
pub enum Hash {
    Sha3([u8; 32])
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
    ParentEntry(LogEntry<T>)
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
    pub head: ParentEntry<T>
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
    BigEndian::write_i64(&mut res, timespec.sec);
    return res;
}

impl<T: Hashable> Log<T> {
    /// Create a new and empty log
    pub fn new() -> Self {
        Log {
            head: ParentEntry::Init
        }
    }

    pub fn iter(&mut self) -> LogIterator<T> {
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

        let new_parent = ParentEntry::Init;
        let head = mem::replace(&mut self.head, new_parent);
        let mut new_log_entry = LogEntry {
            hash: Hash::Sha3([0; 32]),
            dttm: tm,
            entry: entry,
            parent: Box::new(head)
        };
        new_log_entry.hash = new_log_entry.entry_hash();
        self.head = ParentEntry::ParentEntry(new_log_entry);
    }

    fn verify(&self) -> bool {
        let mut parent = &self.head;
        let mut verified = false;
        loop {
            match parent {
                &ParentEntry::Init => {verified = true; break},
                &ParentEntry::ParentEntry(ref x) => parent = &*x.parent
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
        }
    }
}
