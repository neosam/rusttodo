//! Logging library.
//!
//!

extern crate time;
extern crate crypto;
extern crate byteorder;

use std::io::{Write};

// ---- Core types ----

/// Stores one of the supported hash values.
#[derive(Clone, Copy, PartialEq)]
pub enum Hash {
    None,
    Sha3([u8; 32])
}



impl Hash {
    /// Get the hash as byte array.
    pub fn get_bytes(&self) -> Box<[u8]>{
        match self {
            &Hash::None => Box::new([0u8;0]),
            &Hash::Sha3(x) => Box::new(x)
        }
    }
}

/// Chain something like a linked list but additionally store a hash.
pub trait Log<T: Writable> {
    /// Type used as parent entry.
    type E: LogEntry<T>;

    /// Iterator to use
    type I: Iterator<Item=Self::E>;


    /// Add new entry to the log
    fn push(&mut self, T);


    /// Return an iterator which iterates over all entries.
    fn iter(&self) -> Self::I;

    /// Return a mutable iterator which iterates over all entries.
    fn iter_mut(&mut self) -> Self::I;

    /// Return an iterator and transform the ownership to it.
    fn into_iter(self) -> Self::I;


    /// Get the head read only.
    fn head(&self) -> &Self::E;

    /// Get mutable head.
    fn head_mut(&mut self) -> &mut Self::E;


    /// Verify if the hash values are valid.
    fn verify(&self) -> bool;

    /// Rebuild the hash values.
    fn rebuild(&mut self);


}


/// One entry in the log which holds the actual element.
pub trait LogEntry<T: Writable>: Writable {
    /// Let the parent if it exists.
    fn get_parent(&self) -> Option<&LogEntry<T>>;

    /// Get the mutable parent if it exists.
    fn get_parent_mut(&mut self) -> Option<&mut LogEntry<T>>;


    /// Get the hash value of the entry
    fn hash(&self) -> Hash;

    /// Borrow the stored element.
    fn entry(&self) -> &T;

    /// Borrow the stored element read write.
    fn entry_mut(&mut self) -> &mut T;
}

/// Write itself to any write trait.
pub trait Writable {
    fn write_to(&self, write: &mut Write);
}



// ---- Default implementation ----

/// The parent Entry is used to store the preccessor of an element or the head.
///
/// It can either be the beginning without a preccessor, point to a
/// DefaultLogEntry or contain a hash as reference value which will be loaded
/// dynamically.
pub enum ParentEntry<T: Writable> {
    Init,
    Entry(DefaultLogEntry<T>),
    HashRef(Hash)
}

impl<T: Writable> ParentEntry<T> {
    /// Get the hash of a parent entry
    pub fn parent_hash(&self) -> Hash {
        match *self {
            ParentEntry::Init => Hash::None,
            ParentEntry::Entry(ref log_entry) => log_entry.hash(),
            ParentEntry::HashRef(hash) => hash
        }
    }
}

pub struct DefaultLogEntry<T: Writable> {
    pub parent: Box<ParentEntry<T>>,
    pub elem: T,
}

impl<T: Writable> LogEntry<T> for DefaultLogEntry<T> {
    /// Let the parent if it exists.
    fn get_parent(&self) -> Option<&LogEntry<T>> {
        Option::None
    }

    /// Get the mutable parent if it exists.
    fn get_parent_mut(&mut self) -> Option<&mut LogEntry<T>> {
        Option::None
    }


    /// Get the hash value of the entry
    fn hash(&self) -> Hash {
        Hash::None
    }

    /// Borrow the stored element.
    fn entry(&self) -> &T {
        &self.elem
    }

    /// Borrow the stored element read write.
    fn entry_mut(&mut self) -> &mut T {
        &mut self.elem
    }
}

impl<T: Writable> Writable for DefaultLogEntry<T> {
    fn write_to(&self, writer: &mut Write) {
        self.elem.write_to(writer);
    }
}
