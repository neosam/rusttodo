//! Manipulation safe logging using crypo hashes.
//!
//! # Introduction
//! ## Use case:  Bank account software
//! Let's say you write an money account software where transfers between accounts
//! should be logged and multiple users have access.  If you insert a transaction,
//! you want a way to verify that nothing until the transaction was modified.
//! This library gives you a hash for every transaction you insert and the data
//! model makes sure you can quickly detect manipulations up to your transaction.
//!
//! ## More general:  Hashes as manipulation detection
//! When inserting an entry to a log, a hash value is returned.  This value
//! represents the inserted value and all it's previous entries.  Another way to
//! express it would be: it stands for the value and all if its history.
//! If any of it is maniputated,
//!
//! * the returned hash value would not match anymore or
//! * one of the hash values is invalid
//!
//! ## How to change entries
//! The library provides a way to modify entries.  For this, you can can borrow
//! a mutable reference of the entry and modify it.  Doing this will break the
//! verification check.  To fix the check again, a rebuild function is provided
//! by the library which generates a new log with the entries.  The hashes
//! for the entry and all newer entries will be completely different.  Through
//! the hash values, the first modified entry will always be visible by others.
//!
//! Why are there ways to modify data then?  Well, first, thanks to pointers
//! or structures like Call it will be possible anyway so there is no reason
//! to provide a simple and safe way to do this.  Another reason is that
//! modifications are only problematic if the entries are published or the
//! hashes checked into some kind of tracking storage.  Local only data can
//! be modified without causing any issues.
//! 
//!
//! # Usage
//! As the most abstract type, the main type is the Log trait in
//! this module.  It has a basic implementation DefaultLog which
//! implements all of its features (of course) and additionally
//! provides the ability to define custom load and save closures
//! which can be used to save and load entries.  By default, they
//! are empty.
//!
//! Since all entries are chained by their crypto hashes, the
//! Hashable trait must be implemented for the types.  It's also
//! possible to implement the Writable trait which provides a
//! a helper function to calculate the hash.


extern crate time;

use hash::*;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;


// ---- Core types ----

/// Contains a ordered set of entries by using crypto hash to chain them.
pub trait Log {
    type Item: Hashable;

    /// Add new entry to the log
    fn push(&mut self, Self::Item) -> Hash;


    /// Head hash
    fn head_hash(&self) -> Option<Hash>;

    /// Get the parent hash of the given hash.
    ///
    /// If the given hash is the first entry without a successor, it returns
    /// None, otherwise it returns the hash wrapped in Option::Some.
    ///
    /// # Errors
    /// Throws an error if an entry of the hash was not found.
    fn parent_hash(&self, hash: Hash) -> Result<Option<Hash>, LogError>;

    /// Get the borrowed entry of the given hash
    ///
    /// # Errors
    /// Throws an error if an entry of the hash was not found.
    fn get(&self, hash: Hash) -> Result<Self::Item, LogError>;

    /// Verify if hash is in the log
    fn has_hash(&self, hash: Hash) -> bool {
        match self.parent_hash(hash) {
            Ok(_) => true,
            Err(_) => false
        }
    }
}


/// Iterate over the elements of any log.
///
/// # Examples
/// ```
/// use tbd::log::*;
/// use tbd::hashio::*;
/// let mut log = DefaultLog::<String>::default();
///
/// log.push("str1".to_string());
/// log.push("str2".to_string());
///
/// let mut log_iter = LogIteratorRef::from_log(&log);
/// let mut res: Vec<String> = Vec::default();
/// for my_str in log_iter {
///     res.push(my_str.clone());
/// }
///
/// assert_eq!(2, res.len());
/// assert_eq!("str2", res[0]);
/// assert_eq!("str1", res[1]);
/// ```
pub struct LogIteratorRef<'a, L: Log<Item=T> + 'a, T: Hashable> {
    log: &'a L,
    hash: Option<Hash>
}

impl<'a, L: Log<Item=T>, T: Hashable + 'a> LogIteratorRef<'a, L, T> {
    /// Returns an iterator for the given Log.
    pub fn from_log(log: &'a L) -> LogIteratorRef<'a, L, T> {
        LogIteratorRef {
            log: log,
            hash: log.head_hash()
        }
    }
}

impl<'a, L: Log<Item=T>, T: Hashable + 'a> Iterator for LogIteratorRef<'a, L, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        match self.hash {
            None => None,
            Some(hash) => {
                let value = self.log.get(hash).ok();
                self.hash = self.log.parent_hash(hash).unwrap_or(None);
                value
            }
        }
    } 
}


/// Iterator which iterates over the hashes of a log.
///
/// ```
/// use tbd::hash::*;
/// use tbd::log::*;
/// let mut log = DefaultLog::<String>::default();
///
/// log.push("str1".to_string());
/// log.push("str2".to_string());
///
/// let mut log_iter = LogIteratorHash::from_log(&log);
/// let mut res: Vec<Hash> = Vec::new();
/// for hash in log_iter {
///     res.push(hash);
/// }
///
/// assert_eq!(2, res.len());
/// assert_eq!("2c72c3d0cb9c97242f6b3157a75d2ff04e368d6355a5ac650c2c0d6e1eb192ee",
///             res[0].as_string());
/// assert_eq!("43509d8f3af5d7507ab9c90bee7e54602f6103adb4f4a40cc069bbf1aebf2e6c",
///             res[1].as_string());
/// ```
pub struct LogIteratorHash<'a, L: Log<Item=T> + 'a, T: Hashable> {
    log: &'a L,
    hash: Option<Hash>
}

impl<'a, L: Log<Item=T>, T: Hashable + 'a> LogIteratorHash<'a, L, T> {
    /// Returns an iterator for the given Log which provides the hashes.
    pub fn from_log(log: &'a L) -> LogIteratorHash<'a, L, T> {
        LogIteratorHash {
            log: log,
            hash: log.head_hash()
        }
    }
}

impl<'a, L: Log<Item=T>, T: Hashable + 'a> Iterator for LogIteratorHash<'a, L, T> {
    type Item = Hash;

    fn next(&mut self) -> Option<Hash> {
        match self.hash {
            None => None,
            Some(hash) => {
                let value = self.hash;
                self.hash = self.log.parent_hash(hash).unwrap_or(None);
                value
            }
        }
    } 
}






// ---- DefaultLogEntry implementations ----
/// Error type for the default log.
#[derive(Debug, PartialEq)]
pub enum LogError {
    EntryNotFound(Hash),
    Unknown
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LogError::EntryNotFound(hash) => write!(f, "Entry not found for hash: {}",
                                          hash.as_string()),
            LogError::Unknown => write!(f, "Unknown log error")
        }
    }
}

impl Error for LogError {
    fn description(&self) -> &str {
        match *self {
            LogError::EntryNotFound(_) => "Entry for hash not found",
            LogError::Unknown => "Unknown log error"
        }
    }
}


/// Type for each entry of the DefaultLog.
pub struct DefaultLogEntry<T: Hashable + Clone> {
    /// Holds the actial entry.
    pub entry: T,

    /// Reference to the parent.
    pub parent_hash: Option<Hash>
}

/// Default implmentation of the Log.
///
/// It already provides functions to generate iterators for its entries and
/// hashes.
pub struct DefaultLog<T: Hashable + Clone> {
    entries: BTreeMap<Hash, DefaultLogEntry<T>>,
    head: Option<Hash>,
    load: Box<Fn(Hash) -> Option<DefaultLogEntry<T>>>,
    save: Box<Fn(&DefaultLogEntry<T>)>
}

impl<T: Hashable + Clone> DefaultLog<T> {
    /// Get the iterator for the entries.
    pub fn iter(&self) -> LogIteratorRef<DefaultLog<T>, T> {
        LogIteratorRef::from_log(self)
    }

    /// Get an iterator for the hashes.
    pub fn hash_iter(&self) -> LogIteratorHash<DefaultLog<T>, T> {
        LogIteratorHash::from_log(self)
    }

    /// Set load function called when an entry was not found.
    pub fn with_load_fn(mut self, load_fn: Box<Fn(Hash) -> Option<DefaultLogEntry<T>>>) -> DefaultLog<T> {
        self.load = load_fn;
        self
    }

    /// Set load function when entries should be saved.
    ///
    /// This is not used yet.
    pub fn with_save_fn(mut self, save_fn: Box<Fn(&DefaultLogEntry<T>)>) -> DefaultLog<T> {
        self.save = save_fn;
        self
    }
}

impl<T: Hashable + Clone> Log for DefaultLog<T> {
    type Item = T;


    /// Add new entry to log.
    ///
    /// Returns the hash value for the entry.
    fn push(&mut self, t: T) -> Hash {
        let entry_hash = t.as_hash();
        let hash = match self.head {
            None => entry_hash.as_hash(),
            Some(head_hash) => entry_hash.hash_with(head_hash)
        };
        let log_entry = DefaultLogEntry {
            entry: t,
            parent_hash: self.head
        };
        self.entries.insert(hash, log_entry);
        self.head = Some(hash);
        hash
    }

    /// Get the hash of the newest entry if not empty.
    ///
    /// Returns None if it's empty.
    fn head_hash(&self) -> Option<Hash> {
        self.head
    }

    /// Get the parent hash of the given hash if available.
    ///
    /// Returns None if parameter hash was not found or if it was empty.
    fn parent_hash(&self, hash: Hash) -> Result<Option<Hash>, LogError> {
        match self.entries.get(&hash) {
            None => Result::Err(LogError::EntryNotFound(hash)),
            Some(ref entry) => Ok(entry.parent_hash)
        }
    }

    /// Get entry with 
    fn get(&self, hash: Hash) -> Result<Self::Item, LogError> {
        match self.entries.get(&hash) {
            None => Result::Err(LogError::EntryNotFound(hash)),
            Some(ref entry) => Ok(entry.entry.clone())
        }
    }
}

impl<T: Hashable + Clone> Default for DefaultLog<T> {
    fn default() -> Self {
        DefaultLog {
            entries: BTreeMap::new(),
            head: None,
            load: Box::new(|_| None),
            save: Box::new(|_| ())
        }
    }
}



#[derive(PartialEq, Debug)]
pub enum LogVerifyFailure<T> {
    LogHashFailure {
        t: T,
        actual_hash: Hash,
        expected_hash: Hash
    },
    LogError(LogError)
}

fn gen_verify_failure<T>(t: T, act: Hash, exp: Hash)
                           -> LogVerifyFailure<T> {
    LogVerifyFailure::LogHashFailure {
        t: t,
        actual_hash: act,
        expected_hash: exp
    }
}


/// Verifies if the hash values of all entries are correct.
///
pub fn verify_log<L, T>(log: &L) -> Option<LogVerifyFailure<T>>
        where L: Log<Item=T>, T: Hashable {
    let hashes: Vec<Hash> = LogIteratorHash::from_log(log).collect();
    for hash in hashes.iter().rev() {
        let parent_hash_result = log.parent_hash(*hash);
        let entry = match log.get(*hash) {
            Err(err) => return Some(LogVerifyFailure::LogError(err)),
            Ok(hash) => hash
        };
        let entry_hash = entry.as_hash();
        let expected_hash = match parent_hash_result {
            Ok(parent_hash_option) => match parent_hash_option {
                None => entry_hash.as_hash(),
                Some(parent_hash) => entry_hash.hash_with(parent_hash)
            },
            Err(err) => return Some(LogVerifyFailure::LogError(err))
        };

        if *hash != expected_hash {
            return Some(gen_verify_failure(entry, *hash, expected_hash));
        }
    }
    None
}


/// Rebuild a log if the entries can be cloned
///
/// Rebuilding a log will create a new log of the same type and insert all
/// entries again.  This can be used to fix wrong hashes caused by maniputation.

pub fn rebuild_log<L, T>(log: &L) -> Result<L, LogError>
                where L: Log<Item=T> + Default,
                      T: Hashable + Clone {
    let mut res: L = Default::default();
    let hashes: Vec<Hash> = LogIteratorHash::from_log(log).collect();
    for hash in hashes.iter().rev() {
        let entry = try!(log.get(*hash));
        res.push(entry.clone());
    }
    Ok(res)
}
