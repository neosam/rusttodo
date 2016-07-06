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
//!
//! # Examples
//!
//! ```
//! // Load helpful macros by adding the macro_use tag.
//! #[macro_use] extern crate tbd;
//!
//! use tbd::hash::*;
//! use tbd::log::*;
//!
//! // Defining the type we want to store.  Lets use a simple struct which
//! // stores a byte for this example.
//! #[derive(Debug)]
//! struct MyStruct {
//!    x: u8
//! }
//!
//! // Make the struct Hashable.  Then it can be used for the Log types.
//! hashable_for_debug!(MyStruct);
//!
//!
//! fn main() {
//!     // Create new log object.  DefaultLog is the standard implementation
//!     // which also provides support to store and load entries and for iterators.
//!     let mut log: DefaultLog<MyStruct> = DefaultLog::new();
//!
//!     // Add some entries
//!     let first_hash: Hash = log.push(MyStruct{x: 42});
//!     let second_hash: Hash = log.push(MyStruct{x: 23});
//!
//!     // The push method returns the hash value which can be used as key.
//!     assert_eq!("5c9fd46aeb2781bb9ec9e5263cca012a4ea4632f2ac99991c8f430e2d051d268",
//!                    &first_hash.as_string());
//!     assert_eq!("a63ffbc7a358a3556a84531c55647ec9aeb4ca6e0a78edba86511c48c4bca1bd",
//!                    &second_hash.as_string());
//!
//!     // Inserting the same value again gives a completely different hash because
//!     // the hash also contains the previous entry.
//!     let third_hash: Hash = log.push(MyStruct{x: 23});
//!     assert_eq!("5fb3153625b7e41f791f81f4df593f15f8810034322e85916961578d0fbec635",
//!                    &third_hash.as_string());
//!
//!     // With get, we can borrow the entries using the hashes received from the
//!     // push method.
//!     assert_eq!(42, log.get(first_hash).unwrap().x);
//!     assert_eq!(23, log.get(second_hash).unwrap().x);
//!     assert_eq!(23, log.get(third_hash).unwrap().x);
//!
//!     // Iterate over the entries
//!     // This log operates like a stack and will return the last (latest)
//!     // entry first.
//!     let mut res = Vec::<u8>::new();
//!     for item in log.iter() {
//!         res.push(item.x);
//!     }
//!
//!     assert_eq!(23, res[0]);
//!     assert_eq!(23, res[1]);
//!     assert_eq!(42, res[2]);
//!
//!     // We can also iterate over the hashes.  Lets collect all in a Vec.
//!     let mut hashes: Vec<Hash> = log.hash_iter().collect();
//!     assert_eq!(3, hashes.len());
//!     assert_eq!("5fb3153625b7e41f791f81f4df593f15f8810034322e85916961578d0fbec635",
//!                    &hashes[0].as_string());
//!     assert_eq!("a63ffbc7a358a3556a84531c55647ec9aeb4ca6e0a78edba86511c48c4bca1bd",
//!                    &hashes[1].as_string());
//!     assert_eq!("5c9fd46aeb2781bb9ec9e5263cca012a4ea4632f2ac99991c8f430e2d051d268",
//!                    &hashes[2].as_string());
//! }
//! ```


extern crate time;

use hash::*;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;


// ---- Core types ----

/// Contains a ordered set of entries by using crypto hash to chain them.
pub trait Log {
    type Item: Hashable;

    /// Create an empty log
    fn new() -> Self;

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
    fn get(&self, hash: Hash) -> Result<&Self::Item, LogError>;

    /// Get a mutable entry of the given hash
    ///
    /// # Errors
    /// Throws an error if an entry of the hash was not found.
    fn get_mut(&mut self, hash: Hash) -> Result<&mut Self::Item, LogError>;

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
/// let mut log = DefaultLog::<String>::new();
///
/// log.push("str1".to_string());
/// log.push("str2".to_string());
///
/// let mut log_iter = LogIteratorRef::from_log(&log);
/// let mut res: Vec<String> = Vec::new();
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
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
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
/// let mut log = DefaultLog::<String>::new();
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
    EntryNotFound(Hash)
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LogError::EntryNotFound(hash) => write!(f, "Entry not found for hash: {}",
                                          hash.as_string())
        }
    }
}

impl Error for LogError {
    fn description(&self) -> &str {
        match *self {
            LogError::EntryNotFound(_) => "Entry for hash not found"
        }
    }
}


/// Type for each entry of the DefaultLog.
pub struct DefaultLogEntry<T: Hashable> {
    /// Holds the actial entry.
    pub entry: T,

    /// Reference to the parent.
    pub parent_hash: Option<Hash>
}

/// Default implmentation of the Log.
///
/// It already provides functions to generate iterators for its entries and
/// hashes.
pub struct DefaultLog<T: Hashable> {
    entries: BTreeMap<Hash, DefaultLogEntry<T>>,
    head: Option<Hash>,
    load: Box<Fn(Hash) -> Option<DefaultLogEntry<T>>>,
    save: Box<Fn(&DefaultLogEntry<T>)>
}

impl<T: Hashable> DefaultLog<T> {
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

impl<T: Hashable> Log for DefaultLog<T> {
    type Item = T;

    /// Create empty log.
    fn new() -> Self {
        DefaultLog {
            entries: BTreeMap::new(),
            head: None,
            load: Box::new(|_| None),
            save: Box::new(|_| ())
        }
    }

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
    fn get(&self, hash: Hash) -> Result<&Self::Item, LogError> {
        match self.entries.get(&hash) {
            None => Result::Err(LogError::EntryNotFound(hash)),
            Some(ref entry) => Ok(&entry.entry)
        }
    }

    fn get_mut(&mut self, hash: Hash) -> Result<&mut Self::Item, LogError> {
        match self.entries.get_mut(&hash) {
            None => Result::Err(LogError::EntryNotFound(hash)),
            Some(entry) => Ok(&mut entry.entry)
        }
    }
}



#[derive(PartialEq, Debug)]
pub enum LogVerifyFailure<'a, T: 'a> {
    LogHashFailure {
        t: &'a T,
        actual_hash: Hash,
        expected_hash: Hash
    },
    LogError(LogError)
}

fn gen_verify_failure<'a, T>(t: &'a T, act: Hash, exp: Hash)
                           -> LogVerifyFailure<'a, T> {
    LogVerifyFailure::LogHashFailure {
        t: t,
        actual_hash: act,
        expected_hash: exp
    }
}


/// Verifies if the hash values of all entries are correct.
///
/// # Examples
/// ```
/// #[macro_use] extern crate tbd;
/// use tbd::hash::*;
/// use tbd::log::*;
///
/// #[derive(Debug)] struct A {x: u32}
/// hashable_for_debug!(A);
///
/// fn main() {
///    let mut log = DefaultLog::<A>::new();
///    log.push(A{x: 1});
///    let entry_hash = log.push(A{x: 2});
///
///    // Expect the hashes in the logs are correct since no entries were
///    // modified.
///    match verify_log(&log) {
///        // None means, no errors found
///        None => (),
///        // Some means that something is not correct.
///        Some(_) => panic!("Expected no error if nothing was maniputated")
///    }
///
///    // Now lets manipulate some data
///    match log.get_mut(entry_hash) {
///        Err(_) => panic!("Expected an entry here, gave valid hash"),
///        Ok(entry) => entry.x = 3
///    }
///
///    // Verify again and it should find maniputation in the data.
///    match verify_log(&log) {
///        // None would mean that still everything is ok.
///        None => panic!("This time, verification should fail"),
///        // Some means an issue is was found.
///        // This can either be an error while accessing the log entries
///        // or a LogHashFailure which indicates maniputation. 
///        Some(fail) => match fail {
///            // Expecting maniputation and so a LogHashFailure.
///            LogVerifyFailure::LogHashFailure{t: t, expected_hash: exp, actual_hash: act} => {
///                assert_eq!("8da97bd9319b3eddb72c4f1e4b455090f69ee415dedde4e08e45ab31d9982d07",
///                                  exp.as_string());
///                assert_eq!("3b334afb2dad9ebbcdd0654f01b1ba3d55c55442a6d9bcbcc26afeec5a395530",
///                                  act.as_string());
///                assert_eq!(t.x, 3);
///            },
///            // Don't expect an error in the log type.
///            _ => panic!("Unexpected error during verification")
///        }
///    }
/// }
///
/// ```
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
///
/// # Examples
/// ```
/// #[macro_use] extern crate tbd;
/// use tbd::hash::*;
/// use tbd::log::*;
///
/// #[derive(Debug, Clone, PartialEq)]
/// struct A {x: u32}
/// hashable_for_debug!(A);
///
/// fn main() {
///     // Create a log with some dummy data
///     let mut log = DefaultLog::<A>::new();
///     let first_hash = log.push(A{x: 1});
///     let second_hash = log.push(A{x: 2});
///     let third_hash = log.push(A{x: 3});
///
///     // Manipulate the second hash:
///     // - All hashes are still in the log
///     // - Verification will fail since the entries do not match the hashes
///     //     anymore
///     match log.get_mut(second_hash) {
///         Err(_) => panic!("Didn't expect that"),
///         Ok(entry) => entry.x = 0
///     }
///     assert_eq!(true, verify_log(&log) != None);
///     assert_eq!(true, log.has_hash(first_hash)); 
///     assert_eq!(true, log.has_hash(second_hash)); 
///     assert_eq!(true, log.has_hash(third_hash)); 
///
///     // Build new log with fixed hashes.
///     // - Only parts of the hashes will be found in the log
///     //   - First one if found because maniputation took place after its entry
///     //   - Second will not be found anymore because it the manipulated entry
///     //   - Third entry also not be found because it comes after the maniputation
///     //       and so it's already affected.
///     // - Verification will succeed
///     let fixed_log = rebuild_log(&log).unwrap();
///     assert_eq!(None, verify_log(&fixed_log));
///     assert_eq!(true, fixed_log.has_hash(first_hash)); 
///     assert_eq!(false, fixed_log.has_hash(second_hash)); 
///     assert_eq!(false, fixed_log.has_hash(third_hash)); 
/// }
/// ```
pub fn rebuild_log<L: Log<Item=T>, T: Hashable + Clone>(log: &L) -> Result<L, LogError> {
    let mut res = L::new();
    let hashes: Vec<Hash> = LogIteratorHash::from_log(log).collect();
    for hash in hashes.iter().rev() {
        let entry = try!(log.get(*hash));
        res.push(entry.clone());
    }
    Ok(res)
} 
