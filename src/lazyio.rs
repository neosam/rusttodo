use io::*;
use hash::*;
use hashio::*;
use std::io::{Read, Write};

/// Will only be loaded when required.
///
/// Stores a hash of a value and will run the HashIO loader
/// when the get method was called.  Once loaded, it will be stored
/// internally and can be modified.
///
/// It implements Hashable.  As long as the type is not loaded, the
/// stored hash will be used.  When loaded, the real hash will be calcalated
/// by calling the as_hash method of the stored object.
///
/// Use .get_ref to receive a read only reference and .get_mut to even get a mutable
/// reference.  Use .put to override the data.
///
/// HashIO will store the data if 
#[derive(Clone, Debug)]
struct LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized,
              HashIO: HashIOImpl<T> {
    hash: Hash,
    hash_io: HashIO,
    t: Option<T>
}

impl<T> LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized,
              HashIO: HashIOImpl<T> {
    pub fn new(hash: Hash, hash_io: HashIO) -> LazyIO<T> {
        LazyIO {
            hash: hash,
            hash_io: hash_io,
            t: None
        }
    }
}

impl<T> Hashable for LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized,
              HashIO: HashIOImpl<T> {
    fn as_hash(&self) -> Hash {
        match self.t {
            None => self.hash,
            Some(ref t) => t.as_hash()
        }
    }
}

impl<T> Typeable for LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized,
              HashIO: HashIOImpl<T> {
    fn type_hash() -> Hash {
        T::type_hash()
    }
}

impl<T> Hashtype for LazyIO<T>
        where T: Hashtype, T: Writable,
              HashIO: HashIOImpl<T> {}

impl<T> HashIOImpl<LazyIO<T>> for HashIO
        where T: Hashtype, T: Writable,
              HashIO: HashIOImpl<T> {
    fn receive_hashable<R>(&self, _: &mut R, hash: &Hash) -> Result<LazyIO<T>, HashIOError>
                where R: Read {
        Ok(LazyIO::new(hash.clone(), self.clone()))
    }
    fn store_hashable<W>(&self, lazy_io: &LazyIO<T>, write: &mut W) -> Result<(), HashIOError>
                where W: Write {
        match lazy_io.t {
            // Don't store anything which is not yet loaded
            None => Ok(()),
            Some(ref t) =>  self.store_hashable(t, write)
        }
    }

    fn store_childs(&self, lazy_io: &LazyIO<T>) -> Result<(), HashIOError> {
        match lazy_io.t {
            None => Ok(()),
            Some(ref t) => self.store_childs(t)
        }
    }
}

impl<T> LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized, T: Clone,
              HashIO: HashIOImpl<T> {
    pub fn get_ref(&mut self) -> &Option<T> {
        let is_none = self.t.is_none();
        if is_none {
            let res = self.hash_io.get(&self.hash).ok();
            self.t = res;
        }
        &self.t
    }

    pub fn get_mut(&mut self) -> &mut Option<T> {
        let is_none = self.t.is_none();
        if is_none {
            let res = self.hash_io.get(&self.hash).ok();
            self.t = res;
        }
        &mut self.t
    }

    pub fn put(&mut self, t: T) {
        self.t = Some(t)
    }
}

