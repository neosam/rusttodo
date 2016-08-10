use io::*;
use hash::*;
use hashio::*;
use std::io::{Read, Write};
use std::cell::{RefCell, Ref};

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
#[derive(Clone, Debug, PartialEq)]
pub struct LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized,
              HashIO: HashIOImpl<T> {
    hash: Hash,
    hash_io: Option<HashIO>,
    t: RefCell<Option<T>>
}

impl<T> LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized,
              HashIO: HashIOImpl<T> {
    pub fn unloaded(hash: Hash, hash_io: HashIO) -> LazyIO<T> {
        LazyIO {
            hash: hash,
            hash_io: Some(hash_io),
            t: RefCell::new(None)
        }
    }

    pub fn new(t: T) -> LazyIO<T> {
        LazyIO {
            hash: t.as_hash(),
            hash_io: None,
            t: RefCell::new(Some(t))
        }
    }
}

impl<T> Hashable for LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized,
              HashIO: HashIOImpl<T> {
    fn as_hash(&self) -> Hash {
        match *self.t.borrow() {
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
        Ok(LazyIO::unloaded(hash.clone(), self.clone()))
    }

    fn store_hashable<W>(&self, lazy_io: &LazyIO<T>, write: &mut W) -> Result<(), HashIOError>
                where W: Write {
        match *lazy_io.t.borrow() {
            // Don't store anything which is not yet loaded
            None => Ok(()),
            Some(ref t) =>  self.store_hashable(t, write)
        }
    }

    fn store_childs(&self, lazy_io: &LazyIO<T>) -> Result<(), HashIOError> {
        match *lazy_io.t.borrow() {
            None => Ok(()),
            Some(ref t) => self.store_childs(t)
        }
    }
}

impl<T> LazyIO<T>
        where T: Hashtype, T: Writable, T: Sized,
              HashIO: HashIOImpl<T> {

    pub fn get_ref(&self) -> Ref<Option<T>> {
        let is_none = self.t.borrow().is_none();
        if is_none {
            let res = self.hash_io.clone().unwrap().get(&self.hash).ok();
            *self.t.borrow_mut() = res;
        }
        self.t.borrow()
    }

    pub fn put(&mut self, t: T) {
        *self.t.borrow_mut() = Some(t)
    }

    pub fn is_loaded(&self) -> bool {
        self.t.borrow().is_some()
    }
}

#[cfg(test)]
mod test {
    use super::super::lazyio::*;
    use super::super::hash::*;
    use super::super::hashio::*;
    use super::super::io::*;
    use std::io::{Read, Write};
    use std::io;
    use std::fs::remove_dir_all;

    tbd_model!(A, [], [
        [x: LazyIO<String>]
    ]);

    #[test]
    fn test() {
        remove_dir_all("unittest/lazytest").ok();

        let hash_io = HashIO::new("unittest/lazytest".to_string());
        let a = A { x: LazyIO::new("test".to_string()) };
        let hash = a.as_hash();
        hash_io.put(&a).unwrap();

        let a_again: A = hash_io.get(&hash).unwrap();
        assert_eq!(false, a_again.x.is_loaded());
        let new_lazy_opt = a_again.x.get_ref();
        let new_lazy = new_lazy_opt.as_ref().unwrap();
        assert_eq!(true, a_again.x.is_loaded());
        assert_eq!(&"test".to_string(), new_lazy);
    }
}