use io::*;
use hash::*;
use hashio::*;
use std::io::{Read, Write};
use std::cell::{RefCell, Ref, RefMut};

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

    pub fn load(&self) {
        let is_none = self.t.borrow().is_none();
        if is_none {
            let res = self.hash_io.clone().unwrap().get(&self.hash).ok();
            *self.t.borrow_mut() = res;
        }
    }

    pub fn get_ref(&self) -> Ref<Option<T>> {
        self.load();
        self.t.borrow()
    }

    pub fn get_mut(&mut self) -> RefMut<Option<T>> {
        self.load();
        self.t.borrow_mut()
    }

    pub fn unwrap_ref(&self) -> Ref<T> {
        self.load();
        Ref::map(self.t.borrow(), | x | x.as_ref().unwrap())
    }

    pub fn unwrap_mut(&mut self) -> RefMut<T> {
        self.load();
        RefMut::map(self.t.borrow_mut(), | x | x.as_mut().unwrap())
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

    tbd_model!(B, [], [
        [b: String]
    ]);

    tbd_model!(A, [], [
        [a: LazyIO<B>]
    ]);

    #[test]
    fn test() {
        print!("Clean files\n");
        remove_dir_all("unittest/lazytest").ok();

        print!("Setting up...\n");
        let hash_io = HashIO::new("unittest/lazytest".to_string());
        let b = B { b: "test".to_string() };
        let a = A { a: LazyIO::new(b) };
        let hash = a.as_hash();
        hash_io.put(&a).unwrap();

        let mut a_again: A = hash_io.get(&hash).unwrap();
        print!("Hash should equal the one which reqested it\n");
        assert_eq!(hash, a_again.as_hash());
        // Access immutable
        {
            print!("Value should not yet be loaded\n");
            assert_eq!(false, a_again.a.is_loaded());

            print!("Get the reference, value will be loaded automatically\n");
            let new_lazy_opt = a_again.a.get_ref();
            let new_lazy = new_lazy_opt.as_ref().unwrap();

            print!("Verify if value is loaded now\n");
            assert_eq!(true, a_again.a.is_loaded());
            print!("Vefify values\n");
            assert_eq!("test".to_string(), new_lazy.b);

            // immutable borrow goes out of scope here
        }

        print!("Hash should not have changed after value was loaded\n");
        assert_eq!(hash, a_again.as_hash());

        // Access mutable
        {
            print!("Load mutable ref\n");
            let mut new_lazy_opt = a_again.a.get_mut();
            let mut new_lazy = new_lazy_opt.as_mut().unwrap();

            print!("Modify mutable ref\n");
            new_lazy.b = "changed".to_string();

            // mutable borrow goes out of scope here
        }

        print!("Hash should have changed\n");
        let new_hash = a_again.as_hash();
        assert_eq!(false, hash == new_hash);

        print!("Saving again...\n");
        hash_io.put(&a_again).unwrap();

        print!("Reloading...\n");
        let mut a_again: A = hash_io.get(&hash).unwrap();

        {
            print!("Get unwraped value of lazy\n");
            a_again.a.unwrap_ref();
        }

        {
            print!("Get mutable value of lazy\n");
            a_again.a.unwrap_mut();
        }
    }
}