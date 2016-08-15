//! Cryptographic hashes including IO - from version 0.2
//!
//! This module exists to be backward compatible to older types.
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

extern crate crypto;
extern crate byteorder;


use std::io::{Read, Write};
use std::{io, error, fmt};
use hash::*;
use io::*;
use std::fs::{File, create_dir_all};
use std::collections::BTreeMap;
use std::vec::Vec;
use std::path::Path;
use std::fs::rename;



#[derive(Debug)]
pub enum HashIOError1 {
    Undefined(String),
    IOError(io::Error),
    ParseError(Box<error::Error>)
}



impl fmt::Display for HashIOError1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashIOError1::Undefined(ref msg) => write!(f, "Undefined error: {}", msg),
            HashIOError1::IOError(ref err) => err.fmt(f),
            HashIOError1::ParseError(ref err) => write!(f, "Parse error: {}", err)
        }
    }
}

impl error::Error for HashIOError1 {
    fn description(&self) -> &str {
        match *self {
            HashIOError1::Undefined(ref msg) => msg,
            HashIOError1::IOError(ref err) => err.description(),
            HashIOError1::ParseError(ref err) => err.description()
        }
    }
}

impl From<io::Error> for HashIOError1 {
    fn from(err: io::Error) -> HashIOError1 {
        HashIOError1::IOError(err)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HashIO1 {
    pub base_path: String
}

pub trait HashIOImpl1<T: Hashable> {
    fn receive_hashable<R>(&self, read: &mut R) -> Result<T, HashIOError1>
        where R: Read;
    fn store_hashable<W>(&self, hashable: &T, write: &mut W) -> Result<(), HashIOError1>
        where W: Write;

    fn store_childs(&self, _: &T) -> Result<(), HashIOError1> {
        Ok(())
    }
}

impl HashIO1 {
    pub fn new(path: String) -> HashIO1 {
        HashIO1 {
            base_path: path
        }
    }

    pub fn directory_for_hash(&self, hash: &Hash) -> String {
        let hash_str = hash.as_string();
        let mut result = String::new();
        result.push_str(&self.base_path);
        result.push('/');
        result.push_str(&hash_str[0..2]);
        result.push('/');
        result
    }

    pub fn filename_for_hash(&self, hash: &Hash) -> String {
        let hash_str = hash.as_string();
        let mut result = self.directory_for_hash(hash);
        result.push_str(&hash_str[2..]);
        result
    }

    pub fn get<T>(&self, hash: &Hash) -> Result<T, HashIOError1>
                where HashIO1: HashIOImpl1<T>,
                      T: Hashable {
        let filename = self.filename_for_hash(hash);
        let mut read = match File::open(filename.clone()) {
            Ok(x) => x,
            Err(err) => {
                warn!("HashIO1:  Could not open opening {}: {}\n", filename, err);
                return Err(HashIOError1::from(err))
            }
        };
        let result : T = try!(self.receive_hashable(&mut read));
        Ok(result)
    }

    pub fn put<T>(&self, hashable: &T) -> Result<(), HashIOError1>
                where HashIO1: HashIOImpl1<T>,
                      T: Hashable {
        let hash = hashable.as_hash();

        // First, if the entry already exists, skip the insert because it's already saved.
        let filename = self.filename_for_hash(&hash);
        if !Path::new(&filename).exists() {
            // First store all childs and their childs.
            // So we make sure that all dependencies are available when the current object has
            // finished writing.
            try!(self.store_childs(hashable));

            // First write in a slightly modified file which will be renamed when writing was
            // finished.  So we only have valid files or nothing on the expected position but
            // nothing unfinished.
            let safe_filename = format!("{}_", filename);
            let dir = self.directory_for_hash(&hash);
            try!(create_dir_all(dir));
            {
                let mut write = try!(File::create(Path::new(&safe_filename)));
                try!(self.store_hashable(hashable, &mut write));
                // 'write' will go out of scope now and so the file handle will be closed
            }
            try!(rename(safe_filename, filename));
        }
        Ok(())
    }
}



impl Writable for String {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
        let str_bytes = self.as_bytes();
        let len = usize_to_u32_bytes(str_bytes.len());
        let mut size: usize = 0;
        size += try!(write.write(&len));
        size += try!(write.write(&str_bytes));
        Ok(size)
    }
}
hashable_for_writable!(String);

impl HashIOImpl1<String> for HashIO1 {
    fn store_hashable<W>(&self, hashable: &String, write: &mut W) -> Result<(), HashIOError1>
                    where W: Write {
        try!(hashable.write_to(write));
        Ok(())
    }

    fn receive_hashable<R>(&self, read: &mut R) -> Result<String, HashIOError1>
                    where R: Read {
        let len = try!(read_u32(read));
        let bytes = try!(read_bytes(read, len as usize));
        let res = try!(String::from_utf8(bytes).map_err(|x| HashIOError1::ParseError(Box::new(x))));
        Ok(res)
    }
}






macro_rules! tbd_model_1 {
    ($model_name:ident,
            [ $( [$attr_name:ident : $attr_type:ty, $exp_fn:ident, $imp_fn:ident ] ),* ] ,
            [ $( [$hash_name:ident : $hash_type:ty] ),* ]) => {

        #[derive(Debug, Clone, PartialEq)]
        pub struct $model_name {
            $(pub $attr_name: $attr_type,)*
            $(pub $hash_name: $hash_type),*
        }

        impl Writable for $model_name {
            fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
                let mut size = 0;
                try!(write_u32(0, write));
                size += $( try!($exp_fn(self.$attr_name, write)); )*
                $(
                    try!(write_hash(&self.$hash_name.as_hash(), write));
                    size += 32;
                )*
                Ok(size)
            }
        }

        hashable_for_writable!($model_name);

        impl HashIOImpl1<$model_name> for HashIO1 {
            fn receive_hashable<R>(&self, read: &mut R) -> Result<$model_name, HashIOError1>
                    where R: Read {
                try!(read_u32(read));
                $( let $attr_name = try!($imp_fn(read)); )* ;
                $(
                    let $hash_name;
                    {
                        let hash_val = try!(read_hash(read));
                        $hash_name = try!(self.get(&hash_val));
                    }
                )*
                Ok($model_name{
                    $($attr_name: $attr_name,)*
                    $($hash_name: $hash_name),*
                    })
            }

            fn store_childs(&self, hashable: &$model_name) -> Result<(), HashIOError1> {
                $( try!(self.put(&hashable.$hash_name)); )*
                Ok(())
            }

            fn store_hashable<W>(&self, hashable: &$model_name, write: &mut W) -> Result<(), HashIOError1>
                    where W: Write {
                try!(hashable.write_to(write));
                Ok(())
            }
        }
    }
}



#[cfg(test)]
mod test {
    use super::super::hash::*;
    use super::super::hashio_1::*;
    use super::super::io::*;
    use std::io::{Read, Write};

    #[derive(Debug)]
    struct A {
        a: u8,
        b: String
    }

    hashable_for_debug!(A);

    impl HashIOImpl1<A> for HashIO1 {
        fn receive_hashable<R>(&self, read: &mut R) -> Result<A, HashIOError1>
                    where R: Read {
            let a = try!(read_u8(read));
            let b_hash = try!(read_hash(read));
            let b = try!(self.get(&b_hash));
            Ok(A{a: a, b: b})
        }

        fn store_childs(&self, hashable: &A) -> Result<(), HashIOError1> {
            self.put(&hashable.b)
        }

        fn store_hashable<W>(&self, hashable: &A, write: &mut W) -> Result<(), HashIOError1>
                    where W: Write {
            try!(write_u8(hashable.a, write));
            try!(write_hash(&hashable.b.as_hash(), write));
            Ok(())
        }
    }

    #[test]
    fn simple_test() {
        let hash_io = HashIO1::new("unittest/savetest1".to_string());
        let a_hash;
        {
            let a = A {
                a: 10,
                b: "Test".to_string()
            };
            a_hash = a.as_hash();
            hash_io.put(&a).unwrap();
        }

        let a2: A = hash_io.get(&a_hash).unwrap();
        assert_eq!(10, a2.a);
        assert_eq!("Test".to_string(), a2.b);
    }
}



#[cfg(test)]
mod test2 {
    use super::super::hash::*;
    use super::super::hashio_1::*;
    use super::super::io::*;
    use std::io::{Read, Write};
    use std::io;

    tbd_model_1!(A, [
        [a: u8, write_u8, read_u8]
     ], [
        [b: String]
     ]);

    tbd_model_1!(B, [  ]
        , [
            [foo: String],
            [bar: A],
            [foobar: A]
        ]
    );

    #[test]
    fn simple_test() {
        let hash_io = HashIO1::new("unittest/savetest1".to_string());
        let my_hash;
        let b = B {
            foo: "Foo".to_string(),
            bar: A {
                a: 20,
                b: "Foo".to_string()
            },
            foobar: A {
                a: 30,
                b: "baz".to_string()
            }
        };
        my_hash = b.as_hash();
        hash_io.put(&b).unwrap();

        let b_read: B = hash_io.get(&my_hash).unwrap();
        assert_eq!(b, b_read);
        assert_eq!(b.foo, b_read.foo);
        assert_eq!(b.foobar, b_read.foobar);
    }
}


impl<T, U> Writable for BTreeMap<T, U>
    where T: Writable, U: Writable, T: Hashable, U: Hashable {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
        try!(write_u32(0, write));
        try!(write_u32(self.len() as u32, write));
        let mut size: usize = 0;
        for (key, value) in self {
            size += try!(write_hash(&key.as_hash(), write));
            size += try!(write_hash(&value.as_hash(), write));
        }
        Ok(size)
    }
}

impl<T, U> Hashable for BTreeMap<T, U>
    where BTreeMap<T, U>: Writable {
    fn as_hash(&self) -> Hash {
        self.writable_to_hash()
    }
}

impl<T, U> HashIOImpl1<BTreeMap<T, U>> for HashIO1
    where HashIO1: HashIOImpl1<T>,
          HashIO1: HashIOImpl1<U>,
          T: Writable, U: Writable,
          T: Hashable, U: Hashable,
          T: Ord {
    fn store_hashable<W>(&self, hashable: &BTreeMap<T, U>, write: &mut W) -> Result<(), HashIOError1>
        where W: Write {
        for (key, value) in hashable {
            try!(self.put(key));
            try!(self.put(value));
        }
        try!(hashable.write_to(write));
        Ok(())
    }

    fn receive_hashable<R>(&self, read: &mut R) -> Result<BTreeMap<T, U>, HashIOError1>
        where R: Read {
        let mut res = BTreeMap::<T, U>::new();
        try!(read_u32(read));
        let entries = try!(read_u32(read));
        for _ in 0..entries {
            let key_hash = try!(read_hash(read));
            let value_hash = try!(read_hash(read));
            let key = try!(self.get(&key_hash));
            let value = try!(self.get(&value_hash));
            res.insert(key, value);
        }
        Ok(res)
    }
}

#[cfg(test)]
mod btreemaptest {
    use super::super::hash::*;
    use super::super::hashio_1::*;
    use super::super::io::*;
    use std::io::{Read, Write};
    use std::io;
    use std::collections::BTreeMap;

    tbd_model_1!(A, [], [
        [a: BTreeMap<String, String>]
    ]);

    #[test]
    fn test() {
        let hash_io = HashIO1::new("unittest/btreemaptest1".to_string());
        let mut a = A { a: BTreeMap::new() };
        a.a.insert("one".to_string(), "1".to_string());
        a.a.insert("two".to_string(), "2".to_string());
        let hash = a.as_hash();
        hash_io.put(&a).unwrap();
        let a_2 = hash_io.get(&hash).unwrap();
        assert_eq!(a, a_2);
    }
}

impl<T> Writable for Vec<T>
    where T: Writable, T: Hashable {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
        try!(write_u32(0, write));
        try!(write_u32(self.len() as u32, write));
        let mut size: usize = 0;
        for value in self {
            size += try!(write_hash(&value.as_hash(), write));
        }
        Ok(size)
    }
}

impl<T> Hashable for Vec<T>
    where Vec<T>: Writable {
    fn as_hash(&self) -> Hash {
        self.writable_to_hash()
    }
}

impl<T> HashIOImpl1<Vec<T>> for HashIO1
    where HashIO1: HashIOImpl1<T>,
          T: Writable, T: Hashable {
    fn store_hashable<W>(&self, hashable: &Vec<T>, write: &mut W) -> Result<(), HashIOError1>
        where W: Write {
        for value in hashable {
            try!(self.put(value));
        }
        try!(hashable.write_to(write));
        Ok(())
    }

    fn receive_hashable<R>(&self, read: &mut R) -> Result<Vec<T>, HashIOError1>
        where R: Read {
        let mut res = Vec::<T>::new();
        try!(read_u32(read));
        let entries = try!(read_u32(read));
        for _ in 0..entries {
            let value_hash = try!(read_hash(read));
            let value = try!(self.get(&value_hash));
            res.push(value);
        }
        Ok(res)
    }
}
