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

extern crate crypto;
extern crate byteorder;


use std::io::{Read, Write};
use std::{io, error, fmt};
use hash::*;
use io::*;
use std::fs::{File, create_dir_all};



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

pub struct HashIO {
    pub base_path: String
}

pub trait HashIOImpl<T: Hashable> {
    fn receive_hashable<R>(&self, read: &mut R) -> Result<T, HashIOError>
        where R: Read;
    fn store_hashable<W>(&self, hashable: &T, write: &mut W) -> Result<(), HashIOError>
        where W: Write;

    fn store_childs(&self, _: &T) -> Result<(), HashIOError> {
        Ok(())
    }
}

impl HashIO {
    pub fn new(path: String) -> HashIO {
        HashIO {
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

    pub fn get<T>(&self, hash: &Hash) -> Result<T, HashIOError>
                where HashIO: HashIOImpl<T>,
                      T: Hashable {
        let filename = self.filename_for_hash(hash);
        let mut read = try!(File::open(filename));
        let result : T = try!(self.receive_hashable(&mut read));
        Ok(result)
    }

    pub fn put<T>(&self, hashable: &T) -> Result<(), HashIOError>
                where HashIO: HashIOImpl<T>,
                      T: Hashable {
        try!(self.store_childs(hashable));
        let hash = hashable.as_hash();
        let filename = self.filename_for_hash(&hash);
        let dir = self.directory_for_hash(&hash);
        try!(create_dir_all(dir));
        let mut write = try!(File::create(filename));
        try!(self.store_hashable(hashable, &mut write));
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

impl HashIOImpl<String> for HashIO {
    fn store_hashable<W>(&self, hashable: &String, write: &mut W) -> Result<(), HashIOError>
                    where W: Write {
        try!(hashable.write_to(write));
        Ok(())
    }

    fn receive_hashable<R>(&self, read: &mut R) -> Result<String, HashIOError>
                    where R: Read {
        let len = try!(read_u32(read));
        let bytes = try!(read_bytes(read, len as usize));
        let res = try!(String::from_utf8(bytes).map_err(|x| HashIOError::ParseError(Box::new(x))));
        Ok(res)
    }
}

macro_rules! tbd_model {
    ($model_name:ident,
            [ $( [$attr_name:ident : $attr_type:ty, $exp_fn:ident, $imp_fn:ident ] ),* ] ,
            [ $( [$hash_name:ident : $hash_type:ty] ),* ]) => {

        #[derive(Debug, Clone, PartialEq)]
        struct $model_name {
            $($attr_name: $attr_type,),*
            $($hash_name: $hash_type),*
        }

        impl Writable for $model_name {
            fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
                let mut size = 0;
                size += $( try!($exp_fn(self.$attr_name, write)); )*
                $(
                    try!(write_hash(&self.$hash_name.as_hash(), write));
                    size += 32;
                )*
                Ok(size)
            }
        }

        hashable_for_writable!($model_name);

        impl HashIOImpl<$model_name> for HashIO {
            fn receive_hashable<R>(&self, read: &mut R) -> Result<$model_name, HashIOError>
                    where R: Read {
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

            fn store_childs(&self, hashable: &$model_name) -> Result<(), HashIOError> {
                $( try!(self.put(&hashable.$hash_name)); )*
                Ok(())
            }

            fn store_hashable<W>(&self, hashable: &$model_name, write: &mut W) -> Result<(), HashIOError>
                    where W: Write {
                try!(hashable.write_to(write));
                Ok(())
            }
        }
    }
}

tbd_model!(A, [
        [a: u8, write_u8, read_u8]
    ], [
        [c: String]
    ]);


#[cfg(test)]
mod test {
    use super::super::hash::*;
    use super::super::hashio::*;
    use super::super::io::*;
    use std::io::{Read, Write};

    #[derive(Debug)]
    struct A {
        a: u8,
        b: String
    }

    hashable_for_debug!(A);

    impl HashIOImpl<A> for HashIO {
        fn receive_hashable<R>(&self, read: &mut R) -> Result<A, HashIOError>
                    where R: Read {
            let a = try!(read_u8(read));
            let b_hash = try!(read_hash(read));
            let b = try!(self.get(&b_hash));
            Ok(A{a: a, b: b})
        }

        fn store_childs(&self, hashable: &A) -> Result<(), HashIOError> {
            self.put(&hashable.b)
        }

        fn store_hashable<W>(&self, hashable: &A, write: &mut W) -> Result<(), HashIOError>
                    where W: Write {
            try!(write_u8(hashable.a, write));
            try!(write_hash(&hashable.b.as_hash(), write));
            Ok(())
        }
    }

    #[test]
    fn simple_test() {
        let hash_io = HashIO::new("savetest".to_string());
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
    use super::super::hashio::*;
    use super::super::io::*;
    use std::io::{Read, Write};
    use std::io;

    tbd_model!(A, [
        [a: u8, write_u8, read_u8]
     ], [
        [b: String]
     ]);

    tbd_model!(B, [  ]
        , [
            [foo: String],
            [bar: A],
            [foobar: A]
        ]
    );

    #[test]
    fn simple_test() {
        let hash_io = HashIO::new("savetest".to_string());
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