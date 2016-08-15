//! Old LogIO implementation for backward compatibility

extern crate time;


use hash::*;
use hashio_1::*;
use io::*;
use logger::*;
use std::io;
use std::io::{Write, Read};
use std::fs::{File};
use self::time::{now};


pub struct IOLogItem1<T>
    where T: Hashable,
          HashIO1: HashIOImpl1<T> {
    pub parent_hash: Hash,
    pub item: T
}

impl<T> Writable for IOLogItem1<T>
    where T: Hashable,
          HashIO1: HashIOImpl1<T> {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
        let mut size = 0;
        size += try!(write_hash(&self.parent_hash, write));
        try!(write_hash(&self.item.as_hash(), write));
        size += 32;
        Ok(size)
    }
}
impl<T> Hashable for IOLogItem1<T>
    where T: Hashable,
          HashIO1: HashIOImpl1<T> {
    fn as_hash(&self) -> Hash {
        self.writable_to_hash()
    }
}

impl From<HashIOError1> for LogError {
    fn from(err: HashIOError1) -> LogError {
        LogError::CustomError(format!("HashIOError1: {}", err))
    }
}

impl<T> HashIOImpl1<IOLogItem1<T>> for HashIO1
    where T: Hashable,
          HashIO1: HashIOImpl1<T> {
    fn receive_hashable<R>(&self, read: &mut R) -> Result<IOLogItem1<T>, HashIOError1>
        where R: Read {
        let parent_hash = try!(read_hash(read));
        let item;
        {
            let hash_val = try!(read_hash(read));
            item = try!(self.get(&hash_val));
        }
        Ok(IOLogItem1 {
            parent_hash: parent_hash,
            item: item
        })
    }

    fn store_childs(&self, hashable: &IOLogItem1<T>) -> Result<(), HashIOError1> {
        try!(self.put(&hashable.item));
        Ok(())
    }

    fn store_hashable<W>(&self, hashable: &IOLogItem1<T>, write: &mut W) -> Result<(), HashIOError1>
        where W: Write {
        try!(hashable.write_to(write));
        Ok(())
    }


}

pub struct IOLog1<T>
    where T: Hashable,
          HashIO1: HashIOImpl1<T> {
    pub head: Option<IOLogItem1<T>>,
    pub hashio: HashIO1
}

impl<T> IOLog1<T>
    where T: Hashable,
          HashIO1: HashIOImpl1<T> {
    pub fn write_head(&self) -> Result<(), io::Error> {
        if self.head.is_some() {
            let now = time::now();
            let hashio = &self.hashio;
            let timestamp = format!("{}/head-{}", hashio.base_path, now.rfc3339());
            let hash = self.head.as_ref().unwrap().as_hash();
            let filename = format!("{}/head", hashio.base_path);
            let mut file = try!(File::create(filename));
            try!(write_hash(&hash, &mut file));
            let mut backup = try!(File::create(timestamp));
            try!(write_hash(&hash, &mut backup));
        }
        Ok(())
    }
}

impl<T> Log for IOLog1<T>
    where T: Hashable,
          HashIO1: HashIOImpl1<T> {
    type Item = T;

    /// Add new entry to the log
    fn push(&mut self, hashable: T) -> Hash {
        let new_head = IOLogItem1 {
            parent_hash: match &self.head {
                &Option::None => Hash::None,
                &Option::Some(ref parent_item) => parent_item.as_hash()
            },
            item: hashable
        };
        let parent_hash = new_head.parent_hash.clone();
        match self.hashio.put::<IOLogItem1<T>>(&new_head) {
            Ok(_) => (),
            Err(_) => return Hash::None
        }
        let hash = new_head.as_hash();
        self.head = Some(new_head);
        match self.write_head() {
            Ok(_) => (),
            Err(_) => { return Hash::None }
        };
        if hash == parent_hash {
            warn!("hash equals parent hash\n");
        }
        hash
    }


    /// Head hash
    fn head_hash(&self) -> Option<Hash> {
        match &self.head {
            &Option::None => Option::None,
            &Option::Some(ref item) => Some(item.as_hash())
        }
    }

    /// Get the parent hash of the given hash.
    ///
    /// If the given hash is the first entry without a successor, it returns
    /// None, otherwise it returns the hash wrapped in Option::Some.
    ///
    /// # Errors
    /// Throws an error if an entry of the hash was not found.
    fn parent_hash(&self, hash: Hash) -> Result<Option<Hash>, LogError> {
        let item: IOLogItem1<T> = try!(self.hashio.get::<IOLogItem1<T>>(&hash));
        if item.parent_hash == hash {
            warn!("parent_hash detected redundancy\n");
        }
        let res = Ok(match item.parent_hash {
            Hash::None => Option::None,
            _ => Option::Some(item.parent_hash)
        });
        res
    }

    /// Get the borrowed entry of the given hash
    ///
    /// # Errors
    /// Throws an error if an entry of the hash was not found.
    fn get(&self, hash: Hash) -> Result<Self::Item, LogError> {
        let item: IOLogItem1<T> = try!(self.hashio.get::<IOLogItem1<T>>(&hash));
        Ok(item.item)
    }

    // Set defferent head
    fn reset_head(&mut self, hash: &Hash) -> Result<(), LogError> {
        let item: IOLogItem1<T> = try!(self.hashio.get::<IOLogItem1<T>>(&hash));
        self.head = Some(item);
        Ok(())
    }
}

impl<T> IOLog1<T>
    where T: Hashable,
          HashIO1: HashIOImpl1<T> {
    pub fn new(path: String) -> IOLog1<T> {
        let hashio = HashIO1::new(path.clone());
        let filename = format!("{}/head", path.clone());
        let hash = match File::open(filename) {
            Ok(mut file) => read_hash(&mut file).unwrap_or(Hash::None),
            Err(_) => Hash::None
        };
        let head = match hash {
            Hash::None => Option::None,
            _ => hashio.get::<IOLogItem1<T>>(&hash).ok()
        };
        IOLog1 {
            head: head,
            hashio: HashIO1::new(path)
        }
    }
}


#[cfg(test)]
mod test {
    use super::super::hash::*;
    use super::super::io::*;
    use super::super::logger::*;
    use super::*;
    use std::io::{Read, Write};
    use std::io;
    use std::fs::remove_dir_all;
    use super::super::hashio_1::*;

    tbd_model_1!(A, [
            [a: u8, write_u8, read_u8]
         ], [
            [b: String]
         ]);

    #[test]
    fn test() {
        remove_dir_all("unittest/logtest1").ok();
        let mut log = IOLog1::<A>::new("unittest/logtest1".to_string());
        // make sure the log is empty
        assert_eq!(None, log.head_hash());

        let one = A { a: 1, b: "one".to_string() };
        let two = A { a: 2, b: "two".to_string() };
        let hash_one = log.push(one.clone());
        let hash_two = log.push(two.clone());

        print!("Hash written: {}\n", hash_one.as_string());
        print!("Hash written: {}\n", hash_two.as_string());
        let one_ref: A = log.get(hash_one).unwrap();
        let two_ref: A = log.get(hash_two).unwrap();
        assert_eq!(one, one_ref);
        assert_eq!(two, two_ref);

        // Verify if reloading works correcty
        println!("Verify reloading\n");
        let log2 = IOLog1::<A>::new("unittest/logtest1".to_string());
        let two_ref2: A = log.get(log2.head_hash().unwrap()).unwrap();
        assert_eq!(two, two_ref2);

        println!("Log3");
        let log3 = IOLog1::<A>::new("unittest/logtest1".to_string());
        assert_eq!(Ok(Some(hash_one)), log3.parent_hash(hash_two));

        let mut hash_iter = LogIteratorHash::from_log(&log3);
        print!("Hash two\n");
        assert_eq!(Some(hash_two), hash_iter.next());
        print!("Hash one\n");
        assert_eq!(Some(hash_one), hash_iter.next());
        assert_eq!(None, hash_iter.next());

        let mut iter = LogIteratorRef::from_log(&log3);
        assert_eq!(Some(two), iter.next());
        assert_eq!(Some(one), iter.next());
        assert_eq!(None, iter.next());
    }
}