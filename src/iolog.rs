use hash::*;
use hashio::*;
use io::*;
use log::*;
use std::io;
use std::io::{Write, Read};

impl From<HashIOError> for LogError {
    fn from(_: HashIOError) -> LogError {
        LogError::Unknown
    }
}

pub struct IOLogItem<T>
        where T: Hashable,
              HashIO: HashIOImpl<T> {
    parent_hash: Hash,
    item: T
}

impl<T> Writable for IOLogItem<T>
        where T: Hashable,
              HashIO: HashIOImpl<T> {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
        let mut size = 0;
        size += try!(write_hash(&self.parent_hash, write));
        try!(write_hash(&self.item.as_hash(), write));
        size += 32;
        Ok(size)
    }
}
impl<T> Hashable for IOLogItem<T>
        where T: Hashable,
              HashIO: HashIOImpl<T> {
    fn as_hash(&self) -> Hash {
        self.writable_to_hash()
    }
}

impl<T> HashIOImpl<IOLogItem<T>> for HashIO
        where T: Hashable,
              HashIO: HashIOImpl<T> {
    fn receive_hashable<R>(&self, read: &mut R) -> Result<IOLogItem<T>, HashIOError>
            where R: Read {
        let parent_hash = try!(read_hash(read));
        let item;
        {
            let hash_val = try!(read_hash(read));
            item = try!(self.get(&hash_val));
        }
        Ok(IOLogItem {
            parent_hash: parent_hash,
            item: item
        })
    }

    fn store_childs(&self, hashable: &IOLogItem<T>) -> Result<(), HashIOError> {
        try!(self.put(&hashable.item));
        Ok(())
    }

    fn store_hashable<W>(&self, hashable: &IOLogItem<T>, write: &mut W) -> Result<(), HashIOError>
            where W: Write {
        try!(hashable.write_to(write));
        Ok(())
    }
}

pub struct IOLog<T>
        where T: Hashable,
              HashIO: HashIOImpl<T> {
    pub head: Option<IOLogItem<T>>,
    pub hashio: HashIO
}



impl<T> Log for IOLog<T>
        where T: Hashable,
              HashIO: HashIOImpl<T> {
    type Item = T;

    /// Add new entry to the log
    fn push(&mut self, hashable: T) -> Hash {
        match self.hashio.put(&hashable) {
            Ok(_) => (),
            Err(_) => ()
        }
        let hash = hashable.as_hash();
        let new_head = IOLogItem {
            parent_hash: match &self.head {
                &Option::None => Hash::None,
                &Option::Some(ref parent_item) => parent_item.as_hash()
            },
            item: hashable
        };
        self.head = Some(new_head);
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
        let item: IOLogItem<T> = try!(self.hashio.get::<IOLogItem<T>>(&hash));
        Ok(match item.parent_hash {
            Hash::None => Option::None,
            _ => Option::Some(hash)
        })
    }

    /// Get the borrowed entry of the given hash
    ///
    /// # Errors
    /// Throws an error if an entry of the hash was not found.
    fn get(&self, hash: Hash) -> Result<Self::Item, LogError> {
        let item: IOLogItem<T> = try!(self.hashio.get::<IOLogItem<T>>(&hash));
        Ok(item.item)
    }
}

