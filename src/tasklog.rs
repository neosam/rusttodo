//! Task management combined with manipulation save logging.

extern crate crypto;
extern crate byteorder;
extern crate rand;
extern crate time;

use task::*;
use io::*;
use log::*;
use iolog::*;
use iolog_1::IOLog1;
use hashio::*;
use hash::*;
use std::io::{Write, Read};
use std::io;
use self::time::{Tm, now};
use std::fmt;
use std::error;
use hashio_1;
use hashio_1::*;
use std::iter::FromIterator;

#[derive(Debug)]
pub enum TaskLogError {
    TaskStatError(TaskStatError),
    IOError(io::Error),
    LogError(LogError),
    HashIOError(HashIOError),
    NoState

}

impl fmt::Display for TaskLogError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TaskLogError::TaskStatError(ref err) => write!(f, "TaskLogError::TaskStatError: {}", err),
            TaskLogError::IOError(ref err) => write!(f, "TaskLogError::IOError: {}", err),
            TaskLogError::LogError(ref err) => write!(f, "TaskLogError::LogError: {}", err),
            TaskLogError::HashIOError(ref err) => write!(f, "TaskLogError::HashIOError: {}", err),
            TaskLogError::NoState => write!(f, "TaskLogError::NoState")
        }
    }
}

impl error::Error for TaskLogError {
    fn description(&self) -> &str {
        match *self {
            TaskLogError::TaskStatError(ref err) => err.description(),
            TaskLogError::IOError(ref err) => err.description(),
            TaskLogError::LogError(ref err) => err.description(),
            TaskLogError::HashIOError(ref err) => err.description(),
            TaskLogError::NoState => "State is none"
        }
    }
}

impl From<LogError> for TaskLogError {
    fn from(err: LogError) -> TaskLogError {
        TaskLogError::LogError(err)
    }
}

impl From<TaskStatError> for TaskLogError {
    fn from(err: TaskStatError) -> TaskLogError {
        TaskLogError::TaskStatError(err)
    }
}

impl From<io::Error> for TaskLogError {
    fn from(err: io::Error) -> TaskLogError {
        TaskLogError::IOError(err)
    }
}



#[derive(Debug, Clone, PartialEq)]
pub enum TaskAction {
    ScheduleTask(ActiveTask),
    PoolTask(PooledTask),
    CompleteTask(ActiveTask),
    ActivateTask(Vec<ActiveTask>)
}

impl Writable for TaskAction {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
        let version = 1;
        let type_hash = TaskAction::type_hash();
        let mut size : usize = 0;
        size += try!(write_u32(version, write));
        size += try!(write_hash(&type_hash, write));
        match self {
            &TaskAction::ScheduleTask(ref a_task) => {
                size += try!(write_u8(1, write));
                size += try!(write_hash(&a_task.as_hash(), write));
            },
            &TaskAction::PoolTask(ref p_task) => {
                size += try!(write_u8(2, write));
                size += try!(write_hash(&p_task.as_hash(), write));
            },
            &TaskAction::CompleteTask(ref a_task) => {
                size += try!(write_u8(3, write));
                size += try!(write_hash(&a_task.as_hash(), write));
            },
            &TaskAction::ActivateTask(ref a_tasks) => {
                size += try!(write_u8(4, write));
                size += try!(write_hash(&a_tasks.as_hash(), write));
            }
        };
        Ok(size)
    }
}

impl Typeable for TaskAction {
    fn type_hash() -> Hash {
        let mut byte_gen: Vec<u8> = Vec::new();
        let id = String::from("TaskAction");
        let id_bytes = id.as_bytes();
        byte_gen.extend_from_slice(&*Hash::hash_bytes(id_bytes).get_bytes());
        let hash = Hash::hash_bytes(byte_gen.as_slice());
        hash
    }
}
impl Hashtype for TaskAction {}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskAction1 {
    ScheduleTask(ActiveTask1),
    PoolTask(PooledTask1),
    CompleteTask(ActiveTask1),
    ActivateTask(Vec<ActiveTask1>)
}

impl Writable for TaskAction1 {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
        let version = [0u8;4];
        let mut size : usize = 0;
        size += try!(write.write(&version));
        match self {
            &TaskAction1::ScheduleTask(ref a_task) => {
                size += try!(write_u8(1, write));
                size += try!(write_hash(&a_task.as_hash(), write));
            },
            &TaskAction1::PoolTask(ref p_task) => {
                size += try!(write_u8(2, write));
                size += try!(write_hash(&p_task.as_hash(), write));
            },
            &TaskAction1::CompleteTask(ref a_task) => {
                size += try!(write_u8(3, write));
                size += try!(write_hash(&a_task.as_hash(), write));
            },
            &TaskAction1::ActivateTask(ref a_tasks) => {
                size += try!(write_u8(4, write));
                size += try!(write_hash(&a_tasks.as_hash(), write));
            }
        };
        Ok(size)
    }
}

hashable_for_writable!(TaskAction);
hashable_for_writable!(TaskAction1);



impl HashIOImpl<TaskAction> for HashIO {
    fn store_hashable<W>(&self, hashable: &TaskAction, write: &mut W) -> Result<(), HashIOError>
                    where W: Write {
        match hashable {
            &TaskAction::ScheduleTask(ref a_task) => try!(self.put(a_task)),
            &TaskAction::PoolTask(ref p_task) => try!(self.put(p_task)),
            &TaskAction::CompleteTask(ref a_task) => try!(self.put(a_task)),
            &TaskAction::ActivateTask(ref a_tasks) => try!(self.put(a_tasks))
        }
        try!(hashable.write_to(write));
        Ok(())
    }

    fn receive_hashable<R>(&self, read: &mut R, _: &Hash) -> Result<TaskAction, HashIOError>
                    where R: Read {
        let version  = try!(read_u32(read));
        if version < 1 {
            return Err(HashIOError::VersionError(version))
        }
        let hash_type = try!(read_hash(read));
        if hash_type != TaskAction::type_hash() {
            return Err(HashIOError::TypeError(hash_type))
        }
        let action_type = try!(read_u8(read));
        let hash = try!(read_hash(read));
        let action = match action_type {
            1 => {
                let a_task: ActiveTask = try!(self.get(&hash));
                TaskAction::ScheduleTask(a_task)
            }
            2 => {
                let p_task: PooledTask = try!(self.get(&hash));
                TaskAction::PoolTask(p_task)
            }
            3 => {
                let a_task: ActiveTask = try!(self.get(&hash));
                TaskAction::CompleteTask(a_task)
            }
            4 => {
                let a_tasks: Vec<ActiveTask> = try!(self.get(&hash));
                TaskAction::ActivateTask(a_tasks)
            }
            _ => {
                return Err(HashIOError::Undefined(format!("Task Action id undefined: {}",
                                                          action_type)));
            }
        };
        Ok(action)
    }
}

impl HashIOImpl1<TaskAction1> for HashIO1 {
    fn store_hashable<W>(&self, hashable: &TaskAction1, write: &mut W) -> Result<(), HashIOError1>
        where W: Write {
        match hashable {
            &TaskAction1::ScheduleTask(ref a_task) => try!(self.put(a_task)),
            &TaskAction1::PoolTask(ref p_task) => try!(self.put(p_task)),
            &TaskAction1::CompleteTask(ref a_task) => try!(self.put(a_task)),
            &TaskAction1::ActivateTask(ref a_tasks) => try!(self.put(a_tasks))
        }
        try!(hashable.write_to(write));
        Ok(())
    }

    fn receive_hashable<R>(&self, read: &mut R) -> Result<TaskAction1, HashIOError1>
        where R: Read {
        let _ = try!(read_u32(read));
        let action_type = try!(read_u8(read));
        let hash = try!(read_hash(read));
        let action = match action_type {
            1 => {
                let a_task: ActiveTask1 = try!(self.get(&hash));
                TaskAction1::ScheduleTask(a_task)
            }
            2 => {
                let p_task: PooledTask1 = try!(self.get(&hash));
                TaskAction1::PoolTask(p_task)
            }
            3 => {
                let a_task: ActiveTask1 = try!(self.get(&hash));
                TaskAction1::CompleteTask(a_task)
            }
            4 => {
                let a_tasks: Vec<ActiveTask1> = try!(self.get(&hash));
                TaskAction1::ActivateTask(a_tasks)
            }
            _ => {
                return Err(HashIOError1::Undefined(format!("Task Action id undefined: {}",
                                                          action_type)));
            }
        };
        Ok(action)
    }
}

tbd_model!{
    TaskLogEntry {
        [timestamp: Tm, write_tm, read_tm]
    } {
        action: TaskAction,
        state: TaskStat
    } { task_log_entry_convert }
}
tbd_model_1!(TaskLogEntry1, [
    [timestamp: Tm, write_tm, read_tm]
], [
    [action: TaskAction1],
    [state: TaskStat1]
]);
impl From<TaskAction1> for TaskAction {
    fn from(f: TaskAction1) -> TaskAction {
        match f {
            TaskAction1::ScheduleTask(a_task) =>
                TaskAction::ScheduleTask(ActiveTask::from(a_task)),
            TaskAction1::PoolTask(p_task) =>
                TaskAction::PoolTask(PooledTask::from(p_task)),
            TaskAction1::CompleteTask(a_task) =>
                TaskAction::CompleteTask(ActiveTask::from(a_task)),
            TaskAction1::ActivateTask(a_tasks) => {
                let mut res: Vec<ActiveTask> = Vec::new();
                for item in a_tasks {
                    res.push(ActiveTask::from(item));
                }
                TaskAction::ActivateTask(res)
            }
        }
    }
}
impl From<TaskLogEntry1> for TaskLogEntry {
    fn from(f: TaskLogEntry1) -> TaskLogEntry {
        TaskLogEntry {
            timestamp: f.timestamp,
            action: TaskAction::from(f.action),
            state: TaskStat::from(f.state)
        }
    }
}
tbd_old_convert_gen!(task_log_entry_convert, TaskLogEntry1, TaskLogEntry);

pub struct TaskLog {
    pub log: IOLog<TaskLogEntry>,
    pub state: TaskStat
}

impl TaskLog {
    pub fn new(path: String) -> TaskLog {
        print!("Create new TaskLog\n");
        let mut task_log = TaskLog {
            log: IOLog::<TaskLogEntry>::new(path.clone()),
            state: TaskStat::empty_task_stat()
        };
        if task_log.log.head.is_none() {
            print!("Fallback to old version\n");
            let log1 = IOLog1::<TaskLogEntry1>::new(path);
            print!("Old log loaded, collect hashes\n");
            let mut hashes = Vec::from_iter(LogIteratorHash::from_log(&log1));
            hashes.reverse();
            print!("Rewrite log");
            for hash in hashes {
                print!("Rewrite hash: {}\n", hash.as_string());
                let entry1: TaskLogEntry1 = match log1.get(hash) {
                    Ok(x) => x,
                    Err(err) => {
                        print!("Error loading hash {}: {}", hash.as_string(), err);
                        break
                    }
                };
                let entry: TaskLogEntry = TaskLogEntry::from(entry1);
                task_log.log.push(entry);
            }
        }
        if task_log.log.head.is_none() {
            print!("Fallback load failed");
        }
        task_log
    }

    pub fn load_head(&mut self) -> Result<(), TaskLogError> {
        let stat_hash = self.log.head_hash();
        match stat_hash {
            None => self.state = TaskStat::empty_task_stat(),
            Some(hash) => {
                let entry = try!(self.log.get(hash));
                self.state = entry.state
            }
        };
        Ok(())
    }

    pub fn store_state(&mut self, action: TaskAction) -> Result<(), TaskLogError> {
        let tm = now();
        let entry = TaskLogEntry {
            timestamp: tm,
            action: action,
            state: self.state.clone()
        };
        self.log.push(entry);
        Ok(())
    }
}




impl TaskStatTrait for TaskLog {
    type Error = TaskLogError;

    fn add_active_task(&mut self, title: String, description: String,
                       factor: f32, due_days: i16) -> Result<ActiveTask, Self::Error> {
        self.state.update_ref_tm();
        let a_task = try!(self.state.add_active_task(title, description, factor, due_days));
        try!(self.store_state(TaskAction::ScheduleTask(a_task.clone())));
        Ok(a_task)
    }

    fn add_pooled_task(&mut self, title: String, description: String,
                       factor: f32, propability: f32,
                       cool_down: i16, due_days: i16) -> Result<PooledTask, Self::Error> {
        self.state.update_ref_tm();
        let p_task = try!(self.state.add_pooled_task(title, description, factor,
                                propability, cool_down, due_days));
        try!(self.store_state(TaskAction::PoolTask(p_task.clone())));
        Ok(p_task)
    }

    fn activate<R: rand::Rng>(&mut self, rng: &mut R) -> Result<Vec<ActiveTask>, Self::Error> {
        self.state.update_ref_tm();
        let a_tasks = try!(self.state.activate(rng));
        try!(self.store_state(TaskAction::ActivateTask(a_tasks.clone())));
        Ok(a_tasks)
    }

    fn mark_done(&mut self, title: String) -> Result<ActiveTask, Self::Error> {
        self.state.update_ref_tm();
        let a_task = try!(self.state.mark_done(title));
        try!(self.store_state(TaskAction::CompleteTask(a_task.clone())));
        Ok(a_task)
    }

    fn all_actives(&self) -> Result<Vec<ActiveTask>, Self::Error> {
        let a_tasks = try!(self.state.all_actives());
        Ok(a_tasks)
    }

    fn all_pooled(&self) -> Result<Vec<PooledTask>, Self::Error> {
        let p_tasks = try!(self.state.all_pooled());
        Ok(p_tasks)
    }
}