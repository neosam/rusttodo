//! Task management combined with manipulation save logging.

extern crate crypto;
extern crate byteorder;
extern crate rand;
extern crate time;

use task::*;
use io::*;
use log::*;
use iolog::*;
use hashio::*;
use hash::*;
use std::io::{Write, Read};
use std::io;
use self::time::Tm;

#[derive(Debug, Clone, PartialEq)]
pub enum TaskAction {
    ScheduleTask(ActiveTask),
    PoolTask(PooledTask),
    CompleteTask(ActiveTask),
    ActivateTask(Vec<ActiveTask>)
}

impl Writable for TaskAction {
    fn write_to<W: Write>(&self, write: &mut W) -> Result<usize, io::Error> {
        let version = [0u8;4];
        let mut size : usize = 0;
        size += try!(write.write(&version));
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

hashable_for_writable!(TaskAction);

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

    fn receive_hashable<R>(&self, read: &mut R) -> Result<TaskAction, HashIOError>
                    where R: Read {
        let _  = try!(read_u32(read)); // version
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


tbd_model!(TaskLogEntry, [
    [timestamp: Tm, write_tm, read_tm]
], [
    [action: TaskAction],
    [state: TaskStat]
]);

pub struct TaskLog {
    pub log: IOLog<TaskLogEntry>,
    pub state: Option<TaskStat>
}

impl TaskLog {
    pub fn load_head(&mut self) -> Result<(), LogError> {
        let stat_hash = self.log.head_hash();
        match stat_hash {
            None => self.state = None,
            Some(hash) => {
                let entry = try!(self.log.get(hash));
                self.state = Some(entry.state)
            }
        };
        Ok(())
    }
}

