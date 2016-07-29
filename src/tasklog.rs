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
use self::time::{Tm, now};
use std::fmt;
use std::error;

#[derive(Debug)]
pub enum TaskLogError {
    LogError(LogError),
    NoState
}

impl fmt::Display for TaskLogError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TaskLogError::LogError(ref err) => err.fmt(f),
            TaskLogError::NoState => write!(f, "State is none")
        }
    }
}

impl error::Error for TaskLogError {
    fn description(&self) -> &str {
        match *self {
            TaskLogError::LogError(ref err) => err.description(),
            TaskLogError::NoState => "State is none"
        }
    }
}

impl From<LogError> for TaskLogError {
    fn from(err: LogError) -> TaskLogError {
        TaskLogError::LogError(err)
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
    pub fn new(path: String) -> TaskLog {
        TaskLog {
            log: IOLog::new(path),
            state: None
        }
    }

    pub fn load_head(&mut self) -> Result<(), TaskLogError> {
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

    pub fn store_state(&mut self, action: TaskAction) -> Result<(), TaskLogError> {
        match &self.state {
            &None => Err(TaskLogError::NoState),
            &Some(ref state) => {
                let tm = now();
                let entry = TaskLogEntry {
                    timestamp: tm,
                    action: action,
                    state: state.clone()
                };
                self.log.push(entry);
                Ok(())
            }
        }
    }
}

impl TaskStatTrait for TaskLog {
    fn add_active_task(&mut self, title: String, description: String,
                       factor: f32, due_days: i16) -> Option<ActiveTask> {
        // Borrow mutable state
        self.state.as_mut()
            // Unwrap the state, return None otherwise
            .and_then(| state |
                // Run the original function
                state.add_active_task(title, description, factor, due_days)
                    // And return the ActiveTask Option, return None on error
                    .and_then(| a_task | Some(a_task)))
            // Unwrap tha ActiveTask again, return None otherwise
            .and_then(| a_task |
                // Save the task
                self.store_state(TaskAction::ScheduleTask(a_task.clone()))
                    // Convert the result to an Option, discarding the error
                    .ok()
                    // Return the ActiveTask action, return None on an error
                    .and(Some(a_task)))
    }

    fn add_pooled_task(&mut self, title: String, description: String,
                       factor: f32, propability: f32,
                       cool_down: i16, due_days: i16) -> Option<PooledTask> {
        // Borrow mutable state
        self.state.as_mut()
            // Unwrap the state, return None otherwise
            .and_then(| state |
                          // Run the original function
                          state.add_pooled_task(title, description, factor,
                                                propability, cool_down, due_days)
                              // And return the ActiveTask Option, return None on error
                              .and_then(| p_task | Some(p_task)))
            // Unwrap tha ActiveTask again, return None otherwise
            .and_then(| p_task |
                          // Save the task
                          self.store_state(TaskAction::PoolTask(p_task.clone()))
                              // Convert the result to an Option, discarding the error
                              .ok()
                              // Return the ActiveTask action, return None on an error
                              .and(Some(p_task)))
    }

    fn activate<R: rand::Rng>(&mut self, rng: &mut R) -> Option<Vec<ActiveTask>> {
        // Borrow mutable state
        self.state.as_mut()
            // Unwrap the state, return None otherwise
            .and_then(| state |
                          // Run the original function
                          state.activate(rng)
                              // And return the ActiveTask Option, return None on error
                              .and_then(| a_tasks | Some(a_tasks)))
            // Unwrap tha ActiveTask again, return None otherwise
            .and_then(| a_tasks |
                          // Save the task
                          self.store_state(TaskAction::ActivateTask(a_tasks.clone()))
                              // Convert the result to an Option, discarding the error
                              .ok()
                              // Return the ActiveTask action, return None on an error
                              .and(Some(a_tasks)))
    }

    fn mark_done(&mut self, title: String) -> bool {
        self.state.as_mut()
            .and_then(| state |
                if state.mark_done(title.clone()) {
                    state.active.get(&title).cloned()
                } else {
                    None
                }
            ).and_then(| a_task | {
                self.store_state(TaskAction::CompleteTask(a_task)).ok()
            }).is_some()
    }

    fn all_actives(&self) -> Option<Vec<ActiveTask>> {
        self.state.as_ref().and_then(| state | {
            state.all_actives()
        })
    }

    fn all_pooled(&self) -> Option<Vec<PooledTask>> {
        self.state.as_ref().and_then(| state | {
            state.all_pooled()
        })
    }
}