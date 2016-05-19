//! Task and logging management

extern crate crypto;
extern crate byteorder;
extern crate rand;
extern crate time;

use task::*;

pub enum TaskAction {
    ScheduleTask(ActiveTask),
    PoolTask(PooledTask),
    CompleteTask(ActiveTask),
    ActivateTask(Vec<ActiveTask>)
}

