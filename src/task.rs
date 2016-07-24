//! Task management library
//!
//! This is the core tbd library.  Features are:
//! * Adding tasks with a deadline
//! * Adding pooled task which are randomly picked.
//! * Mark task as completed.
//!
//! # Examples
//! ```
//! extern crate tbd;
//! use tbd::task::*;
//!
//! fn main() {
//!     // Create main task management object
//!     let mut task_stat = TaskStat::empty_task_stat();
//!
//!     // Add an active task
//!     task_stat.add_active_task(
//!         // Task title
//!         "A task".to_string(),
//!         // More detailed task description
//!         "A more detailed description of the task".to_string(),
//!         // Importance factor
//!         1.0,
//!         // Task deadline is in three days
//!         3
//!     );
//!
//!     // Add a pooled task
//!     task_stat.add_pooled_task(
//!         // Task title
//!         "Pooled task".to_string(),
//!         // A more detailed description
//!         "A description for the pooled task".to_string(),
//!         // Importance factor
//!         1.0,
//!         // Propability the task is picked (0 = never, 1 = always)
//!         0.5,
//!         // Never pick this task three days until it's finished
//!         3,
//!         // Have five days to complete the task after it was picked
//!         5
//!     );
//!
//!     // Should have the first task as active task
//!     assert_eq!("A task", task_stat.all_actives().unwrap()[0].task.title);
//!     // Should also have the second task as pooled task
//!     assert_eq!("Pooled task", task_stat.all_pooled().unwrap()[0].task.title);
//!
//!     // Mark the active task as completed
//!     assert_eq!(true, task_stat.mark_done("A task".to_string()));
//!     // Method returns false if task was not found
//!     assert_eq!(false, task_stat.mark_done("Foo".to_string()));
//!     // "A task" is now removed
//!     assert_eq!(false, task_stat.mark_done("A task".to_string()));
//!
//!     // Active tasks should be empty now
//!     assert_eq!(0, task_stat.all_actives().unwrap().len());
//! }
//! ```

//#![warn(missing_docs)]

extern crate time;
extern crate rand;

use self::time::{Duration, Tm};
use std::collections::BTreeMap;
use io::*;
use hashio::*;
use std::io;
use hash::*;
use std::io::{Read, Write};

/// Base task type
tbd_model!(Task, [
        [factor: f32, write_f32, read_f32]
    ], [
        [title: String],
        [description: String]
    ]);



/// A task which got activated.
tbd_model!(ActiveTask, [
        [start: Tm, write_tm, read_tm],
        [due: Tm, write_tm, read_tm]
    ], [
        [task: Task]
    ]);


/// A task which is about to get activated
tbd_model!(PooledTask, [
        [propability: f32, write_f32, read_f32],
        [cool_down: i16, write_i16, read_i16],
        [due_days: i16, write_i16, read_i16],
        [cooling_until: Tm, write_tm, read_tm]
    ], [
        [task: Task]
    ]);



/// Overall state of the tasks
tbd_model!(TaskStat, [
        [ref_tm: Tm, write_tm, read_tm]
    ], [
        [active: BTreeMap<String, ActiveTask>],
        [pool: BTreeMap<String, PooledTask>]
    ]);



impl PooledTask {
    fn title_string(&self) -> String {
        self.task.title.to_string()
    }
}

impl ActiveTask {
    fn title_string(&self) -> String {
        self.task.title.to_string()
    }
}

pub trait TaskStatTrait {
    fn add_active_task(&mut self, title: String, description: String,
                       factor: f32, due_days: i16) -> Option<ActiveTask>;
    fn add_pooled_task(&mut self, title: String, description: String,
                       factor: f32, propability: f32,
                       cool_down: i16, due_days: i16) -> Option<PooledTask>;
    fn activate<R: rand::Rng>(&mut self, rng: &mut R) -> Option<Vec<ActiveTask>>;
    fn mark_done(&mut self, title: String) -> bool;
    fn all_actives(&self) -> Option<Vec<ActiveTask>>;
    fn all_pooled(&self) -> Option<Vec<PooledTask>>;
}

/// Floor to the day if tm and remove time zone information
///
/// This is because tasks are based on days by default
fn floor_tm_day(tm: &mut time::Tm) {
    // Remove hours and everything below
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    tm.tm_nsec = 0;

    // Remove daylight saving time and time zone information
    tm.tm_isdst = -1;
    tm.tm_utcoff = 0;
}

/// Task stat implementation
impl TaskStat {
    /// Generate a new and empty task stat
    pub fn empty_task_stat() -> TaskStat {
        TaskStat {
            active: BTreeMap::new(),
            pool: BTreeMap::new(),
            ref_tm: time::now()
        }
    }


    fn pick_random_from_pool<R: rand::Rng>(&self, rng: &mut R) -> Vec<&PooledTask>{
        let mut result = Vec::new();
        for (_, p_task) in self.pool.iter() {
            let rand_num : f32 = rng.next_f32();
            if rand_num < p_task.propability {
                result.push(p_task);
            }
        }
        result
    }

    fn is_p_task_active(&self, p_task: &PooledTask) -> bool {
        self.active.contains_key(&p_task.title_string())
    }

    fn is_p_task_cooling_down(&self, p_task: &PooledTask) -> bool {
        let now = self.ref_tm;
        let task_limit = p_task.cooling_until;
        now < task_limit
    }

    fn can_activate(&self, p_task: &PooledTask) -> bool {
        let is_active = self.is_p_task_active(p_task);
        let is_cooldown = self.is_p_task_cooling_down(p_task);
        if is_active {
            println!("{} is already active", p_task.title_string());
        }
        if is_cooldown {
            println!("{} is cooling down", p_task.title_string());
        }
        return !(is_active || is_cooldown)
    }

    fn p_to_a_task(&self, p_task: &PooledTask) -> ActiveTask {
        let mut finish_day = self.ref_tm + Duration::days(p_task.due_days as i64);
        floor_tm_day(&mut finish_day);
        ActiveTask {
            task: p_task.task.clone(),
            start: self.ref_tm,
            due: finish_day
        }
    }

    fn activate_p_task(&mut self, p_task: &PooledTask) -> ActiveTask {
        let a_task = self.p_to_a_task(p_task);
        self.active.insert(a_task.title_string(), a_task.clone());
        a_task
    }


    fn renew_p_task(&mut self, title: &String) {
        match self.pool.get_mut(title) {
            Some(p_task) => {
                p_task.cooling_until = self.ref_tm +
                    Duration::days(p_task.cool_down as i64)}
            None => ()
        }
    }
}

impl TaskStatTrait for TaskStat {
    fn activate<R: rand::Rng>(&mut self, r: &mut R) -> Option<Vec<ActiveTask>> {
        let mut insert_tasks = Vec::new();
        let mut result : Vec<ActiveTask> = Vec::new();
        {
            let p_tasks = self.pick_random_from_pool(r);
            for p_task in p_tasks {
                if self.can_activate(p_task) {
                    insert_tasks.push(p_task.clone());
                }
            }
        }
        for p_task in insert_tasks {
            result.push(self.activate_p_task(&p_task));
        }
        Some(result)
    }

    /// Generate a new task and add it to the active list
    fn add_active_task(&mut self,
                           title: String,
                           description: String,
                           factor: f32,
                           due_days: i16) -> Option<ActiveTask> {
        floor_tm_day(&mut self.ref_tm);
        let duration = Duration::days(due_days as i64);
        let due = self.ref_tm + duration;
        let a_task = ActiveTask {
            task: Task {
                title: title,
                description: description,
                factor: factor
            },
            start: self.ref_tm,
            due: due
        };
        self.active.insert(a_task.task.title.clone(), a_task.clone());
        Some(a_task)
    }

    fn add_pooled_task(&mut self, title: String, description: String,
                       factor: f32, propability: f32,
                       cool_down: i16, due_days: i16) -> Option<PooledTask> {
        floor_tm_day(&mut self.ref_tm);
        let p_task = PooledTask {
            task: Task {
                title: title,
                description: description,
                factor: factor
            },
            propability: propability,
            cool_down: cool_down,
            due_days: due_days,
            cooling_until: self.ref_tm
        };
        self.pool.insert(p_task.task.title.clone(), p_task.clone());
        Some(p_task)
    }

    fn mark_done(&mut self, title: String) -> bool {
        if !self.active.contains_key(&title) {
            false
        } else {
            self.active.remove(&title);
            self.renew_p_task(&title);
            true
        }
    }

    fn all_actives(&self) -> Option<Vec<ActiveTask>> {
        let mut res: Vec<ActiveTask> = Vec::new();
        for (_, a_task) in self.active.iter() {
            res.push(a_task.clone());
        }
        Some(res)
    }

    fn all_pooled(&self)  -> Option<Vec<PooledTask>> {
        let mut res: Vec<PooledTask> = Vec::new();
        for (_, a_task) in self.pool.iter() {
            res.push(a_task.clone());
        }
        Some(res)
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use super::rand;
    use super::rand::Rng;
    use std::collections::BTreeMap;

    struct TestRand {
        i: usize,
        vals: Vec<u32>,
        vals_f: Vec<f32>
    }

    impl rand::Rng for TestRand {
        fn next_u32(&mut self) -> u32 {
            let index = self.i % self.vals.len();
            self.i += 1;
            self.vals[index]
        }

        fn next_f32(&mut self) -> f32 {
            let index = self.i % self.vals_f.len();
            self.i += 1;
            self.vals_f[index]
        }
    }

    #[test]
    fn test_random() {
        let mut rng = TestRand {
            i: 0,
            vals: vec![0, 1, 2],
            vals_f: vec![0.0, 0.2, 0.5]
        };
        assert_eq!(0.0, rng.next_f32());
        assert_eq!(0.2, rng.next_f32());
        assert_eq!(0.5, rng.next_f32());
        assert_eq!(0.0, rng.next_f32());
        assert_eq!(1, rng.next_u32());
    }

    #[test]
    fn basic_insert_test() {
        let mut task_stat = TaskStat::empty_task_stat();
        task_stat.add_active_task("u".to_string(), "uiae".to_string(), 1.0, 3);
        task_stat.add_pooled_task("i".to_string(), "xvlc".to_string(), 1.0, 0.4,
                                  3, 4);

        assert_eq!(1, task_stat.active.len());
        assert_eq!(1, task_stat.pool.len());
    }

    fn default_rng() -> TestRand {
        TestRand {
            i: 0,
            vals: vec![0, 1, 2],
            vals_f: vec![0.0, 0.2, 0.5, 0.7]
        }
    }

    #[test]
    fn random_activate_test () {
        // create a fake ranom generator where we know the results
        let mut rng = default_rng();
        let mut task_stat = TaskStat::empty_task_stat();
        task_stat.add_pooled_task("task a".to_string(), "".to_string(),
                                  1.0, 0.2, 1, 2);
        task_stat.add_pooled_task("task b".to_string(), "".to_string(),
                                  1.0, 0.1, 2, 3);
        task_stat.add_pooled_task("task c".to_string(), "".to_string(),
                                  1.0, 0.7, 0, 1);
        task_stat.activate(&mut rng);
        let actives : BTreeMap<String, ActiveTask> = task_stat.active;
        assert_eq!(true, actives.contains_key(&"task a".to_string()));
        assert_eq!(false, actives.contains_key(&"task b".to_string()));
        assert_eq!(true, actives.contains_key(&"task c".to_string()));
        // todo test other creteria
    }

    #[test]
    fn mark_done_test () {
        let mut task_stat = TaskStat::empty_task_stat();
        task_stat.add_pooled_task("task a".to_string(), "".to_string(),
                                  1.0, 0.2, 1, 2);
        task_stat.add_active_task("task a".to_string(), "".to_string(),
                                  1.0, 3);
        assert_eq!(false, task_stat.mark_done("task b".to_string()));
        assert_eq!(true, task_stat.mark_done("task a".to_string()));
        assert_eq!(false, task_stat.mark_done("task b".to_string()));
    }
}
