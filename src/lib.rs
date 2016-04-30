//! Task management library
//#![warn(missing_docs)]

extern crate time;
extern crate rand;

use time::Duration;
use std::collections::btree_map::BTreeMap;
use rand::random;

pub type FactorT = f32;
pub type CooldownT = i16;
pub type DueDaysT = i16;

/// Base task type
#[derive(Clone)]
pub struct Task {
    title: String,
    description: String,
    factor: FactorT
}

/// A task which got activated.
#[derive(Clone)]
pub struct ActiveTask {
    task: Task,
    due: time::Tm
}

/// A task which is about to get activated
#[derive(Clone)]
pub struct PooledTask {
    task: Task,
    propability: FactorT,
    cool_down: CooldownT,
    due_days: DueDaysT,
    cooling_until: time::Tm
}

/// Overall state of the tasks
pub struct TaskStat<R: rand::Rng> {
    pub active: BTreeMap<String, ActiveTask>,
    pool: BTreeMap<String, PooledTask>,
    ref_tm: time::Tm,
    rnd: R
}



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

trait TaskStatTrait {
    fn add_active_task(&mut self, title: String, description: String,
                       factor: FactorT, due_days: i16);
    fn add_pooled_task(&mut self, title: String, description: String,
                       factor: FactorT, propability: FactorT,
                       cool_down: CooldownT, due_days: DueDaysT);
    fn activate(&mut self);
    fn mark_done(&mut self, title: String) -> bool;
    fn all_actives(&self) -> Vec<ActiveTask>;
    fn all_pooled(&self) -> Vec<PooledTask>;
}

/// Task stat implementation
impl<R: rand::Rng> TaskStat<R> {
    /// Generate a new and empty task stat
    pub fn empty_task_stat() -> TaskStat<rand::ThreadRng> {
        TaskStat {
            active: BTreeMap::new(),
            pool: BTreeMap::new(),
            ref_tm: time::now(),
            rnd: rand::thread_rng()
        }
    }


    fn pick_random_from_pool(&mut self) -> Vec<&PooledTask>{
        let mut result = Vec::new();
        for (_, p_task) in self.pool.iter() {
            let rand_num : f32 = self.rnd.next_f32();
            if rand_num < p_task.propability {
                result.push(p_task);
            }
        }
        result
    }

    fn is_p_task_active(&self, p_task: &PooledTask) -> bool {
        self.pool.contains_key(&p_task.title_string())
    }

    fn is_p_task_cooling_down(&self, p_task: &PooledTask) -> bool {
        let now = self.ref_tm;
        let task_limit = p_task.cooling_until;
        now > task_limit
    }

    fn can_activate(&self, p_task: &PooledTask) -> bool {
        !self.is_p_task_active(p_task) && !self.is_p_task_cooling_down(p_task)
    }

    fn p_to_a_task(&self, p_task: &PooledTask) -> ActiveTask {
        let finish_day = self.ref_tm + Duration::days(p_task.due_days as i64);
        ActiveTask {
            task: p_task.task.clone(),
            due: finish_day
        }
    }

    fn activate_p_task(&mut self, p_task: &PooledTask) {
        let a_task = self.p_to_a_task(p_task);
        self.active.insert(a_task.title_string(), a_task);
    }


}

impl<R: rand::Rng> TaskStatTrait for TaskStat<R> {
    fn activate(&mut self) {
        let mut insert_tasks = Vec::new();
        let p_tasks;
        {
            let p_tasks_= self.pick_random_from_pool();
            p_tasks = p_tasks_.clone();
        }
        {
            for p_task in p_tasks {
                if self.can_activate(p_task) {
                    insert_tasks.push(p_task.clone());
                }
            }
        }
        for p_task in insert_tasks {
            self.activate_p_task(&p_task);
        }
    }
    
    /// Generate a new task and add it to the active list
    fn add_active_task(&mut self,
                           title: String,
                           description: String,
                           factor: FactorT,
                           due_days: i16) {
        let duration = Duration::days(due_days as i64);
        let due = self.ref_tm + duration;
        let a_task = ActiveTask {
            task: Task {
                title: title,
                description: description,
                factor: factor
            },
            due: due
        };
        self.active.insert(a_task.task.title.clone(), a_task); 
    }

    fn add_pooled_task(&mut self, title: String, description: String,
                           factor: FactorT, propability: FactorT,
                           cool_down: CooldownT, due_days: DueDaysT) {
        let p_task = PooledTask {
            task: Task {
                title: title,
                description: description,
                factor: factor
            },
            propability: propability,
            cool_down: cool_down,
            due_days: due_days,
            cooling_until: time::now()
        };
        self.pool.insert(p_task.task.title.clone(), p_task);
    }

    fn mark_done(&mut self, title: String) -> bool {
        return false;
    }

    fn all_actives(&self) -> Vec<ActiveTask> {
        Vec::new()
    }

    fn all_pooled(&self)  -> Vec<PooledTask> {
        Vec::new()
    }
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_insert_test() {
        let mut task_stat = TaskStat::empty_task_stat();
        task_stat.add_active_task("u".to_string(), "uiae".to_string(), 1.0, 3);
        task_stat.add_pooled_task("i".to_string(), "xvlc".to_string(), 1.0, 0.4,
                                  3, 4);

        assert_eq!(1, task_stat.active.len());
        assert_eq!(1, task_stat.pool.len());
    }
}
