//! Task management library
//#![warn(missing_docs)]

extern crate time;
extern crate rand;

use self::time::Duration;
use std::collections::BTreeMap;

pub type FactorT = f32;
pub type CooldownT = i16;
pub type DueDaysT = i16;

/// Base task type
#[derive(Clone)]
pub struct Task {
    pub title: String,
    pub description: String,
    pub factor: FactorT
}

/// A task which got activated.
#[derive(Clone)]
pub struct ActiveTask {
    pub task: Task,
    pub due: time::Tm
}

/// A task which is about to get activated
#[derive(Clone)]
pub struct PooledTask {
    pub task: Task,
    pub propability: FactorT,
    pub cool_down: CooldownT,
    pub due_days: DueDaysT,
    pub cooling_until: time::Tm
}

/// Overall state of the tasks
pub struct TaskStat {
    pub active: BTreeMap<String, ActiveTask>,
    pub pool: BTreeMap<String, PooledTask>,
    pub ref_tm: time::Tm,
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

pub trait TaskStatTrait {
    fn add_active_task(&mut self, title: String, description: String,
                       factor: FactorT, due_days: i16) -> ActiveTask;
    fn add_pooled_task(&mut self, title: String, description: String,
                       factor: FactorT, propability: FactorT,
                       cool_down: CooldownT, due_days: DueDaysT) -> PooledTask;
    fn activate<R: rand::Rng>(&mut self, rng: &mut R) -> Vec<ActiveTask>;
    fn mark_done(&mut self, title: String) -> bool;
    fn all_actives(&self) -> Vec<ActiveTask>;
    fn all_pooled(&self) -> Vec<PooledTask>;
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
    fn activate<R: rand::Rng>(&mut self, r: &mut R) -> Vec<ActiveTask>{
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
        result
    }
    
    /// Generate a new task and add it to the active list
    fn add_active_task(&mut self,
                           title: String,
                           description: String,
                           factor: FactorT,
                           due_days: i16) -> ActiveTask {
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
        self.active.insert(a_task.task.title.clone(), a_task.clone());
        a_task
    }

    fn add_pooled_task(&mut self, title: String, description: String,
                       factor: FactorT, propability: FactorT,
                       cool_down: CooldownT, due_days: DueDaysT) -> PooledTask {
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
        self.pool.insert(p_task.task.title.clone(), p_task.clone());
        p_task
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

    fn all_actives(&self) -> Vec<ActiveTask> {
        let mut res: Vec<ActiveTask> = Vec::new();
        for (_, a_task) in self.active.iter() {
            res.push(a_task.clone());
        }
        res
    }

    fn all_pooled(&self)  -> Vec<PooledTask> {
        let mut res: Vec<PooledTask> = Vec::new();
        for (_, a_task) in self.pool.iter() {
            res.push(a_task.clone());
        }
        res
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use super::rand;
    use super::rand::Rng;
    use super::TaskStatTrait;
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
