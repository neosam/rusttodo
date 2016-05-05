//! Task and logging management

extern crate crypto;
extern crate byteorder;
extern crate rand;
extern crate time;

use log::*;
use task::*;
use self::crypto::sha3::Sha3;
use self::crypto::digest::Digest;
use self::byteorder::{BigEndian, ByteOrder};
use self::rand::Rng;
use self::time::now;

pub enum TaskAction {
    ScheduleTask(ActiveTask),
    PoolTask(PooledTask),
    CompleteTask(ActiveTask),
    ActivateTask(Vec<ActiveTask>)
}

fn f32_to_bytes(val: f32) -> [u8; 4] {
    let mut res : [u8; 4] = [0; 4];
    BigEndian::write_f32(&mut res, val);
    res
}

fn i16_to_bytes(val: i16) -> [u8; 2] {
    let mut res : [u8; 2] = [0; 2];
    BigEndian::write_i16(&mut res, val);
    res
}

impl Hashable for ActiveTask {
    fn to_hash(&self) -> Hash {
        let mut msg_vec: Vec<u8> = Vec::new();

        msg_vec.extend_from_slice(self.task.title.as_bytes());
        msg_vec.extend_from_slice(self.task.description.as_bytes());
        msg_vec.extend_from_slice(&f32_to_bytes(self.task.factor));
        msg_vec.extend_from_slice(&tm_to_bytes(&self.due));

        let msg: &[u8] = msg_vec.as_slice();
        let mut hasher = Sha3::sha3_256();
        hasher.input(msg);
        let mut hash_val: [u8; 32] = [0; 32];
        hasher.result(&mut hash_val);
        let hash = Hash::Sha3(hash_val);
        hash
    }
}

impl Hashable for PooledTask {
    fn to_hash(&self) -> Hash {
        let mut msg_vec: Vec<u8> = Vec::new();

        msg_vec.extend_from_slice(self.task.title.as_bytes());
        msg_vec.extend_from_slice(self.task.description.as_bytes());
        msg_vec.extend_from_slice(&f32_to_bytes(self.task.factor));
        msg_vec.extend_from_slice(&f32_to_bytes(self.propability));
        msg_vec.extend_from_slice(&i16_to_bytes(self.cool_down));
        msg_vec.extend_from_slice(&i16_to_bytes(self.due_days));

        let msg: &[u8] = msg_vec.as_slice();
        let mut hasher = Sha3::sha3_256();
        hasher.input(msg);
        let mut hash_val: [u8; 32] = [0; 32];
        hasher.result(&mut hash_val);
        let hash = Hash::Sha3(hash_val);
        hash
    }
}

impl<T: Hashable> Hashable for Vec<T> {
    fn to_hash(&self) -> Hash {
        let mut msg_vec : Vec<u8> = Vec::new();

        for hashable in self {
            msg_vec.extend_from_slice(&hashable.to_hash().get_bytes());
        }

        let msg: &[u8] = msg_vec.as_slice();
        let mut hasher = Sha3::sha3_256();
        hasher.input(msg);
        let mut hash_val: [u8; 32] = [0; 32];
        hasher.result(&mut hash_val);
        let hash = Hash::Sha3(hash_val);
        hash
    }
} 

impl Hashable for TaskAction {
    fn to_hash(&self) -> Hash {
        match self {
            &TaskAction::ScheduleTask(ref a_task) => a_task.to_hash(),
            &TaskAction::PoolTask(ref p_task) => p_task.to_hash(),
            &TaskAction::CompleteTask(ref a_task) => a_task.to_hash(),
            &TaskAction::ActivateTask(ref a_tasks) => a_tasks.to_hash()
        }
    }
}

pub struct TaskLog {
    pub log: Log<TaskAction>,
    pub task_stat: TaskStat
}


impl TaskStatTrait for TaskLog {
    fn add_active_task(&mut self, title: String, desc: String, factor: FactorT,
                       due_days: DueDaysT) -> ActiveTask {
        let a_task =
            self.task_stat.add_active_task(title, desc, factor, due_days);
        self.log.add_entry(TaskAction::ScheduleTask(a_task.clone()), now());
        a_task
    }

    fn add_pooled_task(&mut self, title: String, desc: String, factor: FactorT,
                       propability: FactorT, cool_down: CooldownT,
                       due_days: DueDaysT) -> PooledTask {
        let p_task =
            self.task_stat.add_pooled_task(title, desc, factor, propability,
                                           cool_down, due_days);
        self.log.add_entry(TaskAction::PoolTask(p_task.clone()), now());
        p_task
    }

    fn activate<R: Rng>(&mut self, rng: &mut R) -> Vec<ActiveTask> {
        let a_tasks = self.task_stat.activate(rng);
        self.log.add_entry(TaskAction::ActivateTask(a_tasks.clone()), now());
        a_tasks
    }

    fn mark_done(&mut self, title: String) -> bool {
        let mut success = self.task_stat.mark_done(title.clone());
        if success {
            if let Some(a_task) = self.task_stat.active.get(&title) {
                self.log.add_entry(TaskAction::CompleteTask(a_task.clone()), now());
            } else {
                success = false;
            }
        } else {
            success = false;
        }
        success
    }

    fn all_actives(&self) -> Vec<ActiveTask> {
        self.task_stat.all_actives()
    }

    fn all_pooled(&self) -> Vec<PooledTask> {
        self.task_stat.all_pooled()
    }
}
