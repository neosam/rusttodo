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
use std::io::Write;
use std::fs::{File, create_dir_all};
use std::io::Error;

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

impl TaskLog {
    /// Create a new and empty TaskLog instance.
    pub fn new() -> TaskLog {
        TaskLog {
            log: Log::new(),
            task_stat: TaskStat::empty_task_stat()
        }
    }
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


impl Writable for String {
    fn write(&self, writer: &mut Write) {
        let mut size: [u8; 4] = [0; 4];
        BigEndian::write_u32(&mut size, self.len() as u32);
        writer.write(self.as_bytes());
    }
}

fn write_f32(writer: &mut Write, f: f32) {
    let mut bytes: [u8; 4] = [0; 4];
    BigEndian::write_f32(&mut bytes, f);
    writer.write(&bytes);
}

fn write_i16(writer: &mut Write, i: i16) {
    let mut bytes: [u8; 2] = [0; 2];
    BigEndian::write_i16(&mut bytes, i);
    writer.write(&bytes);
}

fn write_u32(writer: &mut Write, u: u32) {
    let mut bytes: [u8; 4] = [0; 4];
    BigEndian::write_u32(&mut bytes, u);
    writer.write(&bytes);
}

impl Writable for Task {
    fn write(&self, writer: &mut Write) {
        self.title.write(writer);
        self.description.write(writer);
        write_f32(writer, self.factor);
    }
}

impl Writable for ActiveTask {
    fn write(&self, writer: &mut Write) {
        self.task.write(writer);
        writer.write(&tm_to_bytes(&self.due));
    }
}

impl Writable for PooledTask {
    fn write(&self, writer: &mut Write) {
        self.task.write(writer);
        write_i16(writer, self.cool_down);
        write_i16(writer, self.due_days);
        writer.write(&tm_to_bytes(&self.cooling_until));
    }
}

impl Writable for TaskAction {
    fn write(&self, writer: &mut Write) {
        match self {
            &TaskAction::ScheduleTask(ref a_task) => {
                let task_type: [u8; 1] = [0];
                writer.write(&task_type);
                a_task.write(writer);
            },
            &TaskAction::PoolTask(ref p_task) => {
                let task_type: [u8; 1] = [1];
                writer.write(&task_type);
                p_task.write(writer);
            },
            &TaskAction::CompleteTask(ref a_task) => {
                let task_type: [u8; 1] = [2];
                writer.write(&task_type);
                a_task.write(writer);
            },
            &TaskAction::ActivateTask(ref a_tasks) => {
                let task_type: [u8; 1] = [3];
                let mut size: [u8; 4] = [0; 4];
                writer.write(&task_type);
                BigEndian::write_u32(&mut size, a_tasks.len() as u32);
                writer.write(&size);
            }
        }
    }
}

impl Writable for TaskStat {
    fn write(&self, writer: &mut Write) {
        write_u32(writer, self.active.len() as u32);
        for (_, a_task) in self.active.iter() {
            a_task.write(writer);
        }
        write_u32(writer, self.pool.len() as u32);
        for (_, p_task) in self.pool.iter() {
            p_task.write(writer);
        }
    }
}

pub fn write_task_log_to_fs(task_log: &TaskLog,
                            dir: &str) -> Result <(), Error>{
    save_to_fs(dir, &task_log.log);
    let filename = dir.to_string() + "/state";
    let mut f = try!(File::create(filename));
    task_log.task_stat.write(&mut f);
    f.flush()
}
