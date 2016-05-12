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
use std::io::{Write, Read};
use std::fs::{File, create_dir_all};
use std::io::Error;
use std::cmp::min;

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

impl Readable for String {
    fn read(reader: &mut Read) -> String {
        let size = read_u32(reader);
        let mut str_bytes = read_bytes(reader, size as usize);
        String::from_utf8(str_bytes).unwrap()
    }
}

fn read_bytes(reader: &mut Read, n: usize) -> Vec<u8> {
    let mut read_bytes: usize = 0;
    let mut buffer: [u8; 1024] = [0; 1024];
    let mut res: Vec<u8> = Vec::with_capacity(n);
    while read_bytes < n {
        let bytes_to_read = min(1024, n - read_bytes);
        reader.read(&mut buffer);
        for i in 0..read_bytes {
            res.push(buffer[i]);
        }
    }
    res
}

fn write_f32(writer: &mut Write, f: f32) {
    let mut bytes: [u8; 4] = [0; 4];
    BigEndian::write_f32(&mut bytes, f);
    writer.write(&bytes);
}

fn read_f32(reader: &mut Read) -> f32 {
    let mut bytes: [u8; 4] = [0; 4];
    reader.read(&mut bytes);
    BigEndian::read_f32(&mut bytes)
}

fn write_i16(writer: &mut Write, i: i16) {
    let mut bytes: [u8; 2] = [0; 2];
    BigEndian::write_i16(&mut bytes, i);
    writer.write(&bytes);
}

fn read_i16(reader: &mut Read) -> i16 {
    let mut bytes: [u8; 2] = [0; 2];
    reader.read(&mut bytes);
    BigEndian::read_i16(&bytes)
}

fn write_u32(writer: &mut Write, u: u32) {
    let mut bytes: [u8; 4] = [0; 4];
    BigEndian::write_u32(&mut bytes, u);
    writer.write(&bytes);
}

fn read_u32(reader: &mut Read) -> u32 {
    let mut bytes: [u8; 4] = [0; 4];
    reader.read(&mut bytes);
    BigEndian::read_u32(&mut bytes)
}

fn read_i64(reader: &mut Read) -> i64 {
    let mut bytes: [u8; 8] = [0; 8];
    reader.read(&mut bytes);
    BigEndian::read_i64(&bytes)
}

impl Writable for Task {
    fn write(&self, writer: &mut Write) {
        self.title.write(writer);
        self.description.write(writer);
        write_f32(writer, self.factor);
    }
}

impl Readable for Task {
    fn read(reader: &mut Read) -> Task {
        let title = String::read(reader);
        let desc = String::read(reader);
        let factor = read_f32(reader);
        Task {
            title: title,
            description: desc,
            factor: factor
        }
    }
}

impl Writable for ActiveTask {
    fn write(&self, writer: &mut Write) {
        self.task.write(writer);
        writer.write(&tm_to_bytes(&self.start));
        writer.write(&tm_to_bytes(&self.due));
    }
}

impl Readable for ActiveTask {
    fn read(reader: &mut Read) -> ActiveTask {
        let task = Task::read(reader);
        let start = tm_from_i64(read_i64(reader));
        let due = tm_from_i64(read_i64(reader));
        ActiveTask {
            task: task, 
            start: start,
            due: due
        }
    }
}

impl Writable for PooledTask {
    fn write(&self, writer: &mut Write) {
        self.task.write(writer);
        write_f32(writer, self.propability);
        write_i16(writer, self.cool_down);
        write_i16(writer, self.due_days);
        writer.write(&tm_to_bytes(&self.cooling_until));
    }
}

impl Readable for PooledTask {
    fn read(reader: &mut Read) -> PooledTask {
        let task = Task::read(reader);
        let propability = read_f32(reader);
        let cool_down = read_i16(reader);
        let due_days = read_i16(reader);
        let cooling_until = tm_from_i64(read_i64(reader));
        PooledTask {
            task: task,
            propability: propability,
            cool_down: cool_down,
            due_days: due_days,
            cooling_until: cooling_until
        }
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
                for a_task in a_tasks {
                    a_task.write(writer);
                }
            }
        }
    }
}

impl Readable for TaskAction {
    fn read(reader: &mut Read) -> TaskAction {
        let mut task_type: [u8; 1] = [0; 1];
        reader.read(&mut task_type);
        match task_type[0] {
            1 => TaskAction::ScheduleTask(ActiveTask::read(reader)),
            2 => TaskAction::PoolTask(PooledTask::read(reader)),
            3 => TaskAction::CompleteTask(ActiveTask::read(reader)),
            4 => {
                let length = read_u32(reader);
                let mut a_tasks: Vec<ActiveTask> = Vec::new();
                for i in 0..length {
                    let a_task = ActiveTask::read(reader);
                    a_tasks.push(a_task);
                }
                TaskAction::ActivateTask(a_tasks)
            },
            // I really have to add error handling
            _ => TaskAction::ScheduleTask(ActiveTask{
                task: Task {
                    title: "".to_string(),
                    description: "".to_string(),
                    factor: 0f32
                },
                start: tm_from_i64(0),
                due: tm_from_i64(0)
            })
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

impl Readable for TaskStat {
    fn read(reader: &mut Read) -> TaskStat {
        let mut task_stat = TaskStat::empty_task_stat();
        let a_task_length = read_u32(reader);
        for _ in 0..a_task_length {
            let a_task = ActiveTask::read(reader);
            task_stat.active.insert(a_task.task.title.clone(), a_task.clone());
        }
        let p_task_length = read_u32(reader);
        for _ in 0..p_task_length {
            let p_task = PooledTask::read(reader);
            task_stat.pool.insert(p_task.task.title.clone(), p_task.clone());
        }
        task_stat
    }
}

impl Readable for LogEntry<TaskAction> {
    fn read(reader: &mut Read) -> LogEntry<TaskAction> {
        let hash = Hash::read(reader);
        let dttm = tm_from_i64(read_i64(reader));
        let parent_hash = Hash::read(reader);
        let log_entry = TaskAction::read(reader);
        LogEntry {
            hash: hash,
            dttm: dttm,
            entry: log_entry,
            parent: Box::new(ParentEntry::ParentHash(parent_hash))
        }
    }
}

fn load_parent_entry_from_fs(save_dir: &str, hash: &Hash)
                             -> Result<ParentEntry<TaskAction>, Error> {
    let byte_hash = hash.get_bytes();
    let byte_hash_left = &byte_hash[0..1];
    let byte_hash_right = &byte_hash[1..];
    let filename = save_dir.to_string() + "/"
        + bin_slice_to_hex(byte_hash_left).as_str() + "/"
        + bin_slice_to_hex(byte_hash_right).as_str();
    let mut f = try!(File::open(filename));
    let mut log_entry = LogEntry::read(&mut f);
    log_entry.parent = Box::new(
        try!(load_parent_entry_from_fs(save_dir,
                                  &log_entry.parent.parent_hash())));
    let parent_entry = ParentEntry::ParentEntry(log_entry);
    Result::Ok(parent_entry)
}

fn load_log(save_dir: &str) -> Result<Log<TaskAction>, Error> {
    let head_file_path = save_dir.to_string() + "/head";
    let mut head_file = try!(File::open(head_file_path));
    let mut hash = Hash::read(&mut head_file);
    let parent_entry = try!(load_parent_entry_from_fs(save_dir, &hash));
    let log = Log {
        head: Box::new(parent_entry)
    };
    Result::Ok(log)
}

pub fn write_task_log_to_fs(task_log: &TaskLog,
                            dir: &str) -> Result <(), Error>{
    save_to_fs(dir, &task_log.log);
    let filename = dir.to_string() + "/state";
    let mut f = try!(File::create(filename));
    task_log.task_stat.write(&mut f);
    f.flush()
}
