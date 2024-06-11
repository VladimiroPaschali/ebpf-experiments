use bpf::{MapFlags, MapHandle};
use libbpf_rs as bpf;

pub fn get_map_id(name: &str) -> Option<u32> {
    let mut map_iter = bpf::query::MapInfoIter::default();
    while let Some(map) = map_iter.next() {
        let map_name = map.name.to_str().unwrap();
        if map_name == name {
            println!("map id {}", map.id);
            return Some(map.id);
        }
    }
    None
}

pub fn get_map_by_id(id: u32) -> Option<MapHandle> {
    let map = bpf::MapHandle::from_map_id(id).unwrap();
    println!("{}", map.name());
    Some(map)
}

pub fn get_data_from_map<'a>(map: &MapHandle, key: &[u8], cpu: usize) -> Vec<u64> {
    let flag = MapFlags::empty();
    match map.lookup_percpu(key, flag) {
        Ok(data) => {
            println!("{:?}", data.unwrap().get(0));
            let out = data.unwrap();
            out.iter().map(|x| x[cpu]).collect::Vec<<u64>>()
        }
        Err(_) => {
            println!("Error: {:?}", "Failed to get data from map");
            vec![]
        }
    }
}
