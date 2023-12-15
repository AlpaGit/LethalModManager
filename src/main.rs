use std::collections::HashMap;
use std::fs;
use std::path::{Path};
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::{File};
use std::io::{Write, Read};
use futures_util::stream::StreamExt;
use single_instance::SingleInstance;


#[tokio::main]
async fn main() {
    let instance = SingleInstance::new("lethal_mod_manager").unwrap();

    if !instance.is_single() {
        println!("Another instance is already running, exiting...");
        return;
    }

    let path = get_path();

    let files = scan(&path);
    let remotes_files = get_remote_files().await;

    println!("Path: {}", path);

    sync(&path, &files, &remotes_files).await;

    // delay 10 seconds
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
}

async fn get_remote_files() -> HashMap<String, String> {
    // force no cache
    // current timestamp
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let req = reqwest::get(format!("https://cdn.bubble-network.net/lethal/hashes.json?t={}", since_the_epoch.as_millis())).await.unwrap();
    let body = req.text().await.unwrap();

    println!("Remote hashes: {}", &body);
    serde_json::from_str(&body).unwrap()
}

fn get_path() -> String {
    return get_path_from_registry();
}

fn get_path_from_registry() -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Steam App 1966720").unwrap();
    let install_dir: String = cur_ver.get_value("InstallLocation").unwrap();
    install_dir
}

fn scan(install_dir:&str) -> HashMap<String, String> {
    println!("Scanning files...");

    let blacklisted_dir = vec![
        "Lethal Company_Data",
        "MonoBleedingEdge",
        "Dissonance_Diagnostics"];

    let blacklisted_files = vec![
        "Lethal Company.exe",
        "nvngx_dlss.dll",
        "UnityPlayer.dll",
    ];

    let mut files: HashMap<String, String> = HashMap::new();

    for entry in walkdir::WalkDir::new(install_dir) {
        let entry = entry.unwrap();

        if entry.file_type().is_dir() {
            continue;
        }

        let entry_path = entry.path();
        let file_name = entry.file_name().to_str().unwrap();

        if blacklisted_files.contains(&file_name) {
            continue;
        }

        let relative_path = entry.path().strip_prefix(install_dir).unwrap();

        let mut hash_allowed = true;

        for dir in blacklisted_dir.iter() {
            if relative_path.starts_with(dir) {
                hash_allowed = false;
                continue;
            }
        }

        if !hash_allowed {
            continue;
        }

        let mut relative_path_str = relative_path.to_str().unwrap().to_string();
        relative_path_str = relative_path_str.replace("\\", "/");

        let hash = get_hash(&entry_path.to_str().unwrap());

        files.insert(relative_path_str, hash);
    }

    files
}

fn get_hash(file: &str) -> String {
    //println!("Hashing file: {}", file);
    let mut file = std::fs::File::open(file).unwrap();

    let mut hasher = Sha256::new();
    // read file by 64KB chunks
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();

    format!("{:x}", result)
}

async fn sync(base_dir:&str, local_files:&HashMap<String, String>, remote_files:&HashMap<String, String>) {
    println!("Syncing files...");

    let base_dir = base_dir.replace("\\", "/");

    let mut updated_files = vec![];

    for (local_file_name, local_file_hash) in local_files {
        let path = Path::new(&base_dir).join(local_file_name);
        let local_file_name = local_file_name.as_str();
        let remote_file = remote_files.get(local_file_name);

        if remote_file.is_none() {
            println!("Deleting file: {}", local_file_name);

            fs::remove_file(path)
                .expect(format!("Unable to delete file {}", local_file_name)
                .as_str());

            continue;
        }

        let remote_file_hash = remote_file.unwrap();

        if remote_file_hash != local_file_hash {
            println!("Updating file: {}", local_file_name);
            fs::remove_file(&path)
                    .expect(format!("Unable to delete file {}", local_file_name)
                    .as_str());

            download_file(&format!("https://cdn.bubble-network.net/lethal/{}", local_file_name), &path)
                .await
                .expect("Unable to download file");

            updated_files.push(local_file_name);
        }

        println!("Skipping file: {}", local_file_name);
    }

    for (remote_file_name, remote_file_hash) in remote_files {
        let local_file = local_files.get(remote_file_name);

        let path = Path::new(&base_dir).join(remote_file_name);

        if updated_files.contains(&remote_file_name.as_str()) {
            continue;
        }

        if local_file.is_none() {
            download_file(&format!("https://cdn.bubble-network.net/lethal/{}", remote_file_name), &path)
                .await
                .expect("Unable to download file");
        }
    }

    println!("Done syncing files. Game is up to date");
}

async fn download_file(url: &str, path: &Path) -> Result<(), ()> {
    println!("Downloading file: {}", &path.to_str().unwrap());
    create_dir_all(path.parent().unwrap()).unwrap();

    let res = reqwest::get(url)
        .await.map_err(|err| {
        eprintln!("ERROR: could not download the bundle: {err}");
        ()
    })?;

    let mut file = File::create(path).map_err(|err| {
        eprintln!("ERROR: could not create the file: {path} ({err})", path = path.display());
        ()
    })?;


    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let bytes = item.map_err(|err| {
            eprintln!("ERROR: could not read the bundle: {err}");
            ()
        })?;

        file.write_all(&bytes).map_err(|err| {
            eprintln!("ERROR: could not write the bundle: {err}");
            ()
        })?;
    }

    Ok(())
}

fn create_dir_all(path: &Path) -> Result<(), ()> {
    if path.exists() {
        return Ok(());
    }

    println!("INFO: creating the directory {path}", path = path.display());

    fs::create_dir_all(path).map_err(|err| {
        eprintln!("ERROR: could not create the directory {path}: {err}", path = path.display(), err = err);
        ()
    })
}
