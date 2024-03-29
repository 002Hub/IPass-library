use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{read_dir, read_to_string, File};
use std::io::{Read, Write};

pub fn get_args() -> Vec<String> {
    //! [0] = file path; [n>0] = argument
    std::env::args().collect()
}

#[derive(Debug, Deserialize, Serialize)]
struct Saved {
    success: bool,
    status: u16,
    data: Vec<u8>,
    errorcode: u64,
}

pub fn get_token_path() -> String {
    get_ipass_folder() + "token.ipasst"
}

fn get_token() -> Option<String> {
    let mut token: String = String::new();
    //check if file exists
    if !std::path::Path::new(&get_token_path()).exists() {
        return None;
    }
    File::open(get_token_path())
        .unwrap()
        .read_to_string(&mut token)
        .unwrap();
    Some(token)
}

#[derive(Debug, Deserialize, Serialize)]
struct HashRes {
    success: bool,
    hash: String,
    status: u16,
    errorcode: u64,
}

fn sha256hexhash(data: Vec<u8>) -> String {
    let mut hash = Sha256::new();
    hash.update(data);
    format!("{:X}", hash.finalize())
}

pub async fn isync_compare_hashes() -> bool {
    /*!
     * \brief compare local hash to remote hash
     * \return true if hashes are equal
     * \return false if hashes are not equal
     * \return true if error
     */
    let hash = sha256hexhash(export_data().unwrap());

    let token = get_token();
    match token {
        Some(token) => {
            let client = reqwest::Client::builder().https_only(true).build().unwrap();
            let req = client
                .get("https://ipass.ipost.rocks/hash")
                .header("ipass-auth-token", token)
                .timeout(std::time::Duration::from_secs(3))
                .build();
            if let Ok(req) = req {
                let res = client.execute(req).await;
                if let Ok(res) = res {
                    let body = res.json::<HashRes>().await;
                    if let Ok(body) = body {
                        if body.success {
                            //println!("Hash: {} {}", hash, body.hash);
                            body.hash == hash
                        } else {
                            eprintln!("Error: {}", body.errorcode);
                            true
                        }
                    } else {
                        eprintln!("Error: {}", body.err().unwrap());
                        true
                    }
                } else {
                    eprintln!("Error: {}", res.err().unwrap());
                    true
                }
            } else {
                eprintln!("Error: {}", req.err().unwrap());
                true
            }
        }
        None => {
            eprintln!("No token found!");
            true
        }
    }
}

pub async fn isync_get() -> bool {
    if !isync_compare_hashes().await {
        let token = get_token();
        match token {
            Some(token) => {
                let client = reqwest::Client::builder().https_only(true).build().unwrap();
                let req = client
                    .get("https://ipass.ipost.rocks/saved")
                    .header("ipass-auth-token", token)
                    .timeout(std::time::Duration::from_secs(3))
                    .build();
                if let Ok(req) = req {
                    let res = client.execute(req).await;
                    if let Ok(res) = res {
                        let body = res.json::<Saved>().await;
                        if let Ok(body) = body {
                            if body.success {
                                println!("new hash: {}", sha256hexhash(body.data.clone()));
                                File::create(get_ipass_folder() + "temp.ipassx")
                                    .unwrap()
                                    .write_all(&body.data)
                                    .unwrap();
                                import_file(&(get_ipass_folder() + "temp.ipassx"));
                                std::fs::remove_file(get_ipass_folder() + "temp.ipassx").unwrap();
                                return true;
                            } else {
                                if body.status == 200 {
                                    return true;
                                }
                                eprintln!("Error: {}", body.errorcode);
                                return false;
                            }
                        } else {
                            eprintln!("Error: {}", body.err().unwrap());
                            return false;
                        }
                    } else {
                        eprintln!("Error: {}", res.err().unwrap());
                        return false;
                    }
                } else {
                    eprintln!("Error: {}", req.err().unwrap());
                    return false;
                }
            }
            None => {
                eprintln!("No token found!");
                return false;
            }
        }
    }
    true
}

#[derive(Debug, Deserialize, Serialize)]
struct Save {
    success: bool,
    status: u16,
    errorcode: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct SavedData {
    data: Vec<u8>,
    amount: i32,
    token: String,
}

pub async fn isync_save() -> bool {
    let possible_data = export_data();
    match possible_data {
        Some(data) => {
            let token = get_token();
            match token {
                Some(token) => {
                    let saveddata = SavedData {
                        data,
                        amount: read_dir(get_ipass_folder()).unwrap().count() as i32,
                        token,
                    };

                    let requestbody = serde_json::to_string(&saveddata).unwrap();

                    let client = reqwest::Client::builder().https_only(true).build().unwrap();
                    let req = client
                        .post("https://ipass.ipost.rocks/save")
                        .body(requestbody)
                        .header("content-type", "application/json")
                        .timeout(std::time::Duration::from_secs(5))
                        .build()
                        .unwrap();
                    let res = client.execute(req).await.unwrap();
                    let response = res.json::<Save>().await.unwrap();
                    if response.success {
                        true
                    } else {
                        if response.status == 200 {
                            return true;
                        }
                        eprintln!("Error: {}", response.errorcode);
                        false
                    }
                }
                None => false,
            }
        }
        None => false,
    }
}

pub fn import_data<R: Read>(mut reader: brotli::Decompressor<R>) {
    let mut content: String = String::new();
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf[..]) {
            Err(e) => {
                if let std::io::ErrorKind::Interrupted = e.kind() {
                    continue;
                }
                panic!("{}", e);
            }
            Ok(size) => {
                if size == 0 {
                    break;
                }
                content += std::str::from_utf8(&buf[..size]).unwrap();
            }
        }
    }

    let entries = get_entries().flatten();
    for entry in entries {
        if entry.file_name().to_str().unwrap().ends_with(".ipasst")
            || entry.file_name().to_str().unwrap().ends_with(".ipassx")
        {
            continue;
        }
        std::fs::remove_file(entry.path()).unwrap();
    }

    let lines = content.lines();
    let mut name = "";
    for i in lines {
        if name.is_empty() {
            name = i;
            continue;
        }

        println!("importing {}...", name);

        let mut file = File::create(format!("{}/{}.ipass", get_ipass_folder(), name)).unwrap();
        file.write_all(i.as_bytes()).unwrap();
        name = "";
    }
}

pub fn import_file(file_path: &String) -> bool {
    if std::path::Path::new(file_path).exists() {
        let reader = brotli::Decompressor::new(
            File::open(file_path).unwrap(),
            4096, // buffer size
        );
        import_data(reader);
        true
    } else {
        false
    }
}

pub fn export_data() -> Option<Vec<u8>> {
    let mut collected_data = String::new();
    let paths = std::fs::read_dir(get_ipass_folder()).ok()?;

    for path in paths.flatten() {
        if path.file_name().into_string().ok()?.ends_with(".ipasst")
            || path.file_name().into_string().ok()?.ends_with(".ipassx")
        {
            continue;
        }
        let file_name = path.file_name().into_string().ok()?.replace(".ipass", "");
        let content =
            std::fs::read_to_string(get_ipass_folder() + &path.file_name().to_string_lossy())
                .ok()?;
        collected_data += format!("{}\n{}\n", file_name, content).as_str();
    }

    let mut compressed_data = Vec::new();
    {
        let mut compressor = brotli::CompressorWriter::new(&mut compressed_data, 4096, 11, 22);
        compressor.write_all(collected_data.as_bytes()).ok()?;
        compressor.flush().ok()?;
    }

    Some(compressed_data)
}

pub fn export_file(file_path: &String) -> bool {
    match export_data() {
        Some(compressed_data) => {
            if let Ok(mut file) = std::fs::File::create(file_path) {
                if let Err(e) = file.write_all(&compressed_data) {
                    eprintln!("Failed to write compressed data to file: {}", e);
                    return false;
                }
                true
            } else {
                eprintln!("Failed to create file at path: {}", file_path);
                false
            }
        }
        None => {
            eprintln!("Failed to export data");
            false
        }
    }
}

fn vecu8_to_string(vec: Vec<u8>) -> String {
    let mut do_print_warning = false;
    let mut out: String = String::new();
    for ind in vec {
        if let Ok(a) = std::str::from_utf8(&[ind]) {
            out += a;
        } else {
            do_print_warning = true;
            eprintln!("[WARNING] malformed character {}", ind);
            let mut temp_vec: Vec<u8> = Vec::new();
            temp_vec.insert(0, ind % 128);
            out += vecu8_to_string(temp_vec).as_str();
        }
    }
    if do_print_warning {
        println!("[WARNING] Output may be corrupt");
    }
    out
}

fn generate_nonce(nonce_arg: &str) -> String {
    const NONCE_LEN: usize = 12;
    match nonce_arg.len().cmp(&NONCE_LEN) {
        std::cmp::Ordering::Less => {
            nonce_arg.to_string() + &" ".repeat(NONCE_LEN - nonce_arg.len())
        }
        std::cmp::Ordering::Greater => nonce_arg[0..NONCE_LEN].to_string(),
        std::cmp::Ordering::Equal => nonce_arg.to_string(),
    }
}

fn encrypt_pass(nonce_arg: &str, pass: &str, mpw: &str) -> String {
    let nonce_argument = generate_nonce(nonce_arg);

    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(nonce_argument.as_bytes());

    let nonce_final = &nonce_hasher.finalize()[0..12];

    let mut hasher = Sha256::new();
    hasher.update(mpw.as_bytes());

    let master_pw = &hasher.finalize();

    let cipher = Aes256Gcm::new(master_pw);
    let nonce = Nonce::from_slice(nonce_final); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, pass.as_ref()).unwrap();
    hex::encode(ciphertext)
}

fn decrypt_pass(nonce_arg: &str, pass: Vec<u8>, mpw: &str) -> Result<String, String> {
    let nonce_argument = generate_nonce(nonce_arg);

    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(nonce_argument.as_bytes());

    let nonce_final = &nonce_hasher.finalize()[0..12];

    let mut hasher = Sha256::new();
    hasher.update(mpw.as_bytes());

    let master_pw = &hasher.finalize();
    let cipher = Aes256Gcm::new(master_pw);
    let nonce = Nonce::from_slice(nonce_final); // 96-bits; unique per message

    let plaintext = cipher.decrypt(nonce, pass.as_ref());
    match plaintext {
        Ok(res) => Ok(vecu8_to_string(res)),
        Err(_) => Err("[ERROR] Error decrypting data, check your master password".to_string()),
    }
}

pub fn get_home_folder_str() -> String {
    const HOME_MESSAGE: &str = "Could not get home folder, set the IPASS_HOME environment variable for the parent-folder of where you want to store your passwords";
    match home::home_dir() {
        Some(path) => {
            let p = path.to_str();
            match p {
                Some(pa) => pa.to_owned(),
                None => panic!("{HOME_MESSAGE}"),
            }
        }
        None => panic!("{HOME_MESSAGE}"),
    }
}

pub fn get_ipass_folder() -> String {
    let path = get_home_folder_str() + "/.IPass/";
    std::fs::create_dir_all(&path).unwrap();
    path
}

pub fn create_entry(name: &str, pw: &str, mpw: &str) -> bool {
    let mut entry_name = String::new();
    for c in name.chars() {
        match c {
            ':' | '$' | '<' | '>' | '|' | '?' | '*' | '/' | '\\' => {}
            _ => entry_name.push(c),
        }
    }
    if std::path::Path::new(&(get_ipass_folder() + entry_name.as_str() + ".ipass")).exists() {
        return false;
    }
    let pw = encrypt_pass(&entry_name, pw, mpw);
    let mut file = File::create(get_ipass_folder() + entry_name.as_str() + ".ipass").unwrap();
    file.write_all(pw.as_bytes()).unwrap();
    true
}

fn read_entry(name: &str, mpw: &str) -> Result<String, String> {
    let path = get_ipass_folder() + name + ".ipass";

    //check if entry exists
    if !std::path::Path::new(&path).exists() {
        return Err(format!("Entry {} does not exist", name));
    }

    let err_msg = format!("Should have been able to read the file {}", path);
    let content = &mut read_to_string(path).unwrap_or_else(|_| panic!("{}", err_msg));
    decrypt_pass(name, hex::decode(content).unwrap(), mpw)
}

pub fn get_entry(name: &str, mpw: &str) -> Result<String, String> {
    read_entry(name, mpw)
}

pub fn edit_password(name: &str, password: &str, mpw: &str) -> bool {
    let entry_result = read_entry(name, mpw);
    if let Ok(entry) = entry_result {
        let mut parts = entry.split(';');
        let username = parts.next().unwrap().to_string();
        parts
            .next()
            .expect("Expected to be able to get old password");

        let username_pw_combo = username + ";" + password;
        let data = encrypt_pass(name, &username_pw_combo, mpw);
        let mut file = File::create(get_ipass_folder() + name + ".ipass").unwrap();
        file.write_all(data.as_bytes()).unwrap();
        return true;
    }
    false
}

pub fn edit_username(name: &str, username: &str, mpw: &str) -> bool {
    let entry_result = read_entry(name, mpw);
    if let Ok(entry) = entry_result {
        // println!("entry: {entry}");
        let mut parts = entry.split(';');

        parts
            .next()
            .expect("Expected to be able to get old username");

        let password = parts.next().unwrap();

        let username_pw_combo = username.to_string() + ";" + password;

        let data = encrypt_pass(name, &username_pw_combo, mpw);
        let mut file = File::create(get_ipass_folder() + name + ".ipass").unwrap();
        file.write_all(data.as_bytes()).unwrap();
        return true;
    }
    false
}

pub fn prompt_answer(toprint: &str) -> String {
    prompt_answer_nolower(toprint).to_lowercase()
}

pub fn prompt_answer_nolower(toprint: &str) -> String {
    print!("{toprint}");
    std::io::stdout().flush().unwrap();
    let mut choice = String::new();
    std::io::stdin()
        .read_line(&mut choice)
        .expect("Failed to read choice");

    choice.trim().to_string()
}

pub fn rename(name: &str, new_name: &str, mpw: &str) -> bool {
    if !std::path::Path::new(&(get_ipass_folder() + name + ".ipass")).exists() {
        return false;
    }
    if std::path::Path::new(&(get_ipass_folder() + new_name + ".ipass")).exists() {
        return false;
    }
    let content = &mut read_to_string(get_ipass_folder() + name + ".ipass")
        .expect("Should have been able to read the file");
    if let Ok(mut data) = decrypt_pass(name, hex::decode(content).unwrap(), mpw) {
        data = encrypt_pass(new_name, &data, mpw);
        let mut file = File::create(get_ipass_folder() + new_name + ".ipass").unwrap();
        file.write_all(data.as_bytes()).unwrap();
        return true;
    }
    false
}

pub fn get_entries() -> std::fs::ReadDir {
    read_dir(get_ipass_folder()).unwrap()
}

pub fn random_password() -> String {
    const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!\"$%&/()=?{[]}\\,.-;:_><|+*#'";
    let alph_len: usize = ALPHABET.len();
    let char_set: Vec<char> = ALPHABET.chars().collect();
    let mut chars_index: Vec<u8> = vec![0; 20];
    OsRng.fill_bytes(&mut chars_index);
    chars_index
        .iter()
        .map(|index| char_set[(*index as usize) % alph_len].to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn encrypt_decrypt() {
        const NAME: &str = "test";
        const PASSWORD: &str = "test";
        const MASTER_PASSWORD: &str = "test";
        let encrypted = hex::decode(super::encrypt_pass(NAME, PASSWORD, MASTER_PASSWORD)).unwrap();
        let decrypted = super::decrypt_pass(NAME, encrypted, MASTER_PASSWORD).unwrap();
        assert_eq!(decrypted, PASSWORD);
    }

    #[test]
    fn encrypt_decrypt_error() {
        const NAME: &str = "test";
        const PASSWORD: &str = "test";
        const MASTER_PASSWORD: &str = "test";
        let encrypted = hex::decode(super::encrypt_pass(NAME, PASSWORD, MASTER_PASSWORD)).unwrap();
        let decrypted = super::decrypt_pass(NAME, encrypted, "test2");
        assert!(decrypted.is_err());
    }

    #[test]
    fn create_delete_entry() {
        const NAME: &str = "test";
        const PASSWORD: &str = "test";
        const MASTER_PASSWORD: &str = "test";
        let created = super::create_entry(NAME, PASSWORD, MASTER_PASSWORD);
        assert!(created);
        let entry = super::read_entry(NAME, MASTER_PASSWORD);
        assert!(entry.is_ok());
        assert_eq!(entry.unwrap(), PASSWORD);

        let deleted = std::fs::remove_file(super::get_ipass_folder() + NAME + ".ipass");
        assert!(deleted.is_ok());
        let entry = super::read_entry(NAME, MASTER_PASSWORD);
        assert!(entry.is_err());
    }

    #[test]
    fn test_get_ipass_folder() {
        let path = super::get_ipass_folder();
        let path = std::path::Path::new(&path);
        assert!(path.is_dir());
        assert!(path.exists());
    }

    #[test]
    fn test_get_home_folder() {
        let path = super::get_home_folder_str();
        let path = std::path::Path::new(&path);
        assert!(path.is_dir());
        assert!(path.exists());
    }

    #[test]
    fn test_nonce() {
        let nonce = super::generate_nonce("test");
        assert_eq!(nonce, "test        ");
        let nonce = super::generate_nonce("0123456789abcdef");
        assert_eq!(nonce, "0123456789ab");
    }

    #[test]
    fn test_random_pw_length() {
        for _ in 0..100_000 {
            assert_eq!(super::random_password().len(), 20);
        }
    }

    #[test]
    fn test_sha256hexhash() {
        let to_hash = "test".as_bytes().to_vec();
        let hash = super::sha256hexhash(to_hash);
        assert_eq!(
            hash,
            "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
        );
    }
}
