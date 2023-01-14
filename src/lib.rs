use std::io::{Read, Write};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use sha2::{Sha256, Digest};
use std::fs::{
    File,
    read_dir,
    read_to_string
};
use rand::{
    rngs::OsRng,
    RngCore
};

pub fn get_args() -> Vec<String> {
    //! [0] = file path; [n>0] = argument
    std::env::args().collect()
}

// pub fn isync_upload() {
//     todo!("Post request");
// }

// pub fn isync_download() -> String {
//     todo!("Get request");
// }

pub fn import_file(location:&String) -> bool {
    if std::path::Path::new(&(location.clone()+"/export.ipassx")).exists() {
        let mut reader = brotli::Decompressor::new(
            File::open(location.clone()+"/export.ipassx").unwrap(),
            4096, // buffer size
        );
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
                    content += &std::str::from_utf8(&buf[..size]).unwrap();
                }
            }
        }

        let lines = content.lines();
        let mut name = "";
        for i in lines {
            if name == "" {
                name = i;
                continue;
            }

            let mut file = File::create(format!("{}/{}.ipass",get_ipass_folder(), name)).unwrap();
            file.write_all(i.as_bytes()).unwrap();
            name = "";
        }
        return true;
    } else {
        return false;
    }
}

pub fn export_file(location:&String) -> bool {
    let mut collected_data: String = String::new();

    let paths = read_dir(get_ipass_folder()).unwrap();

    for p in paths {
        if let Ok(path) = p {
            let content = &mut read_to_string(get_ipass_folder()+&path.file_name().into_string().unwrap()).expect("Should have been able to read the file");
            collected_data += format!("{}\n{}\n", path.file_name().into_string().unwrap().replace(".ipass", ""),content).as_str();
        }
    }

    if let Ok(file) = File::create(location.clone()+"/export.ipassx") {
        let mut writer = brotli::CompressorWriter::new(
            file,
            4096,
            11,
            22);
        
        match writer.write_all(collected_data.as_bytes()) {
            Err(e) => panic!("{}", e),
            Ok(_) => {},
        }

        return true;
    } else {
        return false;
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
            eprintln!("[WARNING] malformed character {}",ind);
            let mut temp_vec: Vec<u8> = Vec::new();
            temp_vec.insert(0,ind%128);
            out += vecu8_to_string(temp_vec).as_str();
        }
    }
    if do_print_warning {
        println!("[WARNING] Output may be corrupt");
    }
    return out;
}

fn encrypt_pass(nonce_arg:String, pass: String,mpw: String) -> String {
    let mut nonce_argument = String::new();
    if nonce_arg.len() < 12 {
        nonce_argument = nonce_arg.clone() + &" ".repeat(12-nonce_arg.len());
    }
    if nonce_arg.len() > 12 {
        nonce_argument = nonce_arg[0..12].to_string();
    }

    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(nonce_argument.as_bytes());

    let nonce_final = &nonce_hasher.finalize()[0..12];


    let mut hasher = Sha256::new();
    hasher.update(mpw.as_bytes());

    let master_pw = &hasher.finalize();

    let cipher = Aes256Gcm::new(master_pw);
    let nonce = Nonce::from_slice(nonce_final); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(nonce, pass.as_ref()).unwrap();
    return hex::encode(ciphertext);
}



fn decrypt_pass(nonce_arg:String, pass: Vec<u8>,mpw: String) -> Result<String,String> {
    let mut nonce_argument = String::new();
    if nonce_arg.len() < 12 {
        nonce_argument = nonce_arg.clone() + &" ".repeat(12-nonce_arg.len());
    }
    if nonce_arg.len() > 12 {
        nonce_argument = nonce_arg[0..12].to_string();
    }

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
        Ok(res) => {
            return Ok(vecu8_to_string(res));
        }
        Err(_) => {
            return Err("[ERROR] Error decrypting data, check your master password".to_string());
        }
    }
}

pub fn get_home_folder_str() -> String {
    match home::home_dir() {
        Some(path) => {
            let p = path.to_str();
            match p {
                Some(pa) => return pa.to_owned(),
                None => return "".to_owned(),
            }
        },
        None => return "".to_owned(),
    }
}

pub fn get_ipass_folder() -> String {
    let path = get_home_folder_str()+"/.IPass/";
    std::fs::create_dir_all(&path).unwrap();
    return path;
}

pub fn create_entry(name: &String, pw: String, mpw: String) -> bool {
    if std::path::Path::new(&(get_ipass_folder()+name+".ipass")).exists() {
        return false;
    }
    // println!("{pw}");
    let pw = encrypt_pass(name.to_owned(), pw,mpw);
    let mut file = File::create(get_ipass_folder()+name+".ipass").unwrap();
    file.write_all(pw.as_bytes()).unwrap();
    return true;
}

fn read_entry(name:&String,mpw:String) -> Result<String,String> {
    let content = &mut read_to_string(get_ipass_folder()+name+".ipass").expect("Should have been able to read the file");
    decrypt_pass(name.to_owned(),hex::decode(content).unwrap(),mpw)
}

pub fn get_entry(name:&String, mpw: String) -> Result<String,String> {
    return read_entry(name,mpw);
}

pub fn edit_password(name:&String, password:String, mpw: String) -> bool {
    let entry_result = read_entry(name, mpw.clone());
    if let Ok(entry) = entry_result {
        // println!("entry: {entry}");
        let mut parts = entry.split(";");
        let username = parts.next().unwrap().to_string();
        let _old_password = parts.next().unwrap();
        let data = encrypt_pass(name.to_owned(), username+";"+password.as_str(),mpw);
        let mut file = File::create(get_ipass_folder()+name+".ipass").unwrap();
        file.write_all(data.as_bytes()).unwrap();
        return true;
    }
    return false;
}

pub fn edit_username(name:&String, username: String, mpw: String) -> bool {
    let entry_result = read_entry(name, mpw.clone());
    if let Ok(entry) = entry_result {
        // println!("entry: {entry}");
        let mut parts = entry.split(";");
        let _old_username = parts.next().unwrap();
        let password = parts.next().unwrap();
        let data = encrypt_pass(name.to_owned(), username+";"+password,mpw);
        let mut file = File::create(get_ipass_folder()+name+".ipass").unwrap();
        file.write_all(data.as_bytes()).unwrap();
        return true;
    }
    return false;
}

pub fn prompt_answer(toprint: String) -> String {
    prompt_answer_nolower(toprint).to_lowercase()
}

pub fn prompt_answer_nolower(toprint: String) -> String {
    print!("{toprint}");
    std::io::stdout().flush().unwrap();
    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice).expect("Failed to read choice");

    return choice.trim().to_string();
}

pub fn rename(name: &String, new_name: &String, mpw: String) -> bool {
    if !std::path::Path::new(&(get_ipass_folder()+name+".ipass")).exists() {
        return false;
    }
    if std::path::Path::new(&(get_ipass_folder()+new_name+".ipass")).exists() {
        return false;
    }
    let content = &mut read_to_string(get_ipass_folder()+name+".ipass").expect("Should have been able to read the file");
    let data_result = decrypt_pass(name.to_owned(),hex::decode(content).unwrap(),mpw.clone()).to_owned();
    if let Ok(mut data) = data_result {
        data = encrypt_pass(new_name.to_owned(), data,mpw);
        let mut file = File::create(get_ipass_folder()+new_name+".ipass").unwrap();
        file.write_all(data.as_bytes()).unwrap();
        return true;
    }
    return false;
}

pub fn get_entries() -> std::fs::ReadDir {
    read_dir(get_ipass_folder()).unwrap()
}

pub fn random_password() -> String {
    let alphabet: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!\"$%&/()=?{[]}\\,.-;:_><|+*#'";
    let alph_len: usize = alphabet.chars().count();
    let char_set:Vec<char> = alphabet.chars().collect();
    let mut chars_index: Vec<u8> = vec![0;20];
    OsRng.fill_bytes(&mut chars_index);
    let mut chars: String = String::new();

    for index in chars_index {
        // println!("{} - {} - {}",index,(index as usize)%(alph_len-1),alph_len);
        chars += &char_set[(index as usize)%(alph_len-1)].to_string();
    }
    return chars;
}