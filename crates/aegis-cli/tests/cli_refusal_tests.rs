use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const EXIT_SUCCESS: i32 = 0;
const EXIT_CLI: i32 = 2;

fn base_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aegis-cli"));
    cmd.env_remove("AEGIS_PASSWORD");
    cmd.env_remove("AEGIS_PASSWORD_CONFIRM");
    cmd
}

fn run_cmd(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = base_command();
    cmd.args(args);
    for (key, val) in envs {
        cmd.env(key, val);
    }
    cmd.output().expect("run aegis-cli")
}

fn temp_dir(label: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    dir.push(format!(
        "aegis-cli-test-{}-{}-{}",
        label,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_no_temp(output: &Path) {
    let tmp_path = output.with_extension("tmp");
    assert!(
        !tmp_path.exists(),
        "unexpected temp file: {}",
        tmp_path.display()
    );
}

fn write_file(path: &Path, data: &[u8]) {
    fs::write(path, data).expect("write file");
}

fn generate_key(dir: &Path, name: &str) -> PathBuf {
    let key_path = dir.join(name);
    let output = run_cmd(&["keygen", path_str(&key_path), "--force"], &[]);
    assert_exit(&output, EXIT_SUCCESS);
    key_path
}

#[test]
fn pack_refuses_overwrite_without_force() {
    let dir = temp_dir("pack-overwrite");
    let input = dir.join("input.bin");
    let output = dir.join("packed.aegis");
    write_file(&input, b"hello");
    write_file(&output, b"existing");

    let out = run_cmd(&["pack", path_str(&input), path_str(&output)], &[]);

    assert_exit(&out, EXIT_CLI);
    assert_eq!(fs::read(&output).expect("read output"), b"existing");
    assert_no_temp(&output);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn enc_refuses_overwrite_without_force() {
    let dir = temp_dir("enc-overwrite");
    let input = dir.join("input.bin");
    let output = dir.join("enc.aegis");
    write_file(&input, b"plaintext");
    let keyfile = generate_key(&dir, "recipient.key");
    write_file(&output, b"existing");

    let out = run_cmd(
        &[
            "enc",
            path_str(&input),
            path_str(&output),
            "--recipient-key",
            path_str(&keyfile),
        ],
        &[],
    );

    assert_exit(&out, EXIT_CLI);
    assert_eq!(fs::read(&output).expect("read output"), b"existing");
    assert_no_temp(&output);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn dec_refuses_existing_output() {
    let dir = temp_dir("dec-overwrite");
    let input = dir.join("input.bin");
    let container = dir.join("enc.aegis");
    let output = dir.join("dec.bin");
    write_file(&input, b"plaintext");
    let keyfile = generate_key(&dir, "recipient.key");

    let enc = run_cmd(
        &[
            "enc",
            path_str(&input),
            path_str(&container),
            "--recipient-key",
            path_str(&keyfile),
        ],
        &[],
    );
    assert_exit(&enc, EXIT_SUCCESS);

    write_file(&output, b"existing");
    let dec = run_cmd(
        &[
            "dec",
            path_str(&container),
            path_str(&output),
            "--recipient-key",
            path_str(&keyfile),
        ],
        &[],
    );

    assert_exit(&dec, EXIT_CLI);
    assert_eq!(fs::read(&output).expect("read output"), b"existing");
    assert_no_temp(&output);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn enc_refuses_mixed_recipients_without_allow() {
    let dir = temp_dir("enc-mixed");
    let input = dir.join("input.bin");
    let output = dir.join("enc.aegis");
    write_file(&input, b"plaintext");
    let keyfile = generate_key(&dir, "recipient.key");

    let out = run_cmd(
        &[
            "enc",
            path_str(&input),
            path_str(&output),
            "--recipient-key",
            path_str(&keyfile),
            "--recipient-password",
        ],
        &[],
    );

    assert_exit(&out, EXIT_CLI);
    assert!(!output.exists(), "output should not be created");
    assert_no_temp(&output);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn dec_refuses_missing_credentials() {
    let dir = temp_dir("dec-missing");
    let input = dir.join("input.bin");
    let container = dir.join("enc.aegis");
    let output = dir.join("dec.bin");
    write_file(&input, b"plaintext");
    let keyfile = generate_key(&dir, "recipient.key");

    let enc = run_cmd(
        &[
            "enc",
            path_str(&input),
            path_str(&container),
            "--recipient-key",
            path_str(&keyfile),
        ],
        &[],
    );
    assert_exit(&enc, EXIT_SUCCESS);

    let dec = run_cmd(&["dec", path_str(&container), path_str(&output)], &[]);
    assert_exit(&dec, EXIT_CLI);
    assert!(!output.exists(), "output should not be created");
    assert_no_temp(&output);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rotate_refuses_mixed_recipients_without_allow() {
    let dir = temp_dir("rotate-mixed");
    let input = dir.join("input.bin");
    let container = dir.join("enc.aegis");
    let output = dir.join("rotated.aegis");
    write_file(&input, b"plaintext");
    let keyfile = generate_key(&dir, "recipient.key");
    let new_key = generate_key(&dir, "recipient2.key");

    let enc = run_cmd(
        &[
            "enc",
            path_str(&input),
            path_str(&container),
            "--recipient-key",
            path_str(&keyfile),
        ],
        &[],
    );
    assert_exit(&enc, EXIT_SUCCESS);

    let rotate = run_cmd(
        &[
            "rotate",
            path_str(&container),
            "--output",
            path_str(&output),
            "--auth-key",
            path_str(&keyfile),
            "--add-recipient-key",
            path_str(&new_key),
            "--add-recipient-password",
        ],
        &[],
    );

    assert_exit(&rotate, EXIT_CLI);
    assert!(!output.exists(), "output should not be created");
    assert_no_temp(&output);
    let _ = fs::remove_dir_all(&dir);
}
