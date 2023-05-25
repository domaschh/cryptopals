use crate::challengeone::one::find_encrypted;

mod challengeone;

fn main() {
    let res = find_encrypted("encrypted.txt");
    println!(" {} ", res.unwrap().0);
}
