use crate::challengeone::one::find_encrypted;

mod challengeone;
pub mod challengetwo;

fn main() {
    let res = find_encrypted("encrypted.txt");
    println!(" {} ", res.unwrap().0);
}
