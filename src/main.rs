use class_group::primitives::cl_dl_public_setup::*;
use curv::arithmetic::Converter;
use curv::elliptic::curves::Point;
use curv::elliptic::curves::Scalar;
use curv::elliptic::curves::Secp256k1;
use curv::BigInt;
// use num_traits::Num;

const seed: &str =  "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848";

fn main() {
    let mut enc = Vec::new();
    let mut dec = Vec::new();
    for _ in 0..10 {
        let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(seed, 10).unwrap());
        let (secret_key, public_key) = group.keygen();
        let dl_keypair = {
            let sk = Scalar::<Secp256k1>::random();
            let pk = Point::<Secp256k1>::generator() * &sk;
            (sk, pk)
        };

        let t = std::time::Instant::now();
        let (ciphertext, proof) =
            verifiably_encrypt(&group, &public_key, (&dl_keypair.0, &dl_keypair.1));
        enc.push(t.elapsed());

        // let v = bincode::serialize(&ciphertext).unwrap();
        let c1 = ciphertext.clone().c1;
        let c2 = ciphertext.clone().c2;
        let a1 = c1.a;
        let b1 = c1.b;
        let c1 = c1.c;
        let a2 = c2.a;
        let b2 = c2.b;
        let c2 = c2.c;
        let mut v1 = a1.to_bytes();
        v1.append(&mut b1.to_bytes());
        v1.append(&mut b2.to_bytes());
        v1.append(&mut c1.to_bytes());
        v1.append(&mut c2.to_bytes());
        v1.append(&mut a2.to_bytes());
        // v1.append(&mut b1.to_bytes());

        println!("Size of ciphertext: {}", v1.len());

        let wrong_dl_pk = &dl_keypair.1 + Point::<Secp256k1>::generator();

        let t = std::time::Instant::now();
        assert!(
            proof
                .verify(&group, &public_key, &ciphertext, &dl_keypair.1)
                .is_ok(),
            "proof is valid against valid DL key"
        );
        dec.push(t.elapsed());

        // assert!(
        //     proof
        //         .verify(&group, &public_key, &ciphertext, &wrong_dl_pk)
        //         .is_err(),
        //     "proof is invalid against invalid DL key"
        // );

        // assert_eq!(
        //     decrypt(&group, &secret_key, &ciphertext),
        //     dl_keypair.0,
        //     "plaintext matches what was encrypted"
        // );
        // let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(seed, 10).unwrap());
        // let (secret_key, public_key) = group.keygen();
        // let message = Scalar::<Secp256k1>::random();

        // let t = std::time::Instant::now();
        // let (ciphertext, _) = encrypt(&group, &public_key, &message);
        // enc.push(t.elapsed());

        // let t = std::time::Instant::now();
        // let plaintext = decrypt(&group, &secret_key, &ciphertext);
        // dec.push(t.elapsed());

        // assert_eq!(plaintext, message);
    }
    println!(
        "Average of encryption: {:?}",
        enc.iter().sum::<std::time::Duration>() / enc.len() as u32
    );
    println!(
        "Average of decryption: {:?}",
        dec.iter().sum::<std::time::Duration>() / dec.len() as u32
    );
}
