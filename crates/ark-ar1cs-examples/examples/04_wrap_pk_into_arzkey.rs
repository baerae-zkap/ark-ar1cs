//! Wrap an existing `.ar1cs` + uncompressed `ProvingKey<Bn254>` (e.g.
//! `pk.key` from zkap-circuit's `setup`) into a single `.arzkey` envelope.
//!
//! Usage:
//!   cargo run --release -p ark-ar1cs-examples \
//!     --example 04_wrap_pk_into_arzkey -- <ar1cs-path> <pk-path> <out-arzkey>
//!
//! The PK is read with `deserialize_uncompressed_unchecked` to match
//! zkap-circuit's `crs::persist_setup_output` writer (uncompressed binary).
//! `ArzkeyFile::from_setup_output` derives the VK internally from `pk.vk`,
//! so PK/VK drift inside the resulting `.arzkey` is structurally impossible.

use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

use ark_ar1cs_format::ArcsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_bn254::{Bn254, Fr};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let ar1cs_path = PathBuf::from(
        args.next()
            .ok_or("missing <ar1cs-path> (e.g. configs/1of1.ar1cs)")?,
    );
    let pk_path = PathBuf::from(
        args.next()
            .ok_or("missing <pk-path> (e.g. crs/1-of-1/pk.key)")?,
    );
    let out_path = PathBuf::from(
        args.next()
            .ok_or("missing <out-arzkey> (e.g. crs/1-of-1/circuit.arzkey)")?,
    );

    let ar1cs_size = std::fs::metadata(&ar1cs_path)?.len();
    let pk_size = std::fs::metadata(&pk_path)?.len();
    println!(
        "ar1cs = {} ({:.1} MiB)",
        ar1cs_path.display(),
        ar1cs_size as f64 / 1024.0 / 1024.0
    );
    println!(
        "pk    = {} ({:.1} MiB, uncompressed)",
        pk_path.display(),
        pk_size as f64 / 1024.0 / 1024.0
    );

    println!("Reading .ar1cs ...");
    let arcs = {
        let mut r = BufReader::new(File::open(&ar1cs_path)?);
        ArcsFile::<Fr>::read(&mut r)?
    };
    println!(
        "  num_constraints = {}, num_witness = {}, num_instance = {}",
        arcs.header.num_constraints,
        arcs.header.num_witness_variables,
        arcs.header.num_instance_variables,
    );

    println!("Reading uncompressed ProvingKey<Bn254> ...");
    let pk = {
        let mut r = BufReader::new(File::open(&pk_path)?);
        ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut r)?
    };

    println!("Building ArzkeyFile (vk derived from pk.vk) ...");
    let arzkey = ArzkeyFile::<Bn254>::from_setup_output(arcs, pk);
    arzkey.validate()?;

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut w = BufWriter::new(File::create(&out_path)?);
    arzkey.write(&mut w)?;
    drop(w);

    let out_size = std::fs::metadata(&out_path)?.len();
    println!(
        "Wrote {} ({:.1} MiB)",
        out_path.display(),
        out_size as f64 / 1024.0 / 1024.0
    );
    println!("  ar1cs_blake3 (circuit identity) = {}", hex(&arzkey.header.ar1cs_blake3));
    println!("  vk_blake3                       = {}", hex(&arzkey.header.vk_blake3));
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
