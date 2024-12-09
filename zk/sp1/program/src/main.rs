#![no_main]
sp1_zkvm::entrypoint!(main);

use dcap_rs::types::quotes::version_5::QuoteV5;
use dcap_rs::types::{
    collaterals::IntelCollateral, quotes::version_3::QuoteV3, quotes::version_4::QuoteV4,
    VerifiedOutput,
};
use dcap_rs::utils::cert::{hash_crl_keccak256, hash_x509_keccak256};
use dcap_rs::utils::hash::keccak256sum;
use dcap_rs::utils::quotes::version_3::verify_quote_dcapv3;
use dcap_rs::utils::quotes::version_4::verify_quote_dcapv4;
use dcap_rs::utils::quotes::version_5::verify_quote_dcapv5;

pub fn main() {
    // Read the input
    let input = sp1_zkvm::io::read_vec();

    // TODO: currently current_time does nothing since it can be spoofed by the host
    // we can obtain an attested time from a trusted source that is bound to the input values and verify it

    // deserialize the input
    // read the fixed portion first
    let current_time: u64 = u64::from_le_bytes(input[..8].try_into().unwrap());
    let quote_len = u32::from_le_bytes(input[8..12].try_into().unwrap()) as usize;
    let intel_collaterals_bytes_len =
        u32::from_le_bytes(input[12..16].try_into().unwrap()) as usize;

    // read the variable length fields
    let mut offset = 16 as usize;
    let quote_slice = &input[offset..offset + quote_len];
    offset += quote_len;
    let intel_collaterals_slice = &input[offset..offset + intel_collaterals_bytes_len];
    offset += intel_collaterals_bytes_len;
    assert!(offset == input.len());

    let intel_collaterals = IntelCollateral::from_bytes(&intel_collaterals_slice);

    // check either only platform or processor crls is provided. not both
    let sgx_platform_crl_is_found = (&intel_collaterals.get_sgx_pck_platform_crl()).is_some();
    let sgx_processor_crl_is_found = (&intel_collaterals.get_sgx_pck_processor_crl()).is_some();
    assert!(
        sgx_platform_crl_is_found != sgx_processor_crl_is_found,
        "platform or processor crls only"
    );

    let verified_output: VerifiedOutput;

    let quote_version = u16::from_le_bytes(input[16..18].try_into().unwrap());
    match quote_version {
        3 => {
            let quote = QuoteV3::from_bytes(&quote_slice);
            verified_output = verify_quote_dcapv3(&quote, &intel_collaterals, current_time);
        }
        4 => {
            let quote = QuoteV4::from_bytes(&quote_slice);
            verified_output = verify_quote_dcapv4(&quote, &intel_collaterals, current_time);
        }
        5 => {
            let quote = QuoteV5::from_bytes(&quote_slice);
            verified_output = verify_quote_dcapv5(&quote, &intel_collaterals, current_time);
        }
        _ => {
            panic!("Unsupported quote version {}", quote_version);
        }
    }

    // write public output to the journal
    let serial_output = verified_output.to_bytes();
    let tcbinfo_hash = keccak256sum(&intel_collaterals.tcbinfo_bytes.as_ref().unwrap());
    let qeidentity_hash = keccak256sum(&intel_collaterals.qeidentity_bytes.as_ref().unwrap());
    let sgx_intel_root_ca_cert_hash =
        hash_x509_keccak256(&intel_collaterals.get_sgx_intel_root_ca());
    let sgx_tcb_signing_cert_hash = hash_x509_keccak256(&intel_collaterals.get_sgx_tcb_signing());
    let sgx_intel_root_ca_crl_hash =
        hash_crl_keccak256(&intel_collaterals.get_sgx_intel_root_ca_crl().unwrap());

    let sgx_pck_crl;
    if sgx_platform_crl_is_found {
        sgx_pck_crl = intel_collaterals.get_sgx_pck_platform_crl().unwrap();
    } else {
        sgx_pck_crl = intel_collaterals.get_sgx_pck_processor_crl().unwrap();
    }

    let sgx_pck_crl_hash = hash_crl_keccak256(&sgx_pck_crl);

    // the output has the following format:
    // serial_output_len (2 bytes)
    // serial_output (VerifiedOutput) (SGX: 397 bytes, TDX: 597 bytes)
    // current_time (8 bytes)
    // tcbinfov2_hash
    // qeidentityv2_hash
    // sgx_intel_root_ca_cert_hash
    // sgx_tcb_signing_cert_hash
    // sgx_tcb_intel_root_ca_crl_hash
    // sgx_pck_platform_crl_hash or sgx_pck_processor_crl_hash
    let journal_len = serial_output.len() + 226;
    let mut output: Vec<u8> = Vec::with_capacity(journal_len);
    let output_len: u16 = serial_output.len() as u16;

    output.extend_from_slice(&output_len.to_be_bytes());
    output.extend_from_slice(&serial_output);
    output.extend_from_slice(&current_time.to_be_bytes());
    output.extend_from_slice(&tcbinfo_hash);
    output.extend_from_slice(&qeidentity_hash);
    output.extend_from_slice(&sgx_intel_root_ca_cert_hash);
    output.extend_from_slice(&sgx_tcb_signing_cert_hash);
    output.extend_from_slice(&sgx_intel_root_ca_crl_hash);
    output.extend_from_slice(&sgx_pck_crl_hash);

    sp1_zkvm::io::commit_slice(&output);
}
