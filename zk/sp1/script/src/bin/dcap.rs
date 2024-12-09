use dcap_rs::types::{collaterals::IntelCollateral, VerifiedOutput};
use sp1_sdk::{utils, HashableKey, ProverClient, SP1Stdin};

pub const DCAP_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

fn main() {
    utils::setup_logger();

    let v5_quote = include_bytes!("../../data/quote_tdx_v5_90c06f000000.dat").to_vec();

    let mut intel_collaterals = IntelCollateral::new();
    intel_collaterals.set_tcbinfo_bytes(include_bytes!("../../data/tcbinfo-tdx-v3.json"));
    intel_collaterals.set_qeidentity_bytes(include_bytes!("../../data/identity_tdx.json"));
    intel_collaterals.set_intel_root_ca_der(include_bytes!(
        "../../data/Intel_SGX_Provisioning_Certification_RootCA.cer"
    ));
    intel_collaterals.set_sgx_tcb_signing_pem(include_bytes!("../../data/signing_cert.pem"));
    intel_collaterals
        .set_sgx_intel_root_ca_crl_der(include_bytes!("../../data/intel_root_ca_crl.der"));
    intel_collaterals.set_sgx_platform_crl_der(include_bytes!("../../data/pck_platform_crl.der"));

    let intel_collaterals_bytes = intel_collaterals.to_bytes();

    // get current time in seconds since epoch
    // let current_time = std::time::SystemTime::now()
    //     .duration_since(std::time::UNIX_EPOCH)
    //     .unwrap()
    //     .as_secs();
    let current_time = 1733691651u64;
    let current_time_bytes = current_time.to_le_bytes();

    // ZL: perform a simple serialization of the inputs
    // [current_time: u64][quote_len: u32][intel_collaterals_len: u32][quote: var][intel_collaterals: var]
    let quote_len = v5_quote.len() as u32;
    let intel_collaterals_bytes_len = intel_collaterals_bytes.len() as u32;
    let total_len = 8 + 4 + 4 + quote_len + intel_collaterals_bytes_len;

    let mut input = Vec::with_capacity(total_len as usize);
    input.extend_from_slice(&current_time_bytes);
    input.extend_from_slice(&quote_len.to_le_bytes());
    input.extend_from_slice(&intel_collaterals_bytes_len.to_le_bytes());
    input.extend_from_slice(&v5_quote);
    input.extend_from_slice(&intel_collaterals_bytes);

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);

    let client = ProverClient::new();

    // Execute the program first
    let (ret, report) = client.execute(DCAP_ELF, stdin.clone()).run().unwrap();
    println!(
        "executed program with {} cycles",
        report.total_instruction_count()
    );
    // println!("{:?}", report);

    // Generate the proof
    let (pk, vk) = client.setup(DCAP_ELF);
    let proof = client.prove(&pk, stdin.clone()).groth16().run().unwrap();
    // let proof = client.prove(&pk, stdin.clone()).plonk().run().unwrap();

    // Verify proof
    client.verify(&proof, &vk).expect("Failed to verify proof");
    println!("Successfully verified proof.");

    let ret_slice = ret.as_slice();
    let output_len = u16::from_be_bytes([ret_slice[0], ret_slice[1]]) as usize;
    let mut output = Vec::with_capacity(output_len);
    output.extend_from_slice(&ret_slice[2..2 + output_len]);

    println!("Execution Output: {}", hex::encode(ret_slice));
    println!(
        "Proof pub value: {}",
        hex::encode(proof.public_values.as_slice())
    );
    println!("VK: {}", vk.bytes32().to_string().as_str());
    println!("Proof: {}", hex::encode(proof.bytes()));

    let parsed_output = VerifiedOutput::from_bytes(&output);
    println!("{:?}", parsed_output);
}
