use std::process::ExitCode;

use std::io;

use io::Write;

use rs_pubkey2derived::x25519_dalek;

use x25519_dalek::PublicKey;

use rs_pubkey2derived::Combined;
use rs_pubkey2derived::Salt;
use rs_pubkey2derived::SharedInfo;
use rs_pubkey2derived::SymmetricKey;
use rs_pubkey2derived::raw2pubkey;

const FQDN: &str = "com.github.takanoriyanagitani";
const APP_CODE_NAME: &str = "pubkey2derived";
const USE_CASE: &str = "alice-bob";

fn sub() -> Result<(), io::Error> {
    let si: SharedInfo = SharedInfo::new(
        FQDN.as_bytes(),
        APP_CODE_NAME.as_bytes(),
        USE_CASE.as_bytes(),
    );

    let salt_data: [u8; 32] = hex_literal::hex!(
        "
			9dfb 4af5 b126 5eca 3f94 720c 1a52 4238
			175e c574 100c 4932 6978 3ed2 b048 a57a
		"
    );

    // for test purpose only; use CSPRNG to get this
    let salt: Salt = Salt { salt: salt_data };

    // this must be received
    let pubkey_raw: [u8; 32] = hex_literal::hex!(
        "
			daf3 6d0b 0722 1706 1b87 65b2 a566 ee1d
			fbcd 15af e3c9 ce91 c5c8 0436 bca5 3930
		"
    );
    let pubkey: PublicKey = raw2pubkey(pubkey_raw);

    let combined: Combined = Combined::from_public_key(&pubkey, salt, si);

    let salt64: String = combined.salt_base64();
    let my_pub_pem: String = combined.my_pub_key_to_pem()?;

    let derived: SymmetricKey = combined.derive_key()?;
    let sk256: String = derived.digest();

    println!("salt: {salt64}");
    println!("digest of symmetric key: {sk256}");

    io::stdout().lock().write_all(my_pub_pem.as_bytes())?;

    Ok(())
}

fn main() -> ExitCode {
    sub().map(|_| ExitCode::SUCCESS).unwrap_or_else(|e| {
        eprintln!("{e}");
        ExitCode::FAILURE
    })
}
