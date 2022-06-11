use crate::error::ClientRaError;
use crate::ClientRaResult;
use aesm_client::{AesmClient, QuoteInfo, QuoteType, QuoteResult};
use ra_common::msg::{Gid, Quote, RaMsg0, RaMsg1, RaMsg2, RaMsg3, RaMsg4};
use sgx_crypto::cmac::MacTag;
use sgx_crypto::key_exchange::DHKEPublicKey;
use sgx_isa::Report;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::mem::size_of;
use std::io::{BufReader, BufRead};
use std::net::TcpStream;
use serde_json;
use byteorder::*;

use aesm_client::sgx::AesmClientExt;

pub struct ClientRaContext {
    /* pub aesm_client: AesmClient, */
    /* pub aesm_stream: TcpStream, */
    pub quote_info: QuoteInfo,
    pub g_a: Option<DHKEPublicKey>,
}

impl ClientRaContext {
    pub fn init() -> ClientRaResult<Self> {
        let quote_info = read_init();

        Ok(Self {
            quote_info,
            g_a: None,
        })
    }

    pub fn do_attestation(
        mut self,
        mut enclave_stream: &mut (impl Read + Write),
        mut sp_stream: &mut (impl Read + Write),
    ) -> ClientRaResult<()> {
        let msg0 = self.get_extended_epid_group_id();
        if cfg!(feature = "verbose") {
            eprintln!("MSG0 generated");
        }

        bincode::serialize_into(&mut sp_stream, &msg0)?;
        sp_stream.flush()?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG0 sent");
        }

        let msg1 = self.get_msg_1(enclave_stream);
        if cfg!(feature = "verbose") {
            eprintln!("MSG1 generated");
        }

        bincode::serialize_into(&mut sp_stream, &msg1)?;
        sp_stream.flush()?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG1 sent");
        }

        let msg2: RaMsg2 = bincode::deserialize_from(&mut sp_stream)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG2 received");
        }

        let msg3 = self.process_msg_2(msg2, enclave_stream)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG3 generated");
        }

        bincode::serialize_into(&mut sp_stream, &msg3)?;
        sp_stream.flush()?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG3 sent");
        }

        let msg4: RaMsg4 = bincode::deserialize_from(&mut sp_stream)?;
        if cfg!(feature = "verbose") {
            eprintln!("MSG4 received");
        }

        bincode::serialize_into(&mut enclave_stream, &msg4).unwrap();
        sp_stream.flush()?;

        if !msg4.is_enclave_trusted {
            return Err(ClientRaError::EnclaveNotTrusted);
        }
        match msg4.is_pse_manifest_trusted {
            Some(t) => {
                if !t {
                    return Err(ClientRaError::PseNotTrusted);
                }
            }
            None => {}
        }
        Ok(())
    }

    /// ExGID = 0 means IAS will be used for remote attestation. This function only
    /// returns 0 for now.
    pub fn get_extended_epid_group_id(&self) -> RaMsg0 {
        RaMsg0 { exgid: 0 }
    }

    pub fn get_msg_1(&mut self, enclave_stream: &mut (impl Read + Write)) -> RaMsg1 {
        let g_a: DHKEPublicKey = bincode::deserialize_from(enclave_stream).unwrap();
        let gid: Gid = self.quote_info.gid().try_into().unwrap();
        self.g_a = Some(g_a.clone());
        RaMsg1 { gid, g_a }
    }

    pub fn process_msg_2(
        &mut self,
        msg2: RaMsg2,
        mut enclave_stream: &mut (impl Read + Write),
    ) -> ClientRaResult<RaMsg3> {
        bincode::serialize_into(&mut enclave_stream, &msg2)?;
        enclave_stream.flush()?;

        let sig_rl = match msg2.sig_rl {
            Some(sig_rl) => sig_rl.to_owned(),
            None => Vec::with_capacity(0),
        };
        let spid = (&msg2.spid[..]).to_owned();

        // Get a Quote and send it to enclave to sign
        let quote = Self::get_quote(/*&self.aesm_client,*/spid, sig_rl, enclave_stream)?;

        // Read MAC for msg3 from enclave
        let mut mac = [0u8; size_of::<MacTag>()];
        enclave_stream.read_exact(&mut mac)?;

        Ok(RaMsg3 {
            g_a: self.g_a.take().unwrap(),
            mac,
            ps_sec_prop: None,
            quote,
        })
    }

    /// Get a Quote and send it to enclave to sign
    pub fn get_quote(
        /* aesm_client: &AesmClient, */
        spid: Vec<u8>,
        sig_rl: Vec<u8>,
        enclave_stream: &mut (impl Read + Write),
    ) -> ClientRaResult<Quote> {
        /* let quote_info = aesm_client.init_quote()?; */
        /* let quote_stream =  */
        /* let mut aesm_stream = BufReader::new(TcpStream::connect("aesm-init")?);
         * let mut quote_info = String::new();
         * aesm_stream.read_line(&mut quote_info).unwrap();
         * println!("got quote_info: {:?}", quote_info);
         * let quote_info: QuoteInfo = serde_json::from_str(&quote_info).unwrap(); */

        let quote_info = read_init();

        // Get report for local attestation with QE from enclave
        enclave_stream.write_all(quote_info.target_info())?;
        enclave_stream.flush()?;
        let mut report = vec![0u8; Report::UNPADDED_SIZE];
        enclave_stream.read_exact(&mut report[..]).expect("Failed to read of size Report::UNPADDED_SIZE");

        // Get a quote and QE report from QE and send them to enclave
        let nonce = vec![0u8; 16]; // TODO change this

        /* let _quote = aesm_client.get_quote(report, spid, sig_rl, QuoteType::Linkable, nonce)?; */
        /* let mut aesm_stream = BufReader::new(TcpStream::connect("aesm-get_quote")?);
         * let mut _quote = String::new();
         * aesm_stream.read_line(&mut _quote).unwrap();
         * println!("got quote_info: {:?}", _quote);
         * let mut _quote: QuoteResult = serde_json::from_str(&_quote).unwrap(); */

        let _quote: QuoteResult = read_get_quote(report, spid, sig_rl);

        enclave_stream.write_all(_quote.quote())?;
        enclave_stream.write_all(_quote.qe_report())?;
        enclave_stream.flush()?;

        let mut quote = [0u8; size_of::<Quote>()];
        quote.copy_from_slice(_quote.quote());


        Ok(quote)
    }
}

fn read_init() -> QuoteInfo {
    let stream = TcpStream::connect("aesm-init");
    let stream = stream.unwrap();
    let mut aesm_stream = BufReader::new(stream);

    /* let mut buf = [0; 30].to_vec();
     * aesm_stream.read_exact(&mut buf); */

    let mut buf = [0; 1118].to_vec();
    aesm_stream.read_exact(&mut buf);
    let quote_info = String::from_utf8(buf).unwrap();

    serde_json::from_str(&quote_info).unwrap()
}

fn read_get_quote(
        report: Vec<u8>,
        spid: Vec<u8>,
        sig_rl: Vec<u8>,
    ) -> QuoteResult {
    let stream = TcpStream::connect("aesm-get_quote");
    let mut stream = stream.unwrap();

    /* let mut aesm_stream = BufRer::new(stream); */

    println!("report: {:?}", report);
    stream.write_all(&report);
    stream.write_all(b"\n");
    println!("spid: {:?}", spid);
    stream.write_all(&spid);
    stream.write_all(&sig_rl);
    println!("after written");

    /* let mut buf = [0; 30].to_vec();
     * aesm_stream.read_exact(&mut buf); */

    let mut buf = [0; 1118].to_vec();
    stream.read_exact(&mut buf);
    let quote_result = String::from_utf8(buf).unwrap();
    println!("quote_result: {:?}", quote_result);

    serde_json::from_str(&quote_result).unwrap()
}
