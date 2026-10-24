//! Verifier for the LiteX DICE lab chip (`tee = "litexdice"`).
//!
//! The chip's boot ROM derives two Ed25519 keys (see trustee-lab/sw/bootrom.c):
//!   DeviceID : from the chip's fused Unique Device Secret, the same on every boot
//!   Alias    : from the UDS and the firmware measurement, so it changes with the firmware
//! and signs an Alias certificate: DeviceID signs (Alias public key || measurement).
//! The firmware then signs REPORT_DATA with the Alias key.
//!
//! This verifier checks the cryptography: the certificate chain and the REPORT_DATA binding.
//! Whether the DeviceID belongs to a genuine chip and whether the measurement is the vendor's
//! firmware are appraisal decisions, so the attestation policy makes them from the claims below.

use super::*;
use async_trait::async_trait;
use ed25519_compact::{PublicKey, Signature};
use serde::Deserialize;
use serde_json::json;
use tracing::{instrument, warn};

#[derive(Deserialize, Debug)]
struct LitexDiceEvidence {
    /// DeviceID public key, 32 bytes, hex
    device_id: String,
    /// Alias certificate: alias_pub (32) || measurement (32) || DeviceID signature (64), hex
    alias_cert: String,
    /// SHA-384 of the KBS runtime data (nonce + TEE public key), hex
    report_data: String,
    /// Alias signature over report_data, hex
    signature: String,
}

#[derive(Debug, Default)]
pub struct LitexDice {}

fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let public_key = PublicKey::from_slice(public_key).context("bad Ed25519 public key")?;
    let signature = Signature::from_slice(signature).context("bad Ed25519 signature")?;
    public_key
        .verify(message, &signature)
        .map_err(|e| anyhow!("signature check failed: {e}"))
}

#[async_trait]
impl Verifier for LitexDice {
    #[instrument(skip_all, name = "LitexDice")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let ev = serde_json::from_value::<LitexDiceEvidence>(evidence)
            .context("Deserialize LiteX DICE evidence failed")?;
        let device_id = hex::decode(&ev.device_id).context("device_id is not hex")?;
        let cert = hex::decode(&ev.alias_cert).context("alias_cert is not hex")?;
        let report_data = hex::decode(&ev.report_data).context("report_data is not hex")?;
        let signature = hex::decode(&ev.signature).context("signature is not hex")?;
        if cert.len() != 128 {
            bail!("alias_cert must be 128 bytes, got {}", cert.len());
        }
        let (alias_pub, measurement, cert_sig) = (&cert[..32], &cert[32..64], &cert[64..]);

        // 1. The chip's ROM issued the certificate: DeviceID signed Alias key + measurement.
        verify(&device_id, &cert[..64], cert_sig).context("Alias certificate")?;

        // 2. The certified firmware produced this evidence: the Alias key signed REPORT_DATA.
        verify(alias_pub, &report_data, &signature).context("REPORT_DATA signature")?;

        // 3. The evidence belongs to this session: REPORT_DATA hashes the KBS nonce and the
        //    firmware's TEE public key, so a recording of an older session doesn't match.
        if let ReportData::Value(expected) = expected_report_data {
            if *expected != report_data {
                bail!("REPORT_DATA does not match this session's nonce and TEE public key");
            }
        }
        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("LiteX DICE chips have no init-data; ignoring it");
        }

        let claims = json!({
            "device_id": ev.device_id,
            "measurement": hex::encode(measurement),
            "alias_pub": hex::encode(alias_pub),
            "report_data": ev.report_data,
        });
        Ok(vec![(claims as TeeEvidenceParsedClaim, "cpu".to_string())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    /// Evidence as the lab chip produces it, for a chosen REPORT_DATA.
    fn evidence(
        device: &KeyPair,
        alias: &KeyPair,
        measurement: [u8; 32],
        report_data: &[u8],
    ) -> TeeEvidence {
        let mut tbs = alias.pk.to_vec();
        tbs.extend_from_slice(&measurement);
        let mut cert = tbs.clone();
        cert.extend_from_slice(device.sk.sign(&tbs, None).as_ref());
        json!({
            "device_id": hex::encode(*device.pk),
            "alias_cert": hex::encode(cert),
            "report_data": hex::encode(report_data),
            "signature": hex::encode(alias.sk.sign(report_data, None).as_ref()),
        })
    }

    #[tokio::test]
    async fn chain_and_binding() {
        let device = KeyPair::from_seed(Seed::new([1; 32]));
        let alias = KeyPair::from_seed(Seed::new([2; 32]));
        let other = KeyPair::from_seed(Seed::new([3; 32]));
        let session = [7u8; 48];
        let ok = |ev| async move {
            LitexDice::default()
                .evaluate(ev, &ReportData::Value(&session), &InitDataHash::NotProvided)
                .await
        };

        // Genuine chain, this session: claims come out.
        let claims = ok(evidence(&device, &alias, [9; 32], &session))
            .await
            .unwrap();
        assert_eq!(claims[0].0["measurement"], hex::encode([9u8; 32]));
        assert_eq!(claims[0].0["device_id"], hex::encode(*device.pk));

        // Evidence from another session (another nonce or TEE key).
        assert!(ok(evidence(&device, &alias, [9; 32], &[8u8; 48]))
            .await
            .is_err());

        // A certificate the chip's DeviceID key didn't sign.
        let mut forged = evidence(&device, &alias, [9; 32], &session);
        forged["device_id"] = json!(hex::encode(*other.pk));
        assert!(ok(forged).await.is_err());

        // A genuine certificate, but REPORT_DATA signed by a different key (the replay attack).
        let mut replay = evidence(&device, &alias, [9; 32], &session);
        replay["signature"] = json!(hex::encode(other.sk.sign(session, None).as_ref()));
        assert!(ok(replay).await.is_err());
    }
}
