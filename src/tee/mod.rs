use std::any::Any;

use crate::errors::*;

pub mod claims;
pub mod sgx_dcap;

/// Trait representing generic evidence.
pub trait GenericEvidence: Any {
    /// Return the CBOR tag used for generating DICE cert.
    fn get_dice_cbor_tag(&self) -> u64;

    /// Return the raw evidence data used for generating DICE cert.
    fn get_raw_evidence_dice(&self) -> &[u8];

    /// Return the type of Trusted Execution Environment (TEE) associated with the evidence.
    fn get_tee_type(&self) -> TeeType;
}

/// Trait representing a generic attester.
pub trait GenericAttester {
    type Evidence: GenericEvidence;

    /// Generate evidence based on the provided report data.
    fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence>;
}

/// Trait representing a generic verifier.
pub trait GenericVerifier {
    type Evidence: GenericEvidence;

    /// Verifiy the provided evidence against the given report data and return claims if verification succeeds.
    fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &[u8],
    ) -> Result<claims::Claims>;
}

/// Enum representing different types of TEEs.
#[derive(Debug,PartialEq)]
pub enum TeeType {
    SgxDcap,
}

impl TeeType {
    /// Detects the current TEE environment and returns the detected TeeType.
    fn detect_env() -> Option<Self> {
        #[cfg(feature = "attester-sgx-dcap")]
        if sgx_dcap::attester::detect_env() {
            return Some(Self::SgxDcap);
        }
        return None;
    }
}

/// A evidence wrapper struct representing evidence generated by `AutoAttester`.
pub struct AutoEvidence(Box<dyn GenericEvidence>);

impl AutoEvidence{
    /// Create evidence from cbor tag and raw evidence of a DICE cert.
    pub(crate) fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> Result<Self> {
        if let Some(res) = sgx_dcap::evidence::create_evidence_from_dice(cbor_tag, raw_evidence) {
            return res.map(|res| Self(Box::new(res)));
        }
        return Err(Error::kind_with_msg(
            ErrorKind::UnrecognizedEvidenceType,
            format!(
                "Unrecognized evidence type, cbor_tag: {:#x?}, raw_evidence: {:02x?}",
                cbor_tag, raw_evidence
            ),
        ));
    }
}

impl GenericEvidence for AutoEvidence {
    fn get_dice_cbor_tag(&self) -> u64 {
        self.0.get_dice_cbor_tag()
    }

    fn get_raw_evidence_dice(&self) -> &[u8] {
        self.0.get_raw_evidence_dice()
    }

    fn get_tee_type(&self) -> TeeType {
        self.0.get_tee_type()
    }
}

/// A attester wrapper for automatically selecting and managing different attester implementations based on the detected TEE environment.
pub struct AutoAttester {}


impl AutoAttester{
    pub fn new()->Self{
        Self{}
    }
}

impl GenericAttester for AutoAttester {
    type Evidence = AutoEvidence;

    fn get_evidence(&self, report_data: &[u8]) -> Result<Self::Evidence> {
        let tee_type = TeeType::detect_env();

        if let Some(tee_type) = tee_type {
            match tee_type {
                #[cfg(feature = "attester-sgx-dcap")]
                TeeType::SgxDcap => {
                    let attester = sgx_dcap::attester::SgxDcapAttester::new();
                    attester.get_evidence(report_data).map(|ev|AutoEvidence(Box::new(ev) as Box<dyn GenericEvidence>)) 
                }
                #[allow(unreachable_patterns)]
                _ => {
                    Err(Error::kind_with_msg(
                        ErrorKind::UnsupportedTeeType,
                        format!("No attester for TEE type {tee_type:?}, the corresponding features (like `attester-*`) may be missing.")
                    ))
                }
            }
        } else {
            Err(Error::kind_with_msg(
                ErrorKind::UnsupportedTeeType,
                format!("No TEE was detected on this environment, or the corresponding features (like `attester-*`) may be missing.")
            ))
        }
    }
}

pub struct AutoVerifier {}

impl AutoVerifier{
    pub fn new()->Self{
        Self{}
    }
}

/// A verifier wrapper for verifying `AutoEvidence` by automatically selecting different verifier implementations based on the underlying evidence type of `AutoEvidence`.
impl GenericVerifier for AutoVerifier {
    type Evidence = AutoEvidence;
    
    fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &[u8],
    ) -> Result<claims::Claims> {
        let tee_type = evidence.0.get_tee_type();
        let evidence = evidence.0.as_ref()as &dyn Any;
        match tee_type {
            #[cfg(feature = "verifier-sgx-dcap")]
            TeeType::SgxDcap => {
                match evidence.downcast_ref::<_>() {
                    Some(ev) => {
                        return sgx_dcap::verifier::SgxDcapVerifier::new().verify_evidence(ev, report_data);
                    },
                    None => unreachable!("bug deteccted"),
                }
            }
            #[allow(unreachable_patterns)]
            _ => {
                Err(Error::kind_with_msg(
                    ErrorKind::UnsupportedTeeType,
                    format!("no verifier for tee type {tee_type:?}, the corresponding features (like `verifier-*`) may be missing.")
                ))
            }
        }
    }
}


#[cfg(test)]
pub mod tests {
    use tests::claims::{BUILT_IN_CLAIM_COMMON_QUOTE, BUILT_IN_CLAIM_COMMON_QUOTE_TYPE};

    use crate::errors::*;

    use super::*;

    #[test]
    fn test_auto_attester_and_auto_verifier_on_sgx_dcap() -> Result<()> {
        if TeeType::detect_env() != Some(TeeType::SgxDcap) {
            /* skip */
            return Ok(());
        }

        let report_data = b"test_report_data";
        let attester = AutoAttester::new();
        let evidence = attester.get_evidence(report_data)?;
        assert_eq!(evidence.get_tee_type(), TeeType::SgxDcap);
        let verifier = AutoVerifier::new();
        let claims = verifier.verify_evidence(&evidence, report_data)?;
        println!("generated claims:\n{:?}", claims);

        assert!(claims.contains_key(BUILT_IN_CLAIM_COMMON_QUOTE));
        assert!(claims.contains_key(BUILT_IN_CLAIM_COMMON_QUOTE_TYPE));
        
        Ok(())
    }


    #[test]
    fn test_auto_attester_and_auto_verifier_on_tee() -> Result<()> {
        if TeeType::detect_env() != None {
            /* skip */
            return Ok(());
        }
    
        let report_data = b"test_report_data";
        let attester = AutoAttester::new();
        let res = attester.get_evidence(report_data);
        assert!(res.is_err());
        let Err(err) = res else {panic!()};
        assert_eq!(err.get_kind(), ErrorKind::UnsupportedTeeType);
        Ok(())
    }
}


