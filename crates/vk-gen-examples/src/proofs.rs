use halo2_backend::transcript::{Keccak256Read, Keccak256Write};
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{
        ff::{FromUniformBytes, WithSmallOrderMulGroup},
        pairing::{Engine, MultiMillerLoop},
        serde::SerdeObject,
        CurveExt,
    },
    plonk::{create_proof, verify_proof, Circuit, Error, ProvingKey, VerifyingKey},
    poly::{
        commitment::{CommitmentScheme, Prover, Verifier},
        kzg::strategy::SingleStrategy,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
        VerificationStrategy,
    },
    transcript::{Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand::prelude::StdRng;
use rand::SeedableRng;
use std::fmt::{Debug, Formatter};

#[derive(Copy, Clone, Debug)]
pub enum KZG {
    GWC,
    SHPLONK,
}

impl KZG {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::SHPLONK => 0,
            Self::GWC => 1,
        }
    }
}
impl std::fmt::Display for KZG {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GWC => write!(f, "gwc"),
            Self::SHPLONK => write!(f, "shplonk"),
        }
    }
}

/// Proves a circuit using the SHPLONK multi-opening scheme with KZG commitments.
///
/// # Arguments
/// - `circuit`: The circuit to prove.
/// - `instance`: The public inputs for the circuit.
/// - `params`: The KZG parameters for the curve.
/// - `pk`: The proving key.
///
/// # Returns
/// The proof as a byte vector if successful.
pub fn prove_circuit<E, ConcreteCircuit>(
    circuit: ConcreteCircuit,
    instance: &[Vec<E::Fr>],
    params: &ParamsKZG<E>,
    pk: &ProvingKey<E::G1Affine>,
    kzg: KZG,
) -> Result<Vec<u8>, Error>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    ConcreteCircuit: Circuit<E::Fr>,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    match kzg {
        KZG::GWC => prove_circuit_inner::<KZGCommitmentScheme<E>, ProverGWC<E>, _>(
            circuit, instance, params, pk,
        ),
        KZG::SHPLONK => prove_circuit_inner::<KZGCommitmentScheme<E>, ProverSHPLONK<E>, _>(
            circuit, instance, params, pk,
        ),
    }
}
fn prove_circuit_inner<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    ConcreteCircuit: Circuit<Scheme::Scalar>,
>(
    circuit: ConcreteCircuit,
    instance: &[Vec<Scheme::Scalar>],
    params: &'params Scheme::ParamsProver,
    pk: &ProvingKey<Scheme::Curve>,
) -> Result<Vec<u8>, Error>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let mut transcript = Keccak256Write::<Vec<u8>, _, Challenge255<_>>::init(vec![]);

    // Create a proof
    // let rng = StdRng::seed_from_u64(42);
    let rng = StdRng::from_entropy();
    create_proof::<Scheme, P, _, _, _, _>(
        params,
        pk,
        &[circuit],
        &[instance.to_owned()],
        rng,
        &mut transcript,
    )?;
    let proof: Vec<u8> = transcript.finalize();

    Ok(proof)
}

/// Verifies a circuit proof using the SHPLONK multi-opening scheme with KZG commitments.
///
/// # Arguments
/// - `instance`: The public inputs for the circuit.
/// - `params`: The KZG parameters for the curve.
/// - `vk`: The verification key.
/// - `proof`: The proof bytes to verify.
///
/// # Returns
/// `Ok(())` if the proof is valid, or an error if verification fails.
pub fn verify_circuit<E>(
    instance: &[Vec<E::Fr>],
    params: &ParamsKZG<E>,
    vk: &VerifyingKey<E::G1Affine>,
    proof: &[u8],
    kzg: KZG,
) -> Result<(), Error>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    match kzg {
        KZG::GWC => {
            verify_circuit_inner::<KZGCommitmentScheme<E>, VerifierGWC<E>, SingleStrategy<E>>(
                instance,
                &params.verifier_params(),
                vk,
                proof,
            )
        }
        KZG::SHPLONK => verify_circuit_inner::<
            KZGCommitmentScheme<E>,
            VerifierSHPLONK<E>,
            SingleStrategy<E>,
        >(instance, &params.verifier_params(), vk, proof),
    }
}
fn verify_circuit_inner<
    'params,
    Scheme: CommitmentScheme,
    V: Verifier<'params, Scheme>,
    Strategy: VerificationStrategy<'params, Scheme, V>,
>(
    instance: &[Vec<Scheme::Scalar>],
    params: &'params Scheme::ParamsVerifier,
    vk: &VerifyingKey<Scheme::Curve>,
    proof: &[u8],
) -> Result<(), Error>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let strategy = Strategy::new(params);
    let mut transcript = Keccak256Read::<_, _, Challenge255<_>>::init(proof);
    let _result = verify_proof(
        params,
        vk,
        strategy,
        &[instance.to_owned()],
        &mut transcript,
    )?;

    Ok(())
}
