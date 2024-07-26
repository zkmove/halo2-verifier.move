use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::CurveExt;
use halo2_proofs::halo2curves::ff::{FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::halo2curves::pairing::{Engine, MultiMillerLoop};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::plonk::{create_proof, verify_proof, Circuit, ProvingKey};
use halo2_proofs::poly::commitment::{CommitmentScheme, ParamsProver, Prover, Verifier};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_proofs::poly::{kzg, VerificationStrategy};
use halo2_proofs::transcript::{
    Challenge255, Keccak256Read, Keccak256Write, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use std::fmt::Debug;

pub use halo2_proofs::plonk::{keygen_pk, keygen_vk};
use rand_core::OsRng;

pub fn prove_with_gwc_and_keccak256<E, ConcreteCircuit>(
    circuit: ConcreteCircuit,
    instance: &[&[E::Fr]],
    params: &ParamsKZG<E>,
    pk: ProvingKey<E::G1Affine>,
) -> Vec<u8>
where
    E: Engine + Debug + MultiMillerLoop,
    E::G1Affine:
        SerdeObject + CurveAffine<ScalarExt = <E as Engine>::Fr, CurveExt = <E as Engine>::G1>,
    E::G1: CurveExt<AffineExt = E::G1Affine>,
    E::G2Affine: SerdeObject + CurveAffine,
    ConcreteCircuit: Circuit<E::Fr>,
    <E as Engine>::Fr: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    prove_vm_circuit::<
        KZGCommitmentScheme<E>,
        ProverGWC<E>,
        VerifierGWC<E>,
        kzg::strategy::SingleStrategy<E>,
        _,
    >(circuit, instance, params, pk)
}

// prove circuit,return it proof.
fn prove_vm_circuit<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    V: Verifier<'params, Scheme>,
    Strategy: VerificationStrategy<'params, Scheme, V>,
    ConcreteCircuit: Circuit<Scheme::Scalar>,
>(
    circuit: ConcreteCircuit,
    instance: &[&[Scheme::Scalar]],
    params: &'params Scheme::ParamsProver,
    pk: ProvingKey<Scheme::Curve>,
) -> Vec<u8>
where
    <Scheme as CommitmentScheme>::ParamsVerifier: 'params,
    <Scheme as CommitmentScheme>::Scalar: WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let mut transcript = Keccak256Write::<_, _, Challenge255<_>>::init(vec![]);
    // Create a proof
    let prove_start = std::time::Instant::now();

    create_proof::<Scheme, P, _, _, _, _>(
        params,
        &pk,
        &[circuit],
        &[instance],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();
    println!("proof size {} bytes", proof.len());
    let prove_time = std::time::Instant::now().duration_since(prove_start);
    println!("prove time: {} ms", prove_time.as_millis());

    let verifier_params = params.verifier_params();
    let strategy = Strategy::new(verifier_params);
    let mut transcript = Keccak256Read::<_, _, Challenge255<_>>::init(&proof[..]);
    let verify_start = std::time::Instant::now();
    let result = verify_proof(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[instance],
        &mut transcript,
    );

    let verify_time = std::time::Instant::now().duration_since(verify_start);
    println!("verify time: {} ms", verify_time.as_millis());
    assert!(result.is_ok());
    proof
}
