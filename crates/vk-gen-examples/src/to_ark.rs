use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::CurveConfig;
use ark_serialize::CanonicalDeserialize;
use halo2_base::halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::CurveAffine;

pub trait IntoArk: CurveAffine {
    type ArkConfig: SWCurveConfig;

    fn to_ark(&self) -> ark_ec::short_weierstrass::Affine<Self::ArkConfig> {
        if self.coordinates().is_some().into() {
            let point = self.coordinates().unwrap();
            let x = <Self::ArkConfig as CurveConfig>::BaseField::deserialize_uncompressed(
                point.x().to_repr().as_ref(),
            )
            .unwrap();
            let y = <Self::ArkConfig as CurveConfig>::BaseField::deserialize_uncompressed(
                point.y().to_repr().as_ref(),
            )
            .unwrap();
            ark_ec::short_weierstrass::Affine::<Self::ArkConfig>::new(x, y)
        } else {
            ark_ec::short_weierstrass::Affine::<Self::ArkConfig>::identity()
        }
    }
}

impl IntoArk for G1Affine {
    type ArkConfig = ark_bn254::g1::Config;
}
impl IntoArk for G2Affine {
    type ArkConfig = ark_bn254::g2::Config;
}
