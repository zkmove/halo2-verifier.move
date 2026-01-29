use crate::circuit::helpers::encode_field;
use bcs::Error as BcsError;
use byteorder::{LittleEndian, ReadBytesExt};
use halo2_backend::plonk::{
    ConstraintSystemBack as ConstraintSystem, ExpressionBack as Expression, VarBack,
};
use halo2_middleware::circuit::ChallengeMid as Challenge;
use halo2_proofs::arithmetic::{CurveAffine, Field};
use halo2_proofs::plonk::{Any, Error, ErrorFront};
use std::collections::HashMap;
use std::io::Cursor;
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Index {
    U8(u8),
    U32(u32),
}

impl Index {
    pub(crate) fn value(&self) -> u32 {
        match self {
            Index::U8(v) => *v as u32,
            Index::U32(v) => *v,
        }
    }
}

/// An expression where all field elements are replaced with indices into
/// a constant table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IndexedExpression<F: Field> {
    ConstantIndex(Index, PhantomData<F>),
    Fixed(Index),
    Advice(Index),
    Instance(Index),
    Challenge(Challenge),
    Negated(Box<IndexedExpression<F>>),
    Sum(Box<IndexedExpression<F>>, Box<IndexedExpression<F>>),
    Product(Box<IndexedExpression<F>>, Box<IndexedExpression<F>>),
    Scaled(Box<IndexedExpression<F>>, Index),
}
impl<F: Field> IndexedExpression<F> {
    fn write_identifier<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            IndexedExpression::ConstantIndex(index, _) => {
                write!(writer, "constant_index[{}]", index.value())
            }
            IndexedExpression::Fixed(index) => {
                write!(writer, "fixed_query[{}]", index.value())
            }
            IndexedExpression::Advice(index) => {
                write!(writer, "advice_query[{}]", index.value())
            }
            IndexedExpression::Instance(index) => {
                write!(writer, "instance_query[{}]", index.value())
            }
            IndexedExpression::Challenge(challenge) => {
                write!(writer, "challenge[{}]", challenge.index)
            }
            IndexedExpression::Negated(a) => {
                writer.write_all(b"(-")?;
                a.write_identifier(writer)?;
                writer.write_all(b")")
            }
            IndexedExpression::Sum(a, b) => {
                writer.write_all(b"(")?;
                a.write_identifier(writer)?;
                writer.write_all(b"+")?;
                b.write_identifier(writer)?;
                writer.write_all(b")")
            }
            IndexedExpression::Product(a, b) => {
                writer.write_all(b"(")?;
                a.write_identifier(writer)?;
                writer.write_all(b"*")?;
                b.write_identifier(writer)?;
                writer.write_all(b")")
            }
            IndexedExpression::Scaled(expr, index) => {
                expr.write_identifier(writer)?;
                write!(writer, "*constant_index[{}]", index.value())
            }
        }
    }

    #[allow(unused)]
    pub(crate) fn identifier(&self) -> String {
        let mut cursor = std::io::Cursor::new(Vec::new());
        self.write_identifier(&mut cursor).unwrap();
        String::from_utf8(cursor.into_inner()).unwrap()
    }
}

#[allow(clippy::only_used_in_recursion)]
pub(crate) fn to_indexed_expression<C: CurveAffine>(
    expr: &Expression<C::Scalar>,
    constant_map: &HashMap<Vec<u8>, u32>,
    use_u8_index_for_fields: bool,
    use_u8_index_for_query: bool,
    cs: &ConstraintSystem<C::Scalar>,
) -> Result<IndexedExpression<C::Scalar>, Error> {
    match expr {
        Expression::Constant(f) => {
            let bytes = encode_field::<C>(f);
            let index = *constant_map
                .get(&bytes)
                .ok_or(ErrorFront::Other("Constant not found".to_string()))?;
            let idx = if use_u8_index_for_fields {
                if index >= 256 {
                    return Err(ErrorFront::Other("Index exceeds limit".to_string()).into());
                }
                Index::U8(index as u8)
            } else {
                Index::U32(index)
            };
            Ok(IndexedExpression::ConstantIndex(idx, PhantomData))
        }
        Expression::Var(v) => match v {
            VarBack::Query(q) => {
                let index = q.index;
                let idx = if use_u8_index_for_query {
                    if index >= 256 {
                        return Err(ErrorFront::Other("Index exceeds limit".to_string()).into());
                    }
                    Index::U8(index as u8)
                } else {
                    Index::U32(index as u32)
                };
                match q.column_type {
                    Any::Fixed => Ok(IndexedExpression::Fixed(idx)),
                    Any::Advice => Ok(IndexedExpression::Advice(idx)),
                    Any::Instance => Ok(IndexedExpression::Instance(idx)),
                }
            }
            VarBack::Challenge(c) => Ok(IndexedExpression::Challenge(*c)),
        },
        Expression::Negated(e) => {
            let e_expr = to_indexed_expression::<C>(
                e,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            Ok(IndexedExpression::Negated(Box::new(e_expr)))
        }
        Expression::Sum(a, b) => {
            let a_expr = to_indexed_expression::<C>(
                a,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            let b_expr = to_indexed_expression::<C>(
                b,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            Ok(IndexedExpression::Sum(Box::new(a_expr), Box::new(b_expr)))
        }
        Expression::Product(a, b) => {
            let a_expr = to_indexed_expression::<C>(
                a,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            let b_expr = to_indexed_expression::<C>(
                b,
                constant_map,
                use_u8_index_for_fields,
                use_u8_index_for_query,
                cs,
            )?;
            if let IndexedExpression::ConstantIndex(idx, _) = &a_expr {
                Ok(IndexedExpression::Scaled(Box::new(b_expr), *idx))
            } else if let IndexedExpression::ConstantIndex(idx, _) = &b_expr {
                Ok(IndexedExpression::Scaled(Box::new(a_expr), *idx))
            } else {
                Ok(IndexedExpression::Product(
                    Box::new(a_expr),
                    Box::new(b_expr),
                ))
            }
        }
    }
}

pub(crate) fn serialize_index(
    buffer: &mut Vec<u8>,
    index: &Index,
    use_u8: bool,
) -> bcs::Result<()> {
    match index {
        Index::U8(idx) => {
            if !use_u8 {
                return Err(BcsError::Custom(
                    "use_u8=false but found U8 index (inconsistent flag)".to_string(),
                ));
            }
            buffer.push(*idx);
        }
        Index::U32(idx) => {
            if use_u8 {
                return Err(BcsError::Custom(
                    "use_u8=true but found U32 index (inconsistent flag)".to_string(),
                ));
            }
            buffer.extend(idx.to_le_bytes());
        }
    }
    Ok(())
}

/// Serializes IndexedExpression to custom binary format:
/// tag (1 byte) + payload
/// Tags:
/// 0x00 - ConstantIndex: tag + index (u8/u32)
/// 0x02 - Fixed:       tag + index
/// 0x03 - Advice:      tag + index
/// 0x04 - Instance:    tag + index
/// 0x05 - Challenge:   tag + u32 index
/// 0x06 - Negated:     tag + child expr
/// 0x07 - Sum:         tag + left + right
/// 0x08 - Product:     tag + left + right
/// 0x09 - Scaled:      tag + child expr + scalar index
pub(crate) fn serialize_expression<C: CurveAffine>(
    expr: &IndexedExpression<C::Scalar>,
    buffer: &mut Vec<u8>,
    use_u8_index_for_fields: bool,
    use_u8_index_for_query: bool,
) -> bcs::Result<()> {
    match expr {
        IndexedExpression::ConstantIndex(index, _) => {
            buffer.push(0x00);
            serialize_index(buffer, index, use_u8_index_for_fields)?;
        }
        IndexedExpression::Fixed(index) => {
            buffer.push(0x02);
            serialize_index(buffer, index, use_u8_index_for_query)?;
        }
        IndexedExpression::Advice(index) => {
            buffer.push(0x03);
            serialize_index(buffer, index, use_u8_index_for_query)?;
        }
        IndexedExpression::Instance(index) => {
            buffer.push(0x04);
            serialize_index(buffer, index, use_u8_index_for_query)?;
        }
        IndexedExpression::Challenge(challenge) => {
            buffer.push(0x05);
            let index = challenge.index() as u32;
            buffer.extend(index.to_le_bytes());
        }
        IndexedExpression::Negated(expr) => {
            buffer.push(0x06);
            serialize_expression::<C>(
                expr,
                buffer,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            )?;
        }
        IndexedExpression::Sum(a, b) => {
            buffer.push(0x07);
            serialize_expression::<C>(a, buffer, use_u8_index_for_fields, use_u8_index_for_query)?;
            serialize_expression::<C>(b, buffer, use_u8_index_for_fields, use_u8_index_for_query)?;
        }
        IndexedExpression::Product(a, b) => {
            buffer.push(0x08);
            serialize_expression::<C>(a, buffer, use_u8_index_for_fields, use_u8_index_for_query)?;
            serialize_expression::<C>(b, buffer, use_u8_index_for_fields, use_u8_index_for_query)?;
        }
        IndexedExpression::Scaled(expr, index) => {
            buffer.push(0x09);
            serialize_expression::<C>(
                expr,
                buffer,
                use_u8_index_for_fields,
                use_u8_index_for_query,
            )?;
            serialize_index(buffer, index, use_u8_index_for_fields)?;
        }
    }
    Ok(())
}

pub(crate) fn deserialize_expression<C: CurveAffine>(
    cursor: &mut Cursor<&[u8]>,
    use_u8_fields: bool,
    use_u8_query: bool,
    challenge_phase: &Vec<u8>,
) -> bcs::Result<IndexedExpression<C::Scalar>> {
    let tag = cursor
        .read_u8()
        .map_err(|e| BcsError::Custom(e.to_string()))?;

    match tag {
        0x00 => {
            let idx = if use_u8_fields {
                Index::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                Index::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::ConstantIndex(idx, PhantomData))
        }
        0x02 => {
            let idx = if use_u8_query {
                Index::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                Index::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::Fixed(idx))
        }
        0x03 => {
            let idx = if use_u8_query {
                Index::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                Index::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::Advice(idx))
        }
        0x04 => {
            let idx = if use_u8_query {
                Index::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                Index::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::Instance(idx))
        }
        0x05 => {
            let idx = cursor
                .read_u32::<LittleEndian>()
                .map_err(|e| BcsError::Custom(e.to_string()))?;
            if idx as usize >= challenge_phase.len() {
                return Err(BcsError::Custom(format!(
                    "Challenge index {} out of bounds",
                    idx
                )));
            }
            let phase = challenge_phase[idx as usize];
            Ok(IndexedExpression::Challenge(Challenge {
                index: idx as usize,
                phase,
            }))
        }
        0x06 => {
            let inner =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            Ok(IndexedExpression::Negated(Box::new(inner)))
        }
        0x07 => {
            let a =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            let b =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            Ok(IndexedExpression::Sum(Box::new(a), Box::new(b)))
        }
        0x08 => {
            let a =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            let b =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            Ok(IndexedExpression::Product(Box::new(a), Box::new(b)))
        }
        0x09 => {
            let expr =
                deserialize_expression::<C>(cursor, use_u8_fields, use_u8_query, challenge_phase)?;
            let idx = if use_u8_fields {
                Index::U8(
                    cursor
                        .read_u8()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            } else {
                Index::U32(
                    cursor
                        .read_u32::<LittleEndian>()
                        .map_err(|e| BcsError::Custom(e.to_string()))?,
                )
            };
            Ok(IndexedExpression::Scaled(Box::new(expr), idx))
        }
        _ => Err(BcsError::Custom(format!(
            "Unknown expression tag: 0x{:02x}",
            tag
        ))),
    }
}

pub(crate) fn serialize_exprs<C: CurveAffine>(
    exprs: &[IndexedExpression<C::Scalar>],
    use_u8_index_for_fields: bool,
    use_u8_index_for_query: bool,
) -> bcs::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for expr in exprs {
        serialize_expression::<C>(
            expr,
            &mut bytes,
            use_u8_index_for_fields,
            use_u8_index_for_query,
        )?;
    }
    Ok(bytes)
}

pub(crate) fn deserialize_exprs<C: CurveAffine>(
    bytes: &[u8],
    use_u8_fields: bool,
    use_u8_query: bool,
    challenge_phase: &Vec<u8>,
) -> bcs::Result<Vec<IndexedExpression<C::Scalar>>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let mut cursor = Cursor::new(bytes);
    let mut exprs = Vec::new();

    while cursor.position() < bytes.len() as u64 {
        let expr =
            deserialize_expression::<C>(&mut cursor, use_u8_fields, use_u8_query, challenge_phase)?;
        exprs.push(expr);
    }

    if cursor.position() as usize != bytes.len() {
        return Err(BcsError::Custom(
            "Trailing bytes in expression data".to_string(),
        ));
    }

    Ok(exprs)
}
