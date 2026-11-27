//! LC-Vantablack — Lagrange coded private, straggler-tolerant, Byzantine-
//! resilient inference over `F_p` (`DEV/INVENTIONS_AND_PROOFS.md` Invention 10,
//! V3 Stage 7).
//!
//! Raw byte RS(2,1) in [`super`] only commutes with byte-linear operations, so an
//! arbitrary activation or attention layer destroys the code. Here the client
//! encodes `K` quantized input tensors plus `T` uniform mask tensors into a
//! Lagrange polynomial `u(z)` of degree `K + T - 1`, sends `u(alpha_i)` to `N`
//! workers, and each worker evaluates a degree-`d` layer element-wise. The
//! composite `h(z) = f(u(z))` is a degree-`d(K+T-1)` polynomial, i.e. a
//! Reed-Solomon codeword, so the client recovers `f(X_1)..f(X_K)` by
//! Berlekamp–Welch decoding while tolerating `S` silent stragglers and `A`
//! arbitrary Byzantine outputs whenever
//!
//! ```text
//! N >= d(K + T - 1) + 1 + S + 2A
//! ```
//!
//! The `T` masks make the workers' view information-theoretically independent
//! of the inputs: for any observed evaluation and any candidate input there is
//! exactly one mask assignment producing it.

use std::fmt;

use rand::rngs::OsRng;
use rand::RngCore;

pub const FIELD: u64 = 2_147_483_647;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LccError {
    Shape(&'static str),
    TooFewEvaluations {
        need: usize,
        got: usize,
    },
    Undecodable,
    OutOfField(u64),
}

impl fmt::Display for LccError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape(msg) => write!(f, "{msg}"),
            Self::TooFewEvaluations { need, got } => {
                write!(f, "need {need} usable evaluations, got {got}")
            }
            Self::Undecodable => write!(f, "more errors than the code can correct"),
            Self::OutOfField(v) => write!(f, "{v} is not a canonical field element"),
        }
    }
}

impl std::error::Error for LccError {}

fn add(a: u64, b: u64) -> u64 {
    (a + b) % FIELD
}

fn sub(a: u64, b: u64) -> u64 {
    (a + FIELD - b % FIELD) % FIELD
}

fn mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % FIELD as u128) as u64
}

fn pow(mut base: u64, mut exponent: u64) -> u64 {
    let mut acc = 1u64;
    base %= FIELD;
    while exponent > 0 {
        if exponent & 1 == 1 {
            acc = mul(acc, base);
        }
        base = mul(base, base);
        exponent >>= 1;
    }
    acc
}

fn inverse(a: u64) -> Option<u64> {
    if a.is_multiple_of(FIELD) {
        None
    } else {
        Some(pow(a % FIELD, FIELD - 2))
    }
}

fn random_element() -> u64 {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    u64::from_be_bytes(bytes) % FIELD
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LccTask {
    pub worker_index: usize,
    pub alpha: u64,
    pub assigned_asn: u32,
    pub vector: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LccOutput {
    pub worker_index: usize,
    pub alpha: u64,
    pub vector: Vec<u64>,
}

pub fn apply_layer(layer: &[u64], task: &LccTask) -> LccOutput {
    let vector = task
        .vector
        .iter()
        .map(|&value| {
            let mut acc = 0u64;
            for coefficient in layer.iter().rev() {
                acc = add(mul(acc, value), *coefficient);
            }
            acc
        })
        .collect();
    LccOutput {
        worker_index: task.worker_index,
        alpha: task.alpha,
        vector,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LagrangeCodedInference {
    data_symbols: usize,
    masks: usize,
}

impl LagrangeCodedInference {
    pub fn new(data_symbols: usize, masks: usize) -> Result<Self, LccError> {
        if data_symbols == 0 || masks == 0 {
            return Err(LccError::Shape("K and T must both be at least 1"));
        }
        Ok(Self {
            data_symbols,
            masks,
        })
    }

    pub fn data_symbols(&self) -> usize {
        self.data_symbols
    }

    pub fn masks(&self) -> usize {
        self.masks
    }

    pub fn composite_degree(&self, layer_degree: usize) -> usize {
        layer_degree * (self.data_symbols + self.masks - 1)
    }

    pub fn required_workers(
        &self,
        layer_degree: usize,
        stragglers: usize,
        byzantine: usize,
    ) -> usize {
        self.composite_degree(layer_degree) + 1 + stragglers + 2 * byzantine
    }

    pub fn encode(
        &self,
        inputs: &[Vec<u64>],
        worker_asns: &[u32],
    ) -> Result<Vec<LccTask>, LccError> {
        let masks: Vec<Vec<u64>> = (0..self.masks)
            .map(|_| {
                let width = inputs.first().map_or(0, Vec::len);
                (0..width).map(|_| random_element()).collect()
            })
            .collect();
        self.encode_with_masks(inputs, &masks, worker_asns)
    }

    pub fn encode_with_masks(
        &self,
        inputs: &[Vec<u64>],
        masks: &[Vec<u64>],
        worker_asns: &[u32],
    ) -> Result<Vec<LccTask>, LccError> {
        if inputs.len() != self.data_symbols {
            return Err(LccError::Shape("one input tensor per data symbol"));
        }
        if masks.len() != self.masks {
            return Err(LccError::Shape("one mask tensor per mask symbol"));
        }
        let width = inputs.first().map_or(0, Vec::len);
        if width == 0 {
            return Err(LccError::Shape("input tensors must not be empty"));
        }
        if let Some(bad) = inputs.iter().chain(masks.iter()).find(|t| t.len() != width) {
            let _ = bad;
            return Err(LccError::Shape("every tensor must have the same width"));
        }
        if worker_asns.is_empty() {
            return Err(LccError::Shape("no workers assigned"));
        }
        for tensor in inputs.iter().chain(masks.iter()) {
            if let Some(&value) = tensor.iter().find(|&&v| v >= FIELD) {
                return Err(LccError::OutOfField(value));
            }
        }

        let mut tasks = Vec::with_capacity(worker_asns.len());
        for (worker_index, &assigned_asn) in worker_asns.iter().enumerate() {
            let alpha = (self.data_symbols + self.masks + 1 + worker_index) as u64;
            let vector = (0..width)
                .map(|symbol| {
                    let points: Vec<(u64, u64)> = (0..self.data_symbols)
                        .map(|j| ((j + 1) as u64, inputs[j][symbol]))
                        .chain(
                            (0..self.masks)
                                .map(|m| ((self.data_symbols + m + 1) as u64, masks[m][symbol])),
                        )
                        .collect();
                    let coefficients = interpolate_coefficients(&points);
                    evaluate(&coefficients, alpha)
                })
                .collect();
            tasks.push(LccTask {
                worker_index,
                alpha,
                assigned_asn,
                vector,
            });
        }
        Ok(tasks)
    }

    pub fn decode(
        &self,
        outputs: &[Option<LccOutput>],
        layer_degree: usize,
        byzantine: usize,
    ) -> Result<Vec<Vec<u64>>, LccError> {
        let degree = self.composite_degree(layer_degree);
        let usable: Vec<&LccOutput> = outputs.iter().flatten().collect();
        let need = degree + 2 * byzantine + 1;
        if usable.len() < need {
            return Err(LccError::TooFewEvaluations {
                need,
                got: usable.len(),
            });
        }
        let width = usable[0].vector.len();
        if usable.iter().any(|o| o.vector.len() != width) {
            return Err(LccError::Shape("worker vectors disagree in width"));
        }

        let mut recovered = vec![vec![0u64; width]; self.data_symbols];
        for symbol in 0..width {
            let points: Vec<(u64, u64)> =
                usable.iter().map(|o| (o.alpha, o.vector[symbol])).collect();
            let codeword = berlekamp_welch(&points, degree, byzantine)?;
            for (index, slot) in recovered.iter_mut().enumerate() {
                slot[symbol] = evaluate(&codeword, index as u64 + 1);
            }
        }
        Ok(recovered)
    }
}

fn interpolate_coefficients(points: &[(u64, u64)]) -> Vec<u64> {
    let mut coefficients = vec![0u64; points.len()];
    for (j, &(x_j, y_j)) in points.iter().enumerate() {
        let mut basis = vec![1u64];
        let mut denominator = 1u64;
        for (m, &(x_m, _)) in points.iter().enumerate() {
            if m == j {
                continue;
            }
            let mut next = vec![0u64; basis.len() + 1];
            for (i, coefficient) in basis.iter().enumerate() {
                next[i + 1] = add(next[i + 1], *coefficient);
                next[i] = sub(next[i], mul(*coefficient, x_m));
            }
            basis = next;
            denominator = mul(denominator, sub(x_j, x_m));
        }
        let scale = mul(y_j, inverse(denominator).unwrap_or(0));
        for (i, coefficient) in basis.iter().enumerate() {
            coefficients[i] = add(coefficients[i], mul(scale, *coefficient));
        }
    }
    coefficients
}

fn evaluate(coefficients: &[u64], x: u64) -> u64 {
    coefficients
        .iter()
        .rev()
        .fold(0u64, |acc, coeff| add(mul(acc, x), *coeff))
}

fn berlekamp_welch(
    points: &[(u64, u64)],
    degree: usize,
    errors: usize,
) -> Result<Vec<u64>, LccError> {
    let unknowns = degree + 2 * errors + 1;
    if points.len() < unknowns {
        return Err(LccError::TooFewEvaluations {
            need: unknowns,
            got: points.len(),
        });
    }
    let mut matrix = vec![vec![0u64; unknowns + 1]; points.len()];
    for (row, &(x, y)) in points.iter().enumerate() {
        let mut power = 1u64;
        for slot in matrix[row].iter_mut().take(degree + errors + 1) {
            *slot = power;
            power = mul(power, x);
        }
        let mut power = 1u64;
        for offset in 0..errors {
            matrix[row][degree + errors + 1 + offset] = sub(0, mul(y, power));
            power = mul(power, x);
        }
        let mut rhs = y;
        for _ in 0..errors {
            rhs = mul(rhs, x);
        }
        matrix[row][unknowns] = rhs;
    }

    let solution = solve_mod(matrix, unknowns)?;
    let q = &solution[..=degree + errors];
    let mut e = vec![0u64; errors + 1];
    for offset in 0..errors {
        e[offset] = solution[degree + errors + 1 + offset];
    }
    e[errors] = 1;
    divide(q, &e)
}

fn solve_mod(mut matrix: Vec<Vec<u64>>, vars: usize) -> Result<Vec<u64>, LccError> {
    let rows = matrix.len();
    let mut pivot = 0usize;
    for column in 0..vars {
        let found = (pivot..rows).find(|&r| matrix[r][column] != 0);
        let Some(found) = found else {
            return Err(LccError::Undecodable);
        };
        matrix.swap(pivot, found);
        let scale = inverse(matrix[pivot][column]).ok_or(LccError::Undecodable)?;
        for slot in matrix[pivot].iter_mut().skip(column) {
            *slot = mul(*slot, scale);
        }
        for row in 0..rows {
            if row == pivot {
                continue;
            }
            let factor = matrix[row][column];
            if factor == 0 {
                continue;
            }
            let pivot_row = matrix[pivot][column..=vars].to_vec();
            for (slot, base) in matrix[row][column..=vars].iter_mut().zip(pivot_row.iter()) {
                *slot = sub(*slot, mul(factor, *base));
            }
        }
        pivot += 1;
        if pivot == rows {
            break;
        }
    }

    let mut solution = vec![0u64; vars];
    for row in matrix.iter().take(pivot) {
        if let Some(column) = (0..vars).find(|&c| row[c] != 0) {
            solution[column] = row[vars];
        }
    }
    Ok(solution)
}

fn divide(numerator: &[u64], denominator: &[u64]) -> Result<Vec<u64>, LccError> {
    let den_degree = denominator.len() - 1;
    if numerator.len() <= den_degree {
        return Err(LccError::Undecodable);
    }
    let mut remainder = numerator.to_vec();
    let lead_inverse = inverse(denominator[den_degree]).ok_or(LccError::Undecodable)?;
    let mut quotient = vec![0u64; numerator.len() - den_degree];
    for shift in (0..quotient.len()).rev() {
        let coefficient = mul(remainder[shift + den_degree], lead_inverse);
        quotient[shift] = coefficient;
        for offset in 0..=den_degree {
            let term = mul(coefficient, denominator[offset]);
            remainder[shift + offset] = sub(remainder[shift + offset], term);
        }
    }
    if remainder.iter().any(|&value| value != 0) {
        return Err(LccError::Undecodable);
    }
    while quotient.len() > 1 && quotient.last() == Some(&0) {
        quotient.pop();
    }
    Ok(quotient)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asns(n: usize) -> Vec<u32> {
        (0..n).map(|i| 13_000 + i as u32).collect()
    }

    #[test]
    fn the_worker_bound_is_the_theorem_bound() {
        let linear = LagrangeCodedInference::new(1, 1).unwrap();
        assert_eq!(linear.required_workers(1, 1, 1), 5);
        assert_eq!(linear.required_workers(1, 0, 0), 2);
        assert_eq!(linear.required_workers(2, 0, 1), 2 + 1 + 2);
        let two_inputs = LagrangeCodedInference::new(2, 1).unwrap();
        assert_eq!(two_inputs.composite_degree(1), 2);
        assert_eq!(two_inputs.required_workers(1, 1, 0), 4);
        assert!(LagrangeCodedInference::new(0, 1).is_err());
        assert!(LagrangeCodedInference::new(1, 0).is_err());
    }

    #[test]
    fn a_linear_layer_survives_one_straggler_and_one_liar() {
        let code = LagrangeCodedInference::new(1, 1).unwrap();
        let workers = code.required_workers(1, 1, 1);
        let input = vec![7u64];
        let mask = vec![123_456_789u64];
        let tasks = code
            .encode_with_masks(std::slice::from_ref(&input), &[mask], &asns(workers))
            .expect("encodes");
        assert_eq!(tasks.len(), workers);

        let layer = vec![3u64, 2u64];
        let mut outputs: Vec<Option<LccOutput>> = tasks
            .iter()
            .map(|task| Some(apply_layer(&layer, task)))
            .collect();
        outputs[0] = None; // straggler
        let liar = outputs[3].as_ref().unwrap().clone();
        outputs[3] = Some(LccOutput {
            vector: liar.vector.iter().map(|&v| add(v, 1000)).collect(),
            ..liar
        });

        let recovered = code.decode(&outputs, 1, 1).expect("decodes");
        assert_eq!(recovered, vec![vec![2 * 7 + 3]]);
    }

    #[test]
    fn a_quadratic_layer_needs_and_gets_the_bound() {
        let code = LagrangeCodedInference::new(1, 1).unwrap();
        let workers = code.required_workers(2, 0, 1); // 5
        let input = vec![11u64];
        let tasks = code
            .encode(std::slice::from_ref(&input), &asns(workers))
            .expect("encodes");
        let layer = vec![5u64, 3u64, 2u64];
        let mut outputs: Vec<Option<LccOutput>> = tasks
            .iter()
            .map(|task| Some(apply_layer(&layer, task)))
            .collect();
        let liar = outputs[1].as_ref().unwrap().clone();
        outputs[1] = Some(LccOutput {
            vector: liar.vector.iter().map(|&v| add(v, 42)).collect(),
            ..liar
        });

        let recovered = code.decode(&outputs, 2, 1).expect("decodes");
        let x = 11u64;
        let expected = add(add(mul(2, mul(x, x)), mul(3, x)), 5);
        assert_eq!(recovered, vec![vec![expected]]);

        outputs.pop();
        assert!(matches!(
            code.decode(&outputs, 2, 1),
            Err(LccError::TooFewEvaluations { .. })
        ));
    }

    #[test]
    fn one_worker_learns_nothing_about_the_input() {
        let code = LagrangeCodedInference::new(1, 1).unwrap();
        let workers = 2;
        let observed_task = code
            .encode_with_masks(&[vec![3u64]], &[vec![99u64]], &asns(workers))
            .expect("encodes");
        let observed = observed_task[0].vector[0];
        assert_eq!(observed_task[0].alpha, 3, "worker point after K+T");
        let two_inverse = inverse(2).expect("2 is invertible");

        let mut reachable = std::collections::BTreeSet::new();
        for candidate in 0u64..256 {
            let mask = mul(add(observed, candidate), two_inverse);
            let rebuilt = code
                .encode_with_masks(&[vec![candidate]], &[vec![mask]], &asns(workers))
                .expect("re-encodes");
            assert_eq!(rebuilt[0].vector[0], observed, "same worker view");
            reachable.insert(candidate);
        }
        assert_eq!(reachable.len(), 256, "every input is equally consistent");
    }

    #[test]
    fn malformed_jobs_are_refused() {
        let code = LagrangeCodedInference::new(2, 1).unwrap();
        assert!(code.encode(&[vec![1u64]], &asns(3)).is_err());
        assert!(code
            .encode_with_masks(&[vec![1], vec![2]], &[vec![1, 2]], &asns(3))
            .is_err());
        assert!(code.encode(&[vec![FIELD], vec![1]], &asns(3)).is_err());
        assert!(code.decode(&[None, None], 1, 0).is_err());
    }

    #[test]
    fn field_arithmetic_round_trips() {
        let a = 1_234_567_890u64;
        let b = FIELD - 7;
        assert_eq!(add(sub(a, b), b), a);
        assert_eq!(mul(a, inverse(a).unwrap()), 1);
        assert_eq!(inverse(0), None);
        assert_eq!(pow(2, 31), 1, "2^31 = 2^31 - 1 + 1 in the field");
    }
}
