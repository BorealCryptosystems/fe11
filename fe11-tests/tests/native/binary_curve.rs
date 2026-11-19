// SPDX-License-Identifier: Apache-2.0
//! Small independent public-point oracle over polynomial-basis binary fields.
//!
//! This is test arithmetic on public values, not a constant-time cryptographic
//! implementation. The reduction polynomial and curve coefficients are explicit
//! fixture inputs. No native provider participates in checking the equation.
use super::{arguments::hex, outcome::Failure};
use std::{fs::File, io::Read, path::Path};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Element([u8; 72]);
impl Element {
    fn read(bytes: &[u8]) -> std::result::Result<Self, Failure> {
        if bytes.len() > 72 {
            return Err(Failure::Input("binary_field_width"));
        }
        let mut out = [0; 72];
        for (target, value) in out.iter_mut().zip(bytes.iter().rev()) {
            *target = *value;
        }
        Ok(Self(out))
    }
    fn bit(&self, index: usize) -> bool {
        self.0[index / 8] & (1 << (index % 8)) != 0
    }
    fn degree(&self) -> Option<usize> {
        (0..576).rev().find(|&i| self.bit(i))
    }
    fn xor(mut self, other: Self) -> Self {
        for (a, b) in self.0.iter_mut().zip(other.0) {
            *a ^= b;
        }
        self
    }
    fn shift(&mut self) {
        let mut carry = 0;
        for byte in &mut self.0 {
            let next = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next;
        }
    }
}

pub struct Curve {
    pub oid: Vec<u8>,
    pub generator: Vec<u8>,
    pub width: usize,
    degree: usize,
    polynomial: Element,
    a: Element,
    b: Element,
}
impl Curve {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut input = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(2049)
            .read_to_end(&mut input)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if input.len() > 2048 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&input).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 6 {
            return Err(Failure::Input("binary_curve_fields"));
        }
        let fields = f
            .iter()
            .map(|s| hex(s, 72).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let polynomial = Element::read(&fields[1])?;
        let degree = polynomial
            .degree()
            .ok_or(Failure::Input("binary_polynomial"))?;
        if !(112..=571).contains(&degree) || !polynomial.bit(0) {
            return Err(Failure::Input("binary_polynomial"));
        }
        let width = (degree + 7) / 8;
        if fields[4].len() != width || fields[5].len() != width {
            return Err(Failure::Input("binary_generator_width"));
        }
        let mut generator = vec![4];
        generator.extend_from_slice(&fields[4]);
        generator.extend_from_slice(&fields[5]);
        let curve = Self {
            oid: fields[0].clone(),
            generator,
            width,
            degree,
            polynomial,
            a: Element::read(&fields[2])?,
            b: Element::read(&fields[3])?,
        };
        if !curve.in_field(curve.a) || !curve.in_field(curve.b) {
            return Err(Failure::Input("binary_coefficients"));
        }
        curve.check_raw_point(&curve.generator)?;
        let mut changed = curve.generator.clone();
        *changed
            .last_mut()
            .ok_or(Failure::Input("binary_generator"))? ^= 1;
        if curve.check_raw_point(&changed).is_ok() {
            return Err(Failure::Input("binary_point_negative_control"));
        }
        Ok(curve)
    }
    fn in_field(&self, x: Element) -> bool {
        x.degree().map_or(true, |n| n < self.degree)
    }
    fn multiply(&self, a: Element, b: Element) -> Element {
        let mut out = Element([0; 72]);
        let mut shifted = a;
        for i in 0..self.degree {
            if b.bit(i) {
                out = out.xor(shifted);
            }
            shifted.shift();
            if shifted.bit(self.degree) {
                shifted = shifted.xor(self.polynomial);
            }
        }
        out
    }
    pub fn check_raw_point<'a>(&self, point: &'a [u8]) -> std::result::Result<&'a [u8], Failure> {
        if point.len() != 1 + 2 * self.width || point[0] != 4 {
            return Err(Failure::Oracle("binary_point_encoding"));
        }
        let x = Element::read(&point[1..1 + self.width])?;
        let y = Element::read(&point[1 + self.width..])?;
        if !self.in_field(x) || !self.in_field(y) {
            return Err(Failure::Oracle("binary_point_field_extent"));
        }
        // y² + xy = x³ + ax² + b in GF(2^m).
        let x2 = self.multiply(x, x);
        let left = self.multiply(y, y).xor(self.multiply(x, y));
        let right = self
            .multiply(x2, x)
            .xor(self.multiply(self.a, x2))
            .xor(self.b);
        if left != right {
            return Err(Failure::Oracle("binary_point_equation"));
        }
        Ok(&point[1..1 + self.width])
    }
    pub fn check_der_point<'a>(&self, der: &'a [u8]) -> std::result::Result<&'a [u8], Failure> {
        if der.len() < 3 || der[0] != 4 {
            return Err(Failure::Oracle("binary_point_der"));
        }
        let (offset, length) = match der[1] {
            n @ 0..=127 => (2, n as usize),
            129 if der[2] >= 128 => (3, der[2] as usize),
            _ => return Err(Failure::Oracle("binary_point_der_length")),
        };
        if der.len() != offset + length {
            return Err(Failure::Oracle("binary_point_der_extent"));
        }
        self.check_raw_point(&der[offset..])
    }
}
