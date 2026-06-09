use anyhow::Result;

/// Reference implementation of a biometric template verifier using bit-level similarity.
///
/// **Security warning:** This uses a naive bit-comparison similarity metric.
/// For production biometric verification, use a dedicated biometric library
/// with proper template protection (e.g., fuzzy extractor, homomorphic comparison).
pub struct BiologicalVerifier {
    threshold: f64,
}

impl BiologicalVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self { threshold: 0.85 }
    }

    #[must_use]
    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            threshold: threshold.clamp(0.0, 1.0),
        }
    }

    #[must_use]
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    pub fn verify(&self, sample: &[u8], template: &[u8]) -> Result<bool> {
        if sample.is_empty() || template.is_empty() {
            return Ok(false);
        }
        let score = self.compute_similarity(sample, template);
        Ok(score >= self.threshold)
    }

    #[must_use]
    pub fn compute_similarity(&self, a: &[u8], b: &[u8]) -> f64 {
        let max_len = a.len().max(b.len());
        if max_len == 0 {
            return 1.0;
        }
        let min_len = a.len().min(b.len());
        let mut matching_bits = 0usize;
        for i in 0..min_len {
            matching_bits += (a[i] ^ b[i]).count_zeros() as usize;
        }
        matching_bits as f64 / (max_len * 8) as f64
    }
}

impl Default for BiologicalVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_samples() {
        let v = BiologicalVerifier::new();
        let template = vec![1, 2, 3, 4, 5];
        assert!(v.verify(&template, &template).unwrap());
        assert!((v.compute_similarity(&template, &template) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_completely_different() {
        let v = BiologicalVerifier::new();
        let sample = vec![0xFF; 16];
        let template = vec![0x00; 16];
        assert!(!v.verify(&sample, &template).unwrap());
        assert!((v.compute_similarity(&sample, &template)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_empty_sample() {
        let v = BiologicalVerifier::new();
        assert!(!v.verify(&[], &[1, 2, 3]).unwrap());
    }

    #[test]
    fn test_empty_template() {
        let v = BiologicalVerifier::new();
        assert!(!v.verify(&[1, 2, 3], &[]).unwrap());
    }

    #[test]
    fn test_both_empty() {
        let v = BiologicalVerifier::new();
        assert!(!v.verify(&[], &[]).unwrap());
    }

    #[test]
    fn test_single_byte_half_matching() {
        let v = BiologicalVerifier::with_threshold(0.5);
        let a = vec![0xFF];
        let b = vec![0x00];
        let sim = v.compute_similarity(&a, &b);
        assert!((sim).abs() < 0.01);

        let a = vec![0b10101010];
        let b = vec![0b10101010];
        let sim = v.compute_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_different_lengths_shorter_sample() {
        let v = BiologicalVerifier::with_threshold(0.0);
        let sample = vec![0xFF];
        let template = vec![0xFF, 0xFF];
        let sim = v.compute_similarity(&sample, &template);
        assert!(sim > 0.0 && sim < 1.0);
    }

    #[test]
    fn test_different_lengths_shorter_template() {
        let v = BiologicalVerifier::with_threshold(0.0);
        let sample = vec![0xFF, 0xFF];
        let template = vec![0xFF];
        let sim = v.compute_similarity(&sample, &template);
        assert!(sim > 0.0 && sim < 1.0);
    }

    #[test]
    fn test_custom_threshold_clamped() {
        let v = BiologicalVerifier::with_threshold(1.5);
        assert_eq!(v.threshold(), 1.0);
        let v2 = BiologicalVerifier::with_threshold(-0.5);
        assert_eq!(v2.threshold(), 0.0);
    }

    #[test]
    fn test_default_threshold() {
        let v = BiologicalVerifier::new();
        assert!((v.threshold() - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_one_bit_difference() {
        let v = BiologicalVerifier::new();
        let a = vec![0xFF; 8];
        let mut b = vec![0xFF; 8];
        b[0] = 0xFE; // one bit different
        let sim = v.compute_similarity(&a, &b);
        let expected = 1.0 - 1.0 / (8.0 * 8.0);
        assert!((sim - expected).abs() < 0.01);
        assert!(v.verify(&a, &b).unwrap());
    }
}
