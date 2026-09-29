use num_complex::Complex64;
use std::f64::consts::PI;

/// Antenna array beamformer for steering and null-steering
pub struct Beamformer {
    pub n_elements: usize,
    pub spacing: f64,           // meters between elements
    pub frequency: f64,         // Hz
    pub phase_shifts: Vec<f64>, // radians per element
    wavelength: f64,
}

impl Beamformer {
    /// Create a new beamformer
    pub fn new(n_elements: usize, spacing: f64, frequency: f64) -> Self {
        let wavelength = 3.0e8 / frequency;
        let phase_shifts = vec![0.0; n_elements];
        Self {
            n_elements,
            spacing,
            frequency,
            phase_shifts,
            wavelength,
        }
    }

    /// Calculate phase shifts to steer beam toward a given azimuth and elevation
    /// azimuth: degrees from north (0-360)
    /// elevation: degrees above horizon (0-90)
    pub fn calculate_phase_shifts(&mut self, azimuth: f64, elevation: f64) {
        let az_rad = azimuth.to_radians();
        let el_rad = elevation.to_radians();
        let k = 2.0 * PI / self.wavelength;

        for i in 0..self.n_elements {
            let d = i as f64 * self.spacing;
            // Phase shift for a linear array along the x-axis
            let phase = k * d * az_rad.cos() * el_rad.cos();
            self.phase_shifts[i] = phase;
        }
    }

    /// Apply beamforming: combine signals from all antenna elements
    /// Each signal in the input should be from a different element
    pub fn apply_beamforming(&self, signals: &[Vec<Complex64>]) -> Vec<Complex64> {
        assert_eq!(
            signals.len(),
            self.n_elements,
            "Must have signals from all elements"
        );

        let n_samples = signals[0].len();
        let mut output = Vec::with_capacity(n_samples);

        for i in 0..n_samples {
            let mut sum = Complex64::new(0.0, 0.0);
            for (elem_idx, signal) in signals.iter().enumerate() {
                let phase_shift = Complex64::from_polar(1.0, self.phase_shifts[elem_idx]);
                sum += signal[i] * phase_shift;
            }
            output.push(sum * (1.0 / self.n_elements as f64));
        }

        output
    }

    /// Calculate null-steering weights to place a null toward an interferer
    /// Returns amplitude weights for each element (not phase shifts)
    pub fn null_steering(&self, interferer_azimuth: f64) -> Vec<f64> {
        let az_rad = interferer_azimuth.to_radians();
        let k = 2.0 * PI / self.wavelength;

        let mut weights = Vec::with_capacity(self.n_elements);
        for i in 0..self.n_elements {
            let d = i as f64 * self.spacing;
            let phase = k * d * az_rad.cos();
            // Null steering weight: invert the phase toward interferer
            weights.push((-phase).cos());
        }
        weights
    }

    /// Update frequency (changes wavelength)
    pub fn set_frequency(&mut self, frequency: f64) {
        self.frequency = frequency;
        self.wavelength = 3.0e8 / frequency;
    }
}
