use num_complex::Complex64;

pub struct GardnerTiming {
    pub mu: f64,
    pub interval: f64,
    pub strobe: bool,
    pub last_sample: Complex64,
    pub mid_sample: Complex64,
    pub sample_count: usize,
    pub output_buffer: Vec<Complex64>,
}

impl GardnerTiming {
    pub fn new(sps: usize) -> Self {
        Self {
            mu: 0.0,
            interval: sps as f64,
            strobe: true,
            last_sample: Complex64::new(0.0, 0.0),
            mid_sample: Complex64::new(0.0, 0.0),
            sample_count: 0,
            output_buffer: Vec::new(),
        }
    }

    pub fn process(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        self.output_buffer.clear();
        for &sample in samples {
            self.sample_count += 1;
            if self.strobe {
                self.last_sample = sample;
            } else {
                self.mid_sample = sample;
            }
            if self.sample_count as f64 >= self.interval {
                self.sample_count = 0;
                let error = self.gardner_error();
                self.interval += error * 0.1;
                if self.interval < 1.0 {
                    self.interval = 1.0;
                }
                self.output_buffer.push(self.last_sample);
            }
            self.strobe = !self.strobe;
        }
        self.output_buffer.clone()
    }

    fn gardner_error(&self) -> f64 {
        let delta_re = self.last_sample.re - self.mid_sample.re;
        let delta_im = self.last_sample.im - self.mid_sample.im;
        delta_re * self.mid_sample.re + delta_im * self.mid_sample.im
    }
}
