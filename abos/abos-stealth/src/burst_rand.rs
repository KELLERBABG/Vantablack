use rand::Rng;

pub struct RandomBurstScheduler {
    pub min_interval: u64,
    pub max_interval: u64,
    rng: rand::rngs::ThreadRng,
}

impl RandomBurstScheduler {
    pub fn new(min_interval: u64, max_interval: u64) -> Self {
        Self {
            min_interval,
            max_interval,
            rng: rand::thread_rng(),
        }
    }

    pub fn next_burst_time(&mut self) -> u64 {
        let range = self.max_interval - self.min_interval;
        self.min_interval + self.rng.gen_range(0..=range)
    }
}
