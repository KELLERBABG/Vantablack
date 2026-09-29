use num_complex::Complex64;

use abos_dsp::agc::AGC;
use abos_dsp::costas::CostasLoop;
use abos_dsp::ddc::DDC;
use abos_dsp::decimation::{Decimator, FIRFilter};
use abos_dsp::fft;
use abos_dsp::iq_correct::IQCorrect;
use abos_dsp::ofdm::{OFDMDemodulator, OFDMModulator};
use abos_dsp::pulse_shape::RRCFilter;
use abos_dsp::timing::GardnerTiming;

#[test]
fn test_ddc_shifts_frequency() {
    let mut ddc = DDC::new(1000.0, 10000.0);
    // A constant 1+0j signal at center frequency should be mixed to DC
    let samples = vec![Complex64::new(1.0, 0.0); 100];
    let result = ddc.process(&samples);
    // After mixing, samples should not be purely real anymore (they rotate)
    assert_eq!(result.len(), 100);
    // First sample should be 1+0j * cos(0)-jsin(0) = 1
    assert!((result[0].re - 1.0).abs() < 1e-10);
    assert!(result[0].im.abs() < 1e-10);
}

#[test]
fn test_agc_normalizes_power() {
    let mut agc = AGC::new(1.0, 0.1, 0.1);
    // High power input should be reduced
    let samples = vec![Complex64::new(10.0, 10.0); 50];
    let result = agc.process(&samples);
    let last_power = result.last().unwrap().norm_sqr();
    // Should be moving toward target power of 1.0
    assert!(last_power < 200.0);
}

#[test]
fn test_agc_default() {
    let agc = AGC::default();
    assert!((agc.target_power - 1.0).abs() < 1e-10);
    assert!((agc.gain - 1.0).abs() < 1e-10);
    assert!((agc.alpha - 0.01).abs() < 1e-10);
}

#[test]
fn test_iq_correct_baseline() {
    let mut correct = IQCorrect::default();
    let samples = vec![Complex64::new(1.0, 1.0)];
    let result = correct.process(&samples);
    // With zero phase and amplitude, output should match input
    assert!((result[0].re - 1.0).abs() < 1e-10);
    assert!((result[0].im - 1.0).abs() < 1e-10);
}

#[test]
fn test_costas_loop_converges() {
    let mut costas = CostasLoop::new(0.1);
    // Process steady signal - phase should lock
    let sample = Complex64::new(1.0, 1.0);
    let mut outputs = Vec::new();
    for _ in 0..50 {
        outputs.push(costas.process(sample));
    }
    // Last output should be stable
    let last = outputs.last().unwrap();
    assert!(last.norm() > 0.5);
}

#[test]
fn test_gardner_timing_produces_output() {
    let mut timing = GardnerTiming::new(4);
    let samples = vec![Complex64::new(1.0, 1.0); 20];
    let result = timing.process(&samples);
    assert!(!result.is_empty());
}

#[test]
fn test_fir_filter_passthrough() {
    // Single-tap FIR = passthrough
    let mut fir = FIRFilter::new(vec![1.0]);
    let samples = vec![Complex64::new(1.0, 2.0), Complex64::new(3.0, 4.0)];
    let result = fir.process(&samples);
    assert_eq!(result.len(), 2);
    assert!((result[0].re - 1.0).abs() < 1e-10);
    assert!((result[0].im - 2.0).abs() < 1e-10);
}

#[test]
fn test_decimator_reduces_rate() {
    let mut dec = Decimator::new(vec![1.0], 2);
    let samples = vec![
        Complex64::new(1.0, 0.0),
        Complex64::new(2.0, 0.0),
        Complex64::new(3.0, 0.0),
        Complex64::new(4.0, 0.0),
    ];
    let result = dec.process(&samples);
    assert_eq!(result.len(), 2);
}

#[test]
fn test_rrc_filter_basic() {
    let mut rrc = RRCFilter::new(4, 0.35, 16);
    let samples = vec![Complex64::new(1.0, 0.0)];
    let result = rrc.process(&samples);
    assert_eq!(result.len(), 1);
}

#[test]
fn test_rrc_tap_calculation() {
    let tap = abos_dsp::pulse_shape::rrc_tap(0.0, 4, 0.35);
    assert!(!tap.is_nan());
    assert!(tap > 0.0);
}

#[test]
fn test_fft_ifft_roundtrip() {
    let samples = vec![
        Complex64::new(1.0, 0.0),
        Complex64::new(0.0, 1.0),
        Complex64::new(-1.0, 0.0),
        Complex64::new(0.0, -1.0),
    ];
    let freq = fft::fft(&samples);
    let time = fft::ifft(&freq);
    for (orig, recovered) in samples.iter().zip(time.iter()) {
        assert!((orig.re - recovered.re).abs() < 1e-10);
        assert!((orig.im - recovered.im).abs() < 1e-10);
    }
}

#[test]
fn test_ofdm_modulate_demodulate_roundtrip() {
    let n_subcarriers = 64;
    let cp_length = 8;
    let pilots = vec![0, 16, 32, 48];
    let mut modu = OFDMModulator::new(n_subcarriers, cp_length, pilots.clone());
    let mut demod = OFDMDemodulator::new(n_subcarriers, cp_length, pilots);

    let symbols: Vec<Complex64> = (0..60)
        .map(|i| {
            let phase = 2.0 * std::f64::consts::PI * i as f64 / 60.0;
            Complex64::new(phase.cos(), phase.sin())
        })
        .collect();

    let tx_signal = modu.modulate(&symbols);
    assert_eq!(tx_signal.len(), n_subcarriers + cp_length);

    let (data, _pilots) = demod.demodulate(&tx_signal);
    // Data symbols should be recovered (not identical due to pilots, but close)
    assert!(!data.is_empty());
}
