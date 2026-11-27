//! Narrowband NVIS — the physical contract for the HF fallback.
//!
//! ABOS rides near-vertical-incidence skywave in the 2–10 MHz band. That band
//! is not a wideband channel: the F2 layer's multipath delay spread limits a
//! practical channel to a few kilohertz of coherence bandwidth, and the earlier
//! "1 Mcps / sub-millisecond burst" specification was an SDR sample rate
//! mistaken for on-air occupancy (see `DEV/EPISTEMIC_AUDIT_V2.md` §6).
//!
//! This module is the executable version of the whitepaper's GhostCell-Nano
//! profile. A measured channel is accepted only if it fits the physics:
//!
//! * carrier inside 2–10 MHz, selected below f₀F2 by the sounder;
//! * occupied bandwidth 3–24 kHz;
//! * information rate 24–48 bps after coding;
//! * 180-byte cell → 30–60 s on air at that rate;
//! * spreading gain 20.9–27 dB, with 3–9 dB of coding gain on top.
//!
//! A measurement outside those bounds is *refused*, not clamped: clamping would
//! turn an impossible radio plan into a plausible-looking claim. With no
//! measurement, [`status_json`] says `unmeasured` and [`evidence`] is `None`, so
//! the truth ledger cannot report a profile it did not observe.
//!
//! No on-air SDR integration ships in this build (the ABOS DSP actors report
//! carrier/f₀F2 telemetry but not occupied bandwidth or symbol rate), so in
//! practice this endpoint stays `unmeasured` until a radio layer calls
//! [`note_channel_sample`] with real values.

use serde::Serialize;
use std::sync::{Mutex, OnceLock};

pub const BAND_MIN_KHZ: u32 = 2_000;
pub const BAND_MAX_KHZ: u32 = 10_000;
pub const BANDWIDTH_MIN_HZ: u32 = 3_000;
pub const BANDWIDTH_MAX_HZ: u32 = 24_000;
pub const INFO_BPS_MIN: u32 = 24;
pub const INFO_BPS_MAX: u32 = 48;
pub const CELL_BYTES: u32 = 180;
pub const SPREADING_GAIN_MIN_DB: f64 = 20.9;
pub const SPREADING_GAIN_MAX_DB: f64 = 27.0;
pub const AIRTIME_MIN_SECS: f64 = 30.0;
pub const AIRTIME_MAX_SECS: f64 = 60.0;
pub const EVIDENCE_TTL_SECS: u64 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct NvisProfile {
    pub freq_khz: u32,
    pub bandwidth_hz: u32,
    pub info_bps: u32,
    pub airtime_secs: f64,
    pub spreading_gain_db: f64,
    pub measured_at: u64,
}

impl NvisProfile {
    pub fn from_measurement(
        freq_khz: u32,
        bandwidth_hz: u32,
        info_bps: u32,
        measured_at: u64,
    ) -> Result<Self, String> {
        if !(BAND_MIN_KHZ..=BAND_MAX_KHZ).contains(&freq_khz) {
            return Err(format!(
                "carrier {freq_khz} kHz is outside NVIS {BAND_MIN_KHZ}-{BAND_MAX_KHZ} kHz"
            ));
        }
        if !(BANDWIDTH_MIN_HZ..=BANDWIDTH_MAX_HZ).contains(&bandwidth_hz) {
            return Err(format!(
                "occupied bandwidth {bandwidth_hz} Hz is outside {BANDWIDTH_MIN_HZ}-{BANDWIDTH_MAX_HZ} Hz"
            ));
        }
        if !(INFO_BPS_MIN..=INFO_BPS_MAX).contains(&info_bps) {
            return Err(format!(
                "information rate {info_bps} bps is outside {INFO_BPS_MIN}-{INFO_BPS_MAX} bps"
            ));
        }
        let airtime_secs = (CELL_BYTES * 8) as f64 / info_bps as f64;
        if !(AIRTIME_MIN_SECS..=AIRTIME_MAX_SECS).contains(&airtime_secs) {
            return Err(format!(
                "one {CELL_BYTES}-byte cell takes {airtime_secs:.1} s, outside {AIRTIME_MIN_SECS:.0}-{AIRTIME_MAX_SECS:.0} s"
            ));
        }
        let spreading_gain_db = 10.0 * (bandwidth_hz as f64 / info_bps as f64).log10();
        if !(SPREADING_GAIN_MIN_DB..=SPREADING_GAIN_MAX_DB).contains(&spreading_gain_db) {
            return Err(format!(
                "spreading gain {spreading_gain_db:.2} dB is outside {SPREADING_GAIN_MIN_DB}-{SPREADING_GAIN_MAX_DB} dB"
            ));
        }
        Ok(Self {
            freq_khz,
            bandwidth_hz,
            info_bps,
            airtime_secs,
            spreading_gain_db,
            measured_at,
        })
    }

    pub fn is_fresh(&self) -> bool {
        self.measured_at != 0
            && super::now_secs().saturating_sub(self.measured_at) <= EVIDENCE_TTL_SECS
    }
}

fn registry() -> &'static Mutex<Option<NvisProfile>> {
    static PROFILE: OnceLock<Mutex<Option<NvisProfile>>> = OnceLock::new();
    PROFILE.get_or_init(|| Mutex::new(None))
}

pub fn note_channel_sample(
    freq_khz: u32,
    bandwidth_hz: u32,
    info_bps: u32,
) -> Result<NvisProfile, String> {
    let profile =
        NvisProfile::from_measurement(freq_khz, bandwidth_hz, info_bps, super::now_secs())?;
    *registry().lock().unwrap_or_else(|e| e.into_inner()) = Some(profile);
    Ok(profile)
}

pub fn last_profile() -> Option<NvisProfile> {
    *registry().lock().unwrap_or_else(|e| e.into_inner())
}

pub fn evidence() -> Option<NvisProfile> {
    last_profile().filter(NvisProfile::is_fresh)
}

pub fn status_for(profile: Option<NvisProfile>, now: u64) -> serde_json::Value {
    let (claim, profile_value) = match profile {
        None => ("unmeasured", serde_json::Value::Null),
        Some(p) if p.measured_at == 0 || now.saturating_sub(p.measured_at) > EVIDENCE_TTL_SECS => {
            ("stale", serde_json::json!(p))
        }
        Some(p) => ("verified", serde_json::json!(p)),
    };
    serde_json::json!({
        "claim": claim,
        "profile": profile_value,
        "bounds": {
            "carrier_khz": [BAND_MIN_KHZ, BAND_MAX_KHZ],
            "bandwidth_hz": [BANDWIDTH_MIN_HZ, BANDWIDTH_MAX_HZ],
            "info_bps": [INFO_BPS_MIN, INFO_BPS_MAX],
            "airtime_secs": [AIRTIME_MIN_SECS, AIRTIME_MAX_SECS],
            "spreading_gain_db": [SPREADING_GAIN_MIN_DB, SPREADING_GAIN_MAX_DB],
            "cell_bytes": CELL_BYTES,
            "evidence_ttl_secs": EVIDENCE_TTL_SECS,
        },
        "note": "a measurement outside these bounds is refused, never clamped; no profile is claimed without a fresh measurement",
    })
}

pub fn status_json() -> serde_json::Value {
    status_for(last_profile(), super::now_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(profile: NvisProfile, age: u64) -> NvisProfile {
        NvisProfile {
            measured_at: super::super::now_secs().saturating_sub(age),
            ..profile
        }
    }

    #[test]
    fn documented_corners_produce_thirty_and_sixty_seconds() {
        let narrow = NvisProfile::from_measurement(3_500, 3_000, 24, 1).unwrap();
        assert!((narrow.airtime_secs - 60.0).abs() < 1e-9);
        assert!((narrow.spreading_gain_db - 20.969).abs() < 0.01);
        let wide = NvisProfile::from_measurement(9_000, 24_000, 48, 1).unwrap();
        assert!((wide.airtime_secs - 30.0).abs() < 1e-9);
        assert!((wide.spreading_gain_db - 26.99).abs() < 0.02);
    }

    #[test]
    fn band_bandwidth_rate_and_frequency_edges_are_inclusive_but_outside_is_refused() {
        assert!(NvisProfile::from_measurement(BAND_MIN_KHZ, 12_000, 32, 1).is_ok());
        assert!(NvisProfile::from_measurement(BAND_MAX_KHZ, 12_000, 32, 1).is_ok());
        assert!(NvisProfile::from_measurement(BAND_MIN_KHZ - 1, 12_000, 32, 1).is_err());
        assert!(NvisProfile::from_measurement(BAND_MAX_KHZ + 1, 12_000, 32, 1).is_err());
        assert!(NvisProfile::from_measurement(5_000, BANDWIDTH_MIN_HZ - 1, 24, 1).is_err());
        assert!(NvisProfile::from_measurement(5_000, BANDWIDTH_MAX_HZ + 1, 48, 1).is_err());
        assert!(NvisProfile::from_measurement(5_000, 12_000, INFO_BPS_MIN - 1, 1).is_err());
        assert!(NvisProfile::from_measurement(5_000, 12_000, INFO_BPS_MAX + 1, 1).is_err());
    }

    #[test]
    fn an_impossible_wideband_plan_is_refused_rather_than_clamped() {
        assert!(NvisProfile::from_measurement(5_000, 24_000, 1_000_000, 1).is_err());
    }

    #[test]
    fn a_missing_or_stale_measurement_withholds_the_claim() {
        assert_eq!(status_for(None, 100)["claim"], "unmeasured");
        let profile = NvisProfile::from_measurement(5_000, 12_000, 32, 100).unwrap();
        assert_eq!(status_for(Some(profile), 100)["claim"], "verified");
        let stale = at(profile, EVIDENCE_TTL_SECS + 1);
        assert!(!stale.is_fresh());
        assert_eq!(
            status_for(Some(stale), super::super::now_secs())["claim"],
            "stale"
        );
    }

    #[test]
    fn the_ledger_evidence_requires_a_fresh_measurement() {
        let profile = NvisProfile::from_measurement(5_000, 12_000, 32, 1).unwrap();
        let fresh = at(profile, 0);
        assert!(fresh.is_fresh());
        let stale = at(profile, EVIDENCE_TTL_SECS + 1);
        assert!(!stale.is_fresh());
    }
}
