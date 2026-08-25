//! The banding helpers pin the FIRST severity bands and the
//! scaled-integer rounding, so constructors and validators share one
//! implementation of the rule.

use cvss_rs::{Severity, score_to_severity, v2_0};
use rstest::rstest;

#[rstest]
#[case(0.0, Some(Severity::None))]
#[case(0.04, Some(Severity::None))] // 0.4 scales to 0
#[case(0.05, Some(Severity::Low))] // 0.5 scales to 1
#[case(0.1, Some(Severity::Low))]
#[case(3.9, Some(Severity::Low))]
#[case(3.95, Some(Severity::Medium))] // 39.5 scales to 40
#[case(4.0, Some(Severity::Medium))]
#[case(6.9, Some(Severity::Medium))]
#[case(7.0, Some(Severity::High))]
#[case(8.9, Some(Severity::High))]
#[case(8.95, Some(Severity::Critical))] // 89.5 scales to 90
#[case(9.0, Some(Severity::Critical))]
#[case(10.0, Some(Severity::Critical))]
#[case(-0.1, None)]
#[case(10.1, None)]
#[case(f64::NAN, None)]
#[case(f64::INFINITY, None)]
fn unified_banding(#[case] score: f64, #[case] expected: Option<Severity>) {
    assert_eq!(score_to_severity(score), expected);
}

#[rstest]
#[case(0.0, Some(v2_0::Severity::Low))]
#[case(3.9, Some(v2_0::Severity::Low))]
#[case(3.95, Some(v2_0::Severity::Medium))] // 39.5 scales to 40
#[case(4.0, Some(v2_0::Severity::Medium))]
#[case(6.9, Some(v2_0::Severity::Medium))]
#[case(7.0, Some(v2_0::Severity::High))]
#[case(10.0, Some(v2_0::Severity::High))]
#[case(-0.1, None)]
#[case(10.1, None)]
#[case(f64::NAN, None)]
fn v2_banding(#[case] score: f64, #[case] expected: Option<v2_0::Severity>) {
    assert_eq!(v2_0::score_to_severity(score), expected);
}
