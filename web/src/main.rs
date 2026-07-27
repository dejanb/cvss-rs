use std::str::FromStr;

use leptos::prelude::*;
use wasm_bindgen::JsValue;

use cvss_rs::ParseError;
use cvss_rs::v2_0::CvssV2;
use cvss_rs::v3::CvssV3;
use cvss_rs::v4_0::CvssV4;

fn main() {
    leptos::mount::mount_to_body(|| view! { <App /> });
}

/// Result of parsing a CVSS vector string, dispatched by version.
enum ParsedCvss {
    V2(CvssV2),
    V3(CvssV3),
    V4(CvssV4),
}

/// Auto-detects the CVSS version from the vector prefix and parses accordingly.
fn parse_cvss_vector(input: &str) -> Result<ParsedCvss, ParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ParseError::InvalidPrefixLabel {
            found: String::new(),
        });
    }

    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("CVSS:4.0/") {
        CvssV4::from_str(trimmed).map(ParsedCvss::V4)
    } else if upper.starts_with("CVSS:3.1/") || upper.starts_with("CVSS:3.0/") {
        CvssV3::from_str(trimmed).map(ParsedCvss::V3)
    } else if upper.starts_with("CVSS:2.0/") {
        CvssV2::from_str(trimmed).map(ParsedCvss::V2)
    } else if upper.starts_with("CVSS:") {
        let version = upper
            .split('/')
            .next()
            .and_then(|s| s.strip_prefix("CVSS:"))
            .unwrap_or("unknown");
        Err(ParseError::InvalidPrefixVersion {
            version: version.to_string(),
        })
    } else {
        CvssV2::from_str(trimmed).map(ParsedCvss::V2)
    }
}

/// Reads the `?vector=` query parameter from the current URL.
fn initial_vector() -> String {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|s| web_sys::UrlSearchParams::new_with_str(&s).ok())
        .and_then(|p| p.get("vector"))
        .unwrap_or_default()
}

/// Builds a shareable URL with the vector as a query parameter.
fn build_share_url(vector: &str) -> Option<String> {
    let window = web_sys::window()?;
    let location = window.location();
    let origin = location.origin().ok()?;
    let pathname = location.pathname().ok()?;
    let encoded = js_sys::encode_uri_component(vector);
    Some(format!("{origin}{pathname}?vector={encoded}"))
}

/// Derives a severity label from a calculated score using CVSS v3/v4 thresholds.
fn severity_from_score(score: f64) -> &'static str {
    if score == 0.0 {
        "None"
    } else if score <= 3.9 {
        "Low"
    } else if score <= 6.9 {
        "Medium"
    } else if score <= 8.9 {
        "High"
    } else {
        "Critical"
    }
}

/// Derives a severity label from a calculated score using CVSS v2 thresholds.
fn severity_from_score_v2(score: f64) -> &'static str {
    if score <= 3.9 {
        "Low"
    } else if score <= 6.9 {
        "Medium"
    } else {
        "High"
    }
}

/// Returns the CSS class for a severity label.
fn severity_class(severity: &str) -> &'static str {
    match severity {
        "None" => "severity-none",
        "Low" => "severity-low",
        "Medium" => "severity-medium",
        "High" => "severity-high",
        "Critical" => "severity-critical",
        _ => "severity-none",
    }
}

#[component]
fn App() -> impl IntoView {
    let (input, set_input) = signal(initial_vector());
    let (copied, set_copied) = signal(false);

    let result = move || {
        let value = input.get();
        if value.trim().is_empty() {
            None
        } else {
            Some(parse_cvss_vector(&value))
        }
    };

    Effect::new(move |_| {
        let value = input.get();
        if let Some(window) = web_sys::window()
            && let Ok(history) = window.history()
        {
            let url = if value.trim().is_empty() {
                window
                    .location()
                    .pathname()
                    .unwrap_or_else(|_| "/".to_string())
            } else {
                let encoded = js_sys::encode_uri_component(&value);
                let pathname = window
                    .location()
                    .pathname()
                    .unwrap_or_else(|_| "/".to_string());
                format!("{pathname}?vector={encoded}")
            };
            let _ = history.replace_state_with_url(&JsValue::NULL, "", Some(&url));
        }
    });

    let copy_link = move |_| {
        let value = input.get();
        if let Some(url) = build_share_url(&value)
            && let Some(window) = web_sys::window()
        {
            let clipboard = window.navigator().clipboard();
            let _ = clipboard.write_text(&url);
            set_copied.set(true);
            let handle = set_timeout_with_handle(
                move || set_copied.set(false),
                std::time::Duration::from_secs(2),
            );
            let _ = handle;
        }
    };

    view! {
        <div class="container">
            <header>
                <h1>
                    <span class="badge">"CVSS"</span>
                    " Vector Validator"
                </h1>
                <p class="subtitle">
                    "Validate and inspect "
                    <a href="https://www.first.org/cvss/" target="_blank" rel="noopener">
                        "CVSS"
                    </a>
                    " vector strings (v2.0, v3.0, v3.1, v4.0)"
                </p>
            </header>

            <div class="input-row">
                <input
                    type="text"
                    class="vector-input"
                    placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    prop:value=move || input.get()
                    on:input=move |ev| set_input.set(event_target_value(&ev))
                />
                <button
                    class="share-btn"
                    class:copied=move || copied.get()
                    on:click=copy_link
                    disabled=move || input.get().trim().is_empty()
                >
                    {move || if copied.get() { "Copied!" } else { "Share" }}
                </button>
            </div>

            <div class="result-area">
                {move || match result() {
                    None => view! {
                        <p class="hint">"Enter a CVSS vector string above to validate it."</p>
                    }.into_any(),
                    Some(Err(err)) => view! {
                        <div class="error">
                            <strong>"Parse Error"</strong>
                            <p>{err.to_string()}</p>
                        </div>
                    }.into_any(),
                    Some(Ok(parsed)) => view! {
                        <CvssResult parsed=parsed />
                    }.into_any(),
                }}
            </div>

            <footer>
                <a href="https://github.com/scm-rs/cvss-rs" target="_blank" rel="noopener">
                    "cvss-rs"
                </a>
            </footer>
        </div>
    }
}

/// A single row in a metric table.
struct MetricEntry {
    abbr: &'static str,
    name: &'static str,
    value: String,
}

/// Renders a table of metrics with a group header.
#[component]
fn MetricGroup(title: &'static str, entries: Vec<MetricEntry>) -> impl IntoView {
    if entries.is_empty() {
        return ().into_any();
    }
    view! {
        <div class="metric-group">
            <h3>{title}</h3>
            <table class="metrics">
                {entries.into_iter().map(|e| view! {
                    <tr>
                        <td class="metric-abbr"><code>{e.abbr}</code></td>
                        <td class="metric-name">{e.name}</td>
                        <td class="metric-value"><code>{e.value}</code></td>
                    </tr>
                }).collect::<Vec<_>>()}
            </table>
        </div>
    }
    .into_any()
}

/// Displays the full parsed CVSS result with scores and metrics.
#[component]
fn CvssResult(parsed: ParsedCvss) -> impl IntoView {
    match parsed {
        ParsedCvss::V2(cvss) => render_v2(cvss).into_any(),
        ParsedCvss::V3(cvss) => render_v3(cvss).into_any(),
        ParsedCvss::V4(cvss) => render_v4(cvss).into_any(),
    }
}

/// Renders a score banner with version label, score, and severity.
#[component]
fn ScoreBanner(
    version: &'static str,
    score: Option<f64>,
    severity: &'static str,
    #[prop(optional)] nomenclature: String,
) -> impl IntoView {
    let score_text = score
        .map(|s| format!("{s:.1}"))
        .unwrap_or_else(|| "N/A".to_string());
    let sev_class = severity_class(severity);
    let show_nomenclature = if nomenclature.is_empty() {
        None
    } else {
        Some(nomenclature)
    };

    view! {
        <div class="score-banner">
            <span class="version-badge">{version}</span>
            {show_nomenclature.map(|n| view! { <span class="nomenclature-badge">{n}</span> })}
            <span class=format!("score {sev_class}")>{score_text}</span>
            <span class=format!("severity-label {sev_class}")>{severity}</span>
        </div>
    }
}

/// Renders the parsed CVSS v2.0 result.
fn render_v2(cvss: CvssV2) -> impl IntoView {
    let base_score = cvss.calculated_base_score();
    let temporal_score = cvss.calculated_temporal_score();
    let environmental_score = cvss.calculated_environmental_score();
    let severity = base_score.map(severity_from_score_v2).unwrap_or("None");

    let mut base = Vec::new();
    if let Some(v) = &cvss.access_vector {
        base.push(MetricEntry {
            abbr: "AV",
            name: "Access Vector",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.access_complexity {
        base.push(MetricEntry {
            abbr: "AC",
            name: "Access Complexity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.authentication {
        base.push(MetricEntry {
            abbr: "Au",
            name: "Authentication",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.confidentiality_impact {
        base.push(MetricEntry {
            abbr: "C",
            name: "Confidentiality Impact",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.integrity_impact {
        base.push(MetricEntry {
            abbr: "I",
            name: "Integrity Impact",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.availability_impact {
        base.push(MetricEntry {
            abbr: "A",
            name: "Availability Impact",
            value: format!("{v:?}"),
        });
    }

    let mut temporal = Vec::new();
    if let Some(v) = &cvss.exploitability {
        temporal.push(MetricEntry {
            abbr: "E",
            name: "Exploitability",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.remediation_level {
        temporal.push(MetricEntry {
            abbr: "RL",
            name: "Remediation Level",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.report_confidence {
        temporal.push(MetricEntry {
            abbr: "RC",
            name: "Report Confidence",
            value: format!("{v:?}"),
        });
    }

    let mut environmental = Vec::new();
    if let Some(v) = &cvss.collateral_damage_potential {
        environmental.push(MetricEntry {
            abbr: "CDP",
            name: "Collateral Damage Potential",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.target_distribution {
        environmental.push(MetricEntry {
            abbr: "TD",
            name: "Target Distribution",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.confidentiality_requirement {
        environmental.push(MetricEntry {
            abbr: "CR",
            name: "Confidentiality Requirement",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.integrity_requirement {
        environmental.push(MetricEntry {
            abbr: "IR",
            name: "Integrity Requirement",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.availability_requirement {
        environmental.push(MetricEntry {
            abbr: "AR",
            name: "Availability Requirement",
            value: format!("{v:?}"),
        });
    }

    view! {
        <div class="success">
            <ScoreBanner version="CVSS v2.0" score=base_score severity=severity />
            <div class="scores-detail">
                {temporal_score.map(|s| view! {
                    <span class="score-item">"Temporal: " <strong>{format!("{s:.1}")}</strong></span>
                })}
                {environmental_score.map(|s| view! {
                    <span class="score-item">"Environmental: " <strong>{format!("{s:.1}")}</strong></span>
                })}
            </div>
            <MetricGroup title="Base Metrics" entries=base />
            <MetricGroup title="Temporal Metrics" entries=temporal />
            <MetricGroup title="Environmental Metrics" entries=environmental />
        </div>
    }
}

/// Renders the parsed CVSS v3.x result.
fn render_v3(cvss: CvssV3) -> impl IntoView {
    let version_label = match &cvss.version {
        Some(v) => match v {
            cvss_rs::version::VersionV3::V3_0 => "CVSS v3.0",
            cvss_rs::version::VersionV3::V3_1 => "CVSS v3.1",
        },
        None => "CVSS v3.x",
    };
    let base_score = cvss.calculated_base_score();
    let temporal_score = cvss.calculated_temporal_score();
    let environmental_score = cvss.calculated_environmental_score();
    let severity = base_score.map(severity_from_score).unwrap_or("None");

    let mut base = Vec::new();
    if let Some(v) = &cvss.attack_vector {
        base.push(MetricEntry {
            abbr: "AV",
            name: "Attack Vector",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.attack_complexity {
        base.push(MetricEntry {
            abbr: "AC",
            name: "Attack Complexity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.privileges_required {
        base.push(MetricEntry {
            abbr: "PR",
            name: "Privileges Required",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.user_interaction {
        base.push(MetricEntry {
            abbr: "UI",
            name: "User Interaction",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.scope {
        base.push(MetricEntry {
            abbr: "S",
            name: "Scope",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.confidentiality_impact {
        base.push(MetricEntry {
            abbr: "C",
            name: "Confidentiality Impact",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.integrity_impact {
        base.push(MetricEntry {
            abbr: "I",
            name: "Integrity Impact",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.availability_impact {
        base.push(MetricEntry {
            abbr: "A",
            name: "Availability Impact",
            value: format!("{v:?}"),
        });
    }

    let mut temporal = Vec::new();
    if let Some(v) = &cvss.exploit_code_maturity {
        temporal.push(MetricEntry {
            abbr: "E",
            name: "Exploit Code Maturity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.remediation_level {
        temporal.push(MetricEntry {
            abbr: "RL",
            name: "Remediation Level",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.report_confidence {
        temporal.push(MetricEntry {
            abbr: "RC",
            name: "Report Confidence",
            value: format!("{v:?}"),
        });
    }

    let mut environmental = Vec::new();
    if let Some(v) = &cvss.confidentiality_requirement {
        environmental.push(MetricEntry {
            abbr: "CR",
            name: "Confidentiality Requirement",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.integrity_requirement {
        environmental.push(MetricEntry {
            abbr: "IR",
            name: "Integrity Requirement",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.availability_requirement {
        environmental.push(MetricEntry {
            abbr: "AR",
            name: "Availability Requirement",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_attack_vector {
        environmental.push(MetricEntry {
            abbr: "MAV",
            name: "Modified Attack Vector",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_attack_complexity {
        environmental.push(MetricEntry {
            abbr: "MAC",
            name: "Modified Attack Complexity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_privileges_required {
        environmental.push(MetricEntry {
            abbr: "MPR",
            name: "Modified Privileges Required",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_user_interaction {
        environmental.push(MetricEntry {
            abbr: "MUI",
            name: "Modified User Interaction",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_scope {
        environmental.push(MetricEntry {
            abbr: "MS",
            name: "Modified Scope",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_confidentiality_impact {
        environmental.push(MetricEntry {
            abbr: "MC",
            name: "Modified Confidentiality Impact",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_integrity_impact {
        environmental.push(MetricEntry {
            abbr: "MI",
            name: "Modified Integrity Impact",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_availability_impact {
        environmental.push(MetricEntry {
            abbr: "MA",
            name: "Modified Availability Impact",
            value: format!("{v:?}"),
        });
    }

    view! {
        <div class="success">
            <ScoreBanner version=version_label score=base_score severity=severity />
            <div class="scores-detail">
                {temporal_score.map(|s| view! {
                    <span class="score-item">"Temporal: " <strong>{format!("{s:.1}")}</strong></span>
                })}
                {environmental_score.map(|s| view! {
                    <span class="score-item">"Environmental: " <strong>{format!("{s:.1}")}</strong></span>
                })}
            </div>
            <MetricGroup title="Base Metrics" entries=base />
            <MetricGroup title="Temporal Metrics" entries=temporal />
            <MetricGroup title="Environmental Metrics" entries=environmental />
        </div>
    }
}

/// Renders the parsed CVSS v4.0 result.
fn render_v4(cvss: CvssV4) -> impl IntoView {
    let score_info = cvss.calculated_score();
    let score = score_info.as_ref().map(|(s, _)| *s);
    let nomenclature = score_info.map(|(_, n)| n.to_string());
    let severity = score.map(severity_from_score).unwrap_or("None");

    let mut base = Vec::new();
    if let Some(v) = &cvss.attack_vector {
        base.push(MetricEntry {
            abbr: "AV",
            name: "Attack Vector",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.attack_complexity {
        base.push(MetricEntry {
            abbr: "AC",
            name: "Attack Complexity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.attack_requirements {
        base.push(MetricEntry {
            abbr: "AT",
            name: "Attack Requirements",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.privileges_required {
        base.push(MetricEntry {
            abbr: "PR",
            name: "Privileges Required",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.user_interaction {
        base.push(MetricEntry {
            abbr: "UI",
            name: "User Interaction",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.vuln_confidentiality_impact {
        base.push(MetricEntry {
            abbr: "VC",
            name: "Vuln. Confidentiality",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.vuln_integrity_impact {
        base.push(MetricEntry {
            abbr: "VI",
            name: "Vuln. Integrity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.vuln_availability_impact {
        base.push(MetricEntry {
            abbr: "VA",
            name: "Vuln. Availability",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.sub_confidentiality_impact {
        base.push(MetricEntry {
            abbr: "SC",
            name: "Sub. Confidentiality",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.sub_integrity_impact {
        base.push(MetricEntry {
            abbr: "SI",
            name: "Sub. Integrity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.sub_availability_impact {
        base.push(MetricEntry {
            abbr: "SA",
            name: "Sub. Availability",
            value: format!("{v:?}"),
        });
    }

    let mut threat = Vec::new();
    if let Some(v) = &cvss.exploit_maturity {
        threat.push(MetricEntry {
            abbr: "E",
            name: "Exploit Maturity",
            value: format!("{v:?}"),
        });
    }

    let mut environmental = Vec::new();
    if let Some(v) = &cvss.confidentiality_requirement {
        environmental.push(MetricEntry {
            abbr: "CR",
            name: "Confidentiality Requirement",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.integrity_requirement {
        environmental.push(MetricEntry {
            abbr: "IR",
            name: "Integrity Requirement",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.availability_requirement {
        environmental.push(MetricEntry {
            abbr: "AR",
            name: "Availability Requirement",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_attack_vector {
        environmental.push(MetricEntry {
            abbr: "MAV",
            name: "Modified Attack Vector",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_attack_complexity {
        environmental.push(MetricEntry {
            abbr: "MAC",
            name: "Modified Attack Complexity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_attack_requirements {
        environmental.push(MetricEntry {
            abbr: "MAT",
            name: "Modified Attack Requirements",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_privileges_required {
        environmental.push(MetricEntry {
            abbr: "MPR",
            name: "Modified Privileges Required",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_user_interaction {
        environmental.push(MetricEntry {
            abbr: "MUI",
            name: "Modified User Interaction",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_vuln_confidentiality_impact {
        environmental.push(MetricEntry {
            abbr: "MVC",
            name: "Modified Vuln. Confidentiality",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_vuln_integrity_impact {
        environmental.push(MetricEntry {
            abbr: "MVI",
            name: "Modified Vuln. Integrity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_vuln_availability_impact {
        environmental.push(MetricEntry {
            abbr: "MVA",
            name: "Modified Vuln. Availability",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_sub_confidentiality_impact {
        environmental.push(MetricEntry {
            abbr: "MSC",
            name: "Modified Sub. Confidentiality",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_sub_integrity_impact {
        environmental.push(MetricEntry {
            abbr: "MSI",
            name: "Modified Sub. Integrity",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.modified_sub_availability_impact {
        environmental.push(MetricEntry {
            abbr: "MSA",
            name: "Modified Sub. Availability",
            value: format!("{v:?}"),
        });
    }

    let mut supplemental = Vec::new();
    if let Some(v) = &cvss.safety {
        supplemental.push(MetricEntry {
            abbr: "S",
            name: "Safety",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.automatable {
        supplemental.push(MetricEntry {
            abbr: "AU",
            name: "Automatable",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.recovery {
        supplemental.push(MetricEntry {
            abbr: "R",
            name: "Recovery",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.value_density {
        supplemental.push(MetricEntry {
            abbr: "V",
            name: "Value Density",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.vulnerability_response_effort {
        supplemental.push(MetricEntry {
            abbr: "RE",
            name: "Response Effort",
            value: format!("{v:?}"),
        });
    }
    if let Some(v) = &cvss.provider_urgency {
        supplemental.push(MetricEntry {
            abbr: "U",
            name: "Provider Urgency",
            value: format!("{v:?}"),
        });
    }

    view! {
        <div class="success">
            <ScoreBanner version="CVSS v4.0" score=score severity=severity nomenclature=nomenclature.unwrap_or_default() />
            <MetricGroup title="Base Metrics" entries=base />
            <MetricGroup title="Threat Metrics" entries=threat />
            <MetricGroup title="Environmental Metrics" entries=environmental />
            <MetricGroup title="Supplemental Metrics" entries=supplemental />
        </div>
    }
}
