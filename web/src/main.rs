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
            let promise = clipboard.write_text(&url);
            wasm_bindgen_futures::spawn_local(async move {
                if wasm_bindgen_futures::JsFuture::from(promise).await.is_ok() {
                    set_copied.set(true);
                    let _ = set_timeout_with_handle(
                        move || set_copied.set(false),
                        std::time::Duration::from_secs(2),
                    );
                }
            });
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

macro_rules! collect_metrics {
    ($cvss:expr, $( ($field:ident, $abbr:expr, $name:expr) ),* $(,)?) => {{
        let mut entries = Vec::new();
        $(
            if let Some(v) = &$cvss.$field {
                entries.push(MetricEntry { abbr: $abbr, name: $name, value: format!("{v:?}") });
            }
        )*
        entries
    }};
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

fn render_v2(cvss: CvssV2) -> impl IntoView {
    let base_score = cvss.calculated_base_score();
    let temporal_score = cvss.calculated_temporal_score();
    let environmental_score = cvss.calculated_environmental_score();
    let severity = base_score.map(severity_from_score_v2).unwrap_or("None");

    let base = collect_metrics!(
        cvss,
        (access_vector, "AV", "Access Vector"),
        (access_complexity, "AC", "Access Complexity"),
        (authentication, "Au", "Authentication"),
        (confidentiality_impact, "C", "Confidentiality Impact"),
        (integrity_impact, "I", "Integrity Impact"),
        (availability_impact, "A", "Availability Impact"),
    );
    let temporal = collect_metrics!(
        cvss,
        (exploitability, "E", "Exploitability"),
        (remediation_level, "RL", "Remediation Level"),
        (report_confidence, "RC", "Report Confidence"),
    );
    let environmental = collect_metrics!(
        cvss,
        (
            collateral_damage_potential,
            "CDP",
            "Collateral Damage Potential"
        ),
        (target_distribution, "TD", "Target Distribution"),
        (
            confidentiality_requirement,
            "CR",
            "Confidentiality Requirement"
        ),
        (integrity_requirement, "IR", "Integrity Requirement"),
        (availability_requirement, "AR", "Availability Requirement"),
    );

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

    let base = collect_metrics!(
        cvss,
        (attack_vector, "AV", "Attack Vector"),
        (attack_complexity, "AC", "Attack Complexity"),
        (privileges_required, "PR", "Privileges Required"),
        (user_interaction, "UI", "User Interaction"),
        (scope, "S", "Scope"),
        (confidentiality_impact, "C", "Confidentiality Impact"),
        (integrity_impact, "I", "Integrity Impact"),
        (availability_impact, "A", "Availability Impact"),
    );
    let temporal = collect_metrics!(
        cvss,
        (exploit_code_maturity, "E", "Exploit Code Maturity"),
        (remediation_level, "RL", "Remediation Level"),
        (report_confidence, "RC", "Report Confidence"),
    );
    let environmental = collect_metrics!(
        cvss,
        (
            confidentiality_requirement,
            "CR",
            "Confidentiality Requirement"
        ),
        (integrity_requirement, "IR", "Integrity Requirement"),
        (availability_requirement, "AR", "Availability Requirement"),
        (modified_attack_vector, "MAV", "Modified Attack Vector"),
        (
            modified_attack_complexity,
            "MAC",
            "Modified Attack Complexity"
        ),
        (
            modified_privileges_required,
            "MPR",
            "Modified Privileges Required"
        ),
        (
            modified_user_interaction,
            "MUI",
            "Modified User Interaction"
        ),
        (modified_scope, "MS", "Modified Scope"),
        (
            modified_confidentiality_impact,
            "MC",
            "Modified Confidentiality Impact"
        ),
        (modified_integrity_impact, "MI", "Modified Integrity Impact"),
        (
            modified_availability_impact,
            "MA",
            "Modified Availability Impact"
        ),
    );

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

fn render_v4(cvss: CvssV4) -> impl IntoView {
    let score_info = cvss.calculated_score();
    let score = score_info.as_ref().map(|(s, _)| *s);
    let nomenclature = score_info.map(|(_, n)| n.to_string());
    let severity = score.map(severity_from_score).unwrap_or("None");

    let base = collect_metrics!(
        cvss,
        (attack_vector, "AV", "Attack Vector"),
        (attack_complexity, "AC", "Attack Complexity"),
        (attack_requirements, "AT", "Attack Requirements"),
        (privileges_required, "PR", "Privileges Required"),
        (user_interaction, "UI", "User Interaction"),
        (vuln_confidentiality_impact, "VC", "Vuln. Confidentiality"),
        (vuln_integrity_impact, "VI", "Vuln. Integrity"),
        (vuln_availability_impact, "VA", "Vuln. Availability"),
        (sub_confidentiality_impact, "SC", "Sub. Confidentiality"),
        (sub_integrity_impact, "SI", "Sub. Integrity"),
        (sub_availability_impact, "SA", "Sub. Availability"),
    );
    let threat = collect_metrics!(cvss, (exploit_maturity, "E", "Exploit Maturity"),);
    let environmental = collect_metrics!(
        cvss,
        (
            confidentiality_requirement,
            "CR",
            "Confidentiality Requirement"
        ),
        (integrity_requirement, "IR", "Integrity Requirement"),
        (availability_requirement, "AR", "Availability Requirement"),
        (modified_attack_vector, "MAV", "Modified Attack Vector"),
        (
            modified_attack_complexity,
            "MAC",
            "Modified Attack Complexity"
        ),
        (
            modified_attack_requirements,
            "MAT",
            "Modified Attack Requirements"
        ),
        (
            modified_privileges_required,
            "MPR",
            "Modified Privileges Required"
        ),
        (
            modified_user_interaction,
            "MUI",
            "Modified User Interaction"
        ),
        (
            modified_vuln_confidentiality_impact,
            "MVC",
            "Modified Vuln. Confidentiality"
        ),
        (
            modified_vuln_integrity_impact,
            "MVI",
            "Modified Vuln. Integrity"
        ),
        (
            modified_vuln_availability_impact,
            "MVA",
            "Modified Vuln. Availability"
        ),
        (
            modified_sub_confidentiality_impact,
            "MSC",
            "Modified Sub. Confidentiality"
        ),
        (
            modified_sub_integrity_impact,
            "MSI",
            "Modified Sub. Integrity"
        ),
        (
            modified_sub_availability_impact,
            "MSA",
            "Modified Sub. Availability"
        ),
    );
    let supplemental = collect_metrics!(
        cvss,
        (safety, "S", "Safety"),
        (automatable, "AU", "Automatable"),
        (recovery, "R", "Recovery"),
        (value_density, "V", "Value Density"),
        (vulnerability_response_effort, "RE", "Response Effort"),
        (provider_urgency, "U", "Provider Urgency"),
    );

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
