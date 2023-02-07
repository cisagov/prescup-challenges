// This product includes GeoLite2 data created by MaxMind, available from
// <a href="https://www.maxmind.com">https://www.maxmind.com</a>.

use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use lazy_static::lazy_static;
use obfstr::obfstr;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use regex::Regex;
use serde::de::{self, DeserializeOwned, Unexpected};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{Display, Formatter};

const IPV4_CSV: &str = include_str!("../GeoLite2-Country-Blocks-IPv4.csv");
const IPV6_CSV: &str = include_str!("../GeoLite2-Country-Blocks-IPv6.csv");
const LOCATION_CSV: &str = include_str!("../GeoLite2-Country-Locations-en.csv");

lazy_static! {
    static ref IP_ADDR: Regex = Regex::new(r#"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"#).unwrap();
}

type GeonameId = u32;

fn bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    match u8::deserialize(deserializer)? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(de::Error::invalid_value(
            Unexpected::Unsigned(other as u64),
            &"zero or one",
        )),
    }
}

#[derive(Debug, Deserialize)]
struct IpRecord {
    network: IpNet,
    geoname_id: Option<GeonameId>,
    registered_country_geoname_id: Option<GeonameId>,
    represented_country_geoname_id: Option<GeonameId>,
    #[serde(deserialize_with = "bool_from_int")]
    is_anonymous_proxy: bool,
    #[serde(deserialize_with = "bool_from_int")]
    is_satellite_provider: bool,
}

#[derive(Debug, Deserialize)]
struct LocationRecord {
    geoname_id: GeonameId,
    locale_code: String,
    continent_code: String,
    continent_name: String,
    country_iso_code: String,
    country_name: String,
    #[serde(deserialize_with = "bool_from_int")]
    is_in_european_union: bool,
}

#[derive(Debug, Serialize)]
struct Report {
    agent_name: String,
    report_body: String,
}

impl Report {
    fn new(agent_name: String, report_body: String) -> Self {
        Self {
            agent_name,
            report_body,
        }
    }
}

fn load_data<D: DeserializeOwned>(csv_string: &str) -> Result<Vec<D>, Box<dyn Error>> {
    let mut data = vec![];
    let mut reader = csv::Reader::from_reader(csv_string.as_bytes());
    for line in reader.deserialize() {
        let record = line?;
        data.push(record);
    }

    Ok(data)
}

fn generate_report() -> Report {
    let report_blobs = vec![
        obfstr!("- There's a quantum surge in the gamma warp cannon casings.").to_string(),
        obfstr!("- The promethean microfilament is offline. We should de-scramble the neutronium electro-ceramic fetcher.").to_string(),
        obfstr!("- I'm detecting an antimatter particle trace in the sensitive gluon teleporter pads. We should rebuild the containment emergency rocket.").to_string(),
        obfstr!("- There's a neutrino surge in the tantulum caesium propulsion nullifier. We should reboot the electro-plasma bio-containers.").to_string(),
        obfstr!("- We need to completely resynchronize the revolving pulse generator.").to_string(),
        obfstr!("- There's an anomalous power spike in the hyper sensitive magnesium propeller.").to_string(),
        obfstr!("- I'm detecting a temporal anomaly in the manganese electro-ceramic straighteners.").to_string(),
        obfstr!("- I'm detecting a destabilization in the chlorine wave collector brackets. You need to increase power to the quantum shift teleporter pads.").to_string(),
        obfstr!("- I noticed a neutrino surge in the iron gluon crystal. I need to restart the magnesium shifter.").to_string(),
        obfstr!("- The lithium chroniton is offline. I need to de-polarize the platinum phaser bio-filter.").to_string(),
        obfstr!("- There's an anomalous power spike in the neutronium gluon thruster housings. We need to jump-start the dorsal booster amplifier.").to_string(),
        obfstr!("- The antimatter power is offline. I need to fluctuate the chromium ram turbine.").to_string(),
        obfstr!("- The bottom rubidium is offline. We should de-scramble the lithium power converter.").to_string(),
        obfstr!("- There's a series of nanowave pulse signatures in the zirconium phaser splitter. We need to energize the antigravity centrifuge.").to_string(),
    ];

    let agent_names = vec![
        obfstr!("Deinokrates").to_string(),
        obfstr!("Kritoboulos").to_string(),
        obfstr!("Aristocypros").to_string(),
        obfstr!("Artemas").to_string(),
        obfstr!("Theodotus").to_string(),
        obfstr!("Atreus").to_string(),
        obfstr!("Hegesandros").to_string(),
        obfstr!("Halisthertes").to_string(),
    ];

    let mut rng = thread_rng();
    let agent_name = agent_names[rng.gen_range(0..agent_names.len())].clone();
    let report_points_number = rng.gen_range(1..report_blobs.len());
    let report_points: Vec<String> = report_blobs
        .choose_multiple(&mut rng, report_points_number)
        .cloned()
        .collect();

    let report = format!(
        "The following issues are in need of attention:\n{}",
        report_points.join("\n")
    );

    let report = Report::new(agent_name.to_string(), report);

    report
}

fn report_from_cmd_line() -> Report {
    let report_text = std::env::args().skip(1).collect::<Vec<String>>();
    Report::new("".to_string(), report_text.join(" "))
}

fn lookup_geolocation(
    addr: IpAddr,
    ip_records: &Vec<IpRecord>,
    loc_records: &Vec<LocationRecord>,
) -> Option<String> {
    for item in ip_records {
        if item.network.contains(&addr) {
            if let Some(id) = item.geoname_id {
                for location in loc_records.iter() {
                    if location.geoname_id == id {
                        return Some(location.continent_code.clone());
                    }
                }
            }
        };
    }
    None
}

#[derive(Debug)]
struct NoneToErr;

impl Display for NoneToErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Converted Option::None to Result::Err.")
    }
}

impl Error for NoneToErr {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

async fn wrapped_main() -> Result<(), Box<dyn Error>> {
    let report = report_from_cmd_line();
    if report.report_body == "" {
        println!("Agent, please enter your report on the command line.");
        return Ok(());
    }

    #[allow(non_snake_case)]
    let AS = IpAddr::from_str(obfstr!("1.235.189.106"))?;
    #[allow(non_snake_case)]
    let OC = IpAddr::from_str(obfstr!("58.172.47.117"))?;
    #[allow(non_snake_case)]
    let AF = IpAddr::from_str(obfstr!("45.104.34.74"))?;
    #[allow(non_snake_case)]
    let NA = IpAddr::from_str(obfstr!("128.237.119.12"))?;
    #[allow(non_snake_case)]
    let SA = IpAddr::from_str(obfstr!("152.200.19.77"))?;
    #[allow(non_snake_case)]
    let EU = IpAddr::from_str(obfstr!("2.69.27.123"))?;

    let ipv4_data = load_data::<IpRecord>(IPV4_CSV)?;
    let ipv6_data = load_data::<IpRecord>(IPV6_CSV)?;
    let location_data = load_data::<LocationRecord>(LOCATION_CSV)?;

    let mut ip_data = vec![];
    ip_data.extend(ipv4_data);
    ip_data.extend(ipv6_data);

    println!("Welcome, agent. Verifying...");
    let ip_app_addr = obfstr!("104.27.195.88").to_string();
    let get_response = reqwest::get(format!("http://{}/ip", ip_app_addr))
        .await?
        .text()
        .await?;

    let addr = &IP_ADDR.captures(get_response.as_str()).ok_or(NoneToErr)?[0];

    let geo_location =
        lookup_geolocation(IpAddr::from_str(addr)?, &ip_data, &location_data).ok_or(NoneToErr)?;

    let report_addr = match geo_location.as_str() {
        "AS" => AS,
        "OC" => OC,
        "AF" => AF,
        "NA" => NA,
        "SA" => SA,
        "EU" => EU,
        _ => unreachable!(),
    };

    let client = reqwest::Client::new();
    println!("Location verified. Sending your report.");
    let post_response = client
        .post(format!("http://{}/report", report_addr))
        .json(&report)
        .send()
        .await?;
    if post_response.status() == 200 {
        println!("Report accepted. Thank you, agent.");
    } else {
        println!("Report was not accepted. You will be assimilated. Prepare to be probed.")
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = wrapped_main().await {
        obfstr! {
            let error_instructions = "Reporting app raised an error. If you were just \
            experimenting to understand how the application works, then this is expected. \
            However, if this has happened on starting the challenge fresh, please contact \
            PresCup support.";
        }
        println!("{:?}\n\n{}", e, error_instructions);
    }
}
