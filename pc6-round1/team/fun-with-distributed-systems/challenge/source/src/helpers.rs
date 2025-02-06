#![allow(dead_code)]
/*
 * Copyright 2025 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
 *
 * This Software includes and/or makes use of Third-Party Software each subject to its own license.
 * DM25-0166 */

#![allow(unused_variables)]

use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::Read,
    process::Command,
    time::{Duration, Instant},
};

use async_std::io;
use bs58;
use clap::Parser;
use futures::{prelude::*, select};
use libp2p::{
    kad::{
        store::{MemoryStore, RecordStore},
        AddProviderOk, Behaviour, Config, Event, GetProvidersOk, GetRecordOk, InboundRequest, Mode,
        PeerRecord, PutRecordOk, QueryResult, Quorum, Record, RecordKey, StoreInserts,
    },
    mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, StreamProtocol, Swarm, SwarmBuilder,
};
use libp2p_identity::Keypair;
use rand::Rng;
use tracing_subscriber::EnvFilter;

fn run_vmtoolsd_cmd() -> Result<String, ()> {
    #[cfg(feature = "part1")]
    let info_get = "info-get guestinfo.token1";
    #[cfg(feature = "part2")]
    let info_get = "info-get guestinfo.token2";
    #[cfg(feature = "part3")]
    let info_get = "info-get guestinfo.token3";

    let result = Command::new("vmtoolsd").args(["--cmd", info_get]).output();

    let result_out = match result {
        Ok(v) => v,
        Err(e) => {
            println!("ERROR: vmtoolsd command failed with error: {}", e);
            return Err(());
        }
    };

    let result_str = match String::from_utf8(result_out.stdout) {
        Ok(v) => v,
        Err(e) => {
            println!(
                "ERROR: Result from vmtoolsd command could not be parsed as a UTF-8 string: {}",
                e
            );
            return Err(());
        }
    };

    if result_str.trim().is_empty() {
        println!("ERROR: Result from vmtoolsd command was empty.");
        return Err(());
    }

    Ok(result_str.trim().to_string())
}

fn kad_config() -> Config {
    let mut stream_string = "/part".to_string();
    #[cfg(feature = "part1")]
    stream_string.push('1');
    #[cfg(feature = "part2")]
    stream_string.push('2');
    #[cfg(feature = "part3")]
    stream_string.push('3');

    let mut config = Config::new(StreamProtocol::try_from_owned(stream_string).unwrap());
    config.set_record_filtering(StoreInserts::FilterBoth);
    config.set_replication_interval(None);
    config.set_publication_interval(None);
    config.set_record_ttl(None);
    config.set_provider_publication_interval(None);
    config.set_provider_record_ttl(None);

    config
}

#[derive(Debug, Parser)]
struct Args {
    /// Use a specific keypair on startup
    keypair: Option<String>,
    /// Only connect to peers if their multiaddr contains this string
    #[arg(long)]
    multiaddr: Option<String>,
    /// Show the peer's full multiaddr if it's a match
    #[arg(short)]
    show_multiaddr: bool,
}

pub(crate) fn make_swarm() -> Result<Swarm<CustomBehaviour>, Box<dyn Error>> {
    let args = Args::parse();
    let keypair = match args.keypair {
        Some(keypair_arg) => {
            let decoded_bytes = bs58::decode(&keypair_arg).into_vec()?;
            Keypair::from_protobuf_encoding(&decoded_bytes)?
        }
        None => Keypair::generate_ed25519(),
    };

    let peer_id = keypair.public().to_peer_id();
    println!("Using Peer ID {}", peer_id);
    let b58_pair = bs58::encode(keypair.to_protobuf_encoding().unwrap()).into_string();
    println!("Using Keypair {}", b58_pair);

    Ok(SwarmBuilder::with_existing_identity(keypair)
        .with_async_std()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();

            Ok(CustomBehaviour {
                kademlia: Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kad_config()),
                mdns: mdns::async_io::Behaviour::new(mdns::Config::default(), peer_id)?,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build())
}

#[derive(NetworkBehaviour)]
pub(crate) struct CustomBehaviour {
    pub(crate) kademlia: Behaviour<MemoryStore>,
    pub(crate) mdns: mdns::async_io::Behaviour,
}

pub(crate) fn handle_swarm_event(
    swarm: &mut Swarm<CustomBehaviour>,
    event: SwarmEvent<CustomBehaviourEvent>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("Listening in {address:?}");
        }
        SwarmEvent::Behaviour(CustomBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
            let args = Args::parse();
            let filteraddr = args.multiaddr;
            for (peer_id, multiaddr) in list {
                if let Some(ref addr) = filteraddr {
                    if !multiaddr.to_string().contains(addr) {
                        return;
                    }
                }
                match args.show_multiaddr {
                    true => println!("Discovered peer {} with multiaddr {}", peer_id, multiaddr),
                    false => println!("Discovered peer {}", peer_id),
                }
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, multiaddr);
            }
        }
        SwarmEvent::Behaviour(CustomBehaviourEvent::Kademlia(Event::OutboundQueryProgressed {
            result,
            ..
        })) => {
            handle_outbound_query_progressed(swarm, result);
        }
        SwarmEvent::Behaviour(CustomBehaviourEvent::Kademlia(Event::InboundRequest {
            request,
        })) => {
            handle_inbound_request(swarm, request);
        }
        _ => {}
    }
}

pub(crate) fn handle_outbound_query_progressed(
    swarm: &mut Swarm<CustomBehaviour>,
    result: QueryResult,
) {
    match result {
        QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders {
            key, providers, ..
        })) => {
            for peer in providers {
                println!(
                    "Peer {peer:?} provides key {:?}",
                    std::str::from_utf8(key.as_ref()).unwrap()
                );
            }
        }
        QueryResult::GetProviders(Err(err)) => {
            eprintln!("Failed to get providers: {err:?}");
        }
        QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(PeerRecord {
            peer,
            record: Record { key, value, .. },
        }))) => {
            println!(
                "Got record {:?} {:?}",
                std::str::from_utf8(key.as_ref()).unwrap(),
                std::str::from_utf8(&value).unwrap(),
            );

            #[cfg(not(feature = "part2"))]
            if let Some(peer_id) = peer {
                let key = RecordKey::new(&peer_id.to_string());
                let value = vec![];
                let record = Record::new(key.clone(), value);
                let store = swarm.behaviour_mut().kademlia.store_mut();
                match store.put(record) {
                    Ok(_) => {
                        if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(key) {
                            eprintln!("Failed to store friendly peer ID: {e}");
                        }
                    }
                    Err(e) => eprintln!("Failed to store friendly peer ID: {e}"),
                }
            }
        }
        QueryResult::GetRecord(Ok(_)) => {}
        QueryResult::GetRecord(Err(err)) => {
            eprintln!("Failed to get record: {err:?}");
        }
        QueryResult::PutRecord(Ok(PutRecordOk { key })) => {
            println!(
                "Successfully put record {:?}",
                std::str::from_utf8(key.as_ref()).unwrap()
            );
        }
        QueryResult::PutRecord(Err(err)) => {
            eprintln!("Failed to put record: {err:?}");
        }
        QueryResult::StartProviding(Ok(AddProviderOk { key })) => {
            println!(
                "Successfully put provider record {:?}",
                std::str::from_utf8(key.as_ref()).unwrap()
            );
        }
        QueryResult::StartProviding(Err(err)) => {
            eprintln!("Failed to put provider record: {err:?}");
        }
        _ => {}
    }
}

fn store_token(swarm: &mut Swarm<CustomBehaviour>) {
    let store = swarm.behaviour_mut().kademlia.store_mut();
    let token = match run_vmtoolsd_cmd() {
        Ok(v) => v,
        Err(_) => "Token could not be retrieved. Contact support.".to_string(),
    };
    let record_key = RecordKey::new(&"token");
    let record_val = token.as_bytes().to_vec();
    let record = Record::new(record_key.clone(), record_val);
    if let Err(e) = store.put(record) {
        eprintln!("Failed to store token locally: {e}");
        return;
    }
    if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(record_key) {
        eprintln!("Failed to start providing token: {e}");
        return;
    }
}

pub(crate) fn handle_inbound_request(swarm: &mut Swarm<CustomBehaviour>, request: InboundRequest) {
    match request {
        InboundRequest::PutRecord { record, source, .. } => {
            if let Some(item) = record {
                let store = swarm.behaviour_mut().kademlia.store_mut();
                let peer_record_key = RecordKey::new(&source.to_string());

                if let Some(_) = store.get(&peer_record_key) {
                    println!("Stored {:?}", item);
                    store.put(item).unwrap();

                    #[cfg(feature = "hidden")]
                    store_token(swarm);
                }
            }
        }
        InboundRequest::AddProvider { record } => {
            if let Some(item) = record {
                let store = swarm.behaviour_mut().kademlia.store_mut();
                if !store.provided().any(|rec| rec.key == item.key) {
                    match store.add_provider(item.clone()) {
                        Ok(_) => println!(
                            "Peer {} is now providing key {:?}.",
                            item.provider, item.key
                        ),
                        Err(e) => eprintln!("{}", e),
                    }
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn handle_input_line(kademlia: &mut Behaviour<MemoryStore>, line: String) {
    let mut args = line.split(' ');

    let operation = match args.next() {
        Some(op) => op,
        None => {
            eprintln!("expected GET, GET_PROVIDERS, PUT or PUT_PROVIDER");
            return;
        }
    };
    let key = match args.next() {
        Some(key) => RecordKey::new(&key),
        None => {
            eprintln!("Expected key");
            return;
        }
    };

    match operation {
        "GET" => kademlia.get_record(key),
        "GET_PROVIDERS" => kademlia.get_providers(key),
        "PUT" => {
            let value = match args.next() {
                Some(value) => value.as_bytes().to_vec(),
                None => {
                    eprintln!("Expected value");
                    return;
                }
            };
            let record = Record {
                key,
                value,
                publisher: None,
                expires: None,
            };

            #[cfg(not(feature = "part3"))]
            let quorum = Quorum::One;
            #[cfg(feature = "part3")]
            let quorum = Quorum::Majority;

            kademlia
                .put_record(record, quorum)
                .expect("Failed to store record locally.")
        }
        "PUT_PROVIDER" => kademlia
            .start_providing(key)
            .expect("Failed to start providing key"),
        _ => {
            eprintln!("expected GET, GET_PROVIDERS, PUT or PUT_PROVIDER");
            return;
        }
    };
}

fn get_next_check() -> Instant {
    let mut rng = rand::thread_rng();
    Instant::now() + Duration::from_secs(rng.gen_range(5..=15))
}

fn get_known_peers() -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut peers_buffer = String::new();
    File::open("known_peers")?.read_to_string(&mut peers_buffer)?;
    let mut peer_map = HashMap::new();

    for line in peers_buffer.lines() {
        let keypair =
            Keypair::from_protobuf_encoding(&bs58::decode(&line).into_vec().unwrap()).unwrap();
        let peer_id = keypair.public().to_peer_id();

        peer_map.insert(
            peer_id.to_string(),
            bs58::encode(keypair.to_protobuf_encoding().unwrap()).into_string(),
        );
    }

    Ok(peer_map)
}

pub(crate) async fn start_swarm() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut swarm = make_swarm()?;

    swarm.behaviour_mut().kademlia.set_mode(Some(Mode::Server));

    #[cfg(feature = "part2")]
    match get_known_peers().ok() {
        Some(peers) => {
            let store = swarm.behaviour_mut().kademlia.store_mut();
            for (peer_id, keypair) in peers.iter() {
                let record_key = RecordKey::new(&peer_id);
                let record_val = keypair.as_bytes().to_vec();
                let record = Record::new(record_key, record_val);
                println!("Stored {:?}", record);
                store.put(record)?;
            }
        }
        None => println!("No peers file set up!!!"),
    }

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines().fuse();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let mut next_check = get_next_check();

    // Kick it off.
    loop {
        select! {
            line = stdin.select_next_some() => handle_input_line(&mut swarm.behaviour_mut().kademlia, line.expect("Stdin not to close")),
            event = swarm.select_next_some() => handle_swarm_event(&mut swarm, event),
        }

        #[cfg(any(feature = "part1", feature = "part3"))]
        if Instant::now() > next_check {
            let key = RecordKey::new(&"insertcleverkeynamehere");
            swarm.behaviour_mut().kademlia.get_record(key);

            next_check = get_next_check();
        }
    }
}
