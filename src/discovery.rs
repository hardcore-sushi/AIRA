use std::{thread, net::IpAddr};
use astro_dnssd::register::DNSServiceBuilder;
use multicast_dns::discovery::{DiscoveryManager, DiscoveryListeners, ResolveListeners};
use crate::{constants, print_error};

const SERVICE_TYPE: &str = "_aira._tcp";

pub fn advertise_me(){
    thread::spawn(||{
        let mut service = DNSServiceBuilder::new(SERVICE_TYPE)
            .with_name("AIRA Node")
            .with_port(constants::PORT)
            .build()
            .unwrap();
        match service.register(|reply| match reply {
            Ok(_) => {},
            Err(e) => print_error!("Error registering: {:?}", e)
        }) {
         Ok(_) => {
            loop {
                service.process_result();
            }
         }
         Err(e) => print_error!("Unable to register mDNS service. You won't be discoverable by others peers. {}", e)
        };
    });
}

pub fn discover_peers<F: Fn(&DiscoveryManager, IpAddr)>(on_service_discovered: F) {
    let discovery_manager = DiscoveryManager::new();
    match discovery_manager.discover_services(SERVICE_TYPE, DiscoveryListeners{
        on_service_discovered: Some(&|service| {
            discovery_manager.resolve_service(service, ResolveListeners{
                on_service_resolved: Some(&|service| {
                    match service.address {
                        Some(service_ip) => on_service_discovered(&discovery_manager, service_ip.parse().unwrap()),
                        None => print_error!("Service discovered without IP address: {:?}", service)
                    };
                })
            });
        }),
        on_all_discovered: Some(&|| {
            discovery_manager.stop_service_discovery();
        })
    }) {
        Ok(_) => {},
        Err(e) => print_error!(e)
    }
}