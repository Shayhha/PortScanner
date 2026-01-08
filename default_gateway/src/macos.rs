use objc2_core_foundation::{CFString, CFDictionary};
use objc2_system_configuration::{SCDynamicStore, SCDynamicStoreCopyValue};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::error::Error;
use std::ptr;


/**
 * Function for getting default gateway IPv4 and IPv6 addresses for the given interface.
 * Returns tuple of IPv4 and IPv6 vectors, else returns Error if not found given interface.
 */
pub fn get_default_gateway(interface: &str) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), Box<dyn Error>> {
    // create dynamic store for getting gateway information
    let name: CFString = CFString::from_static_string("gateway_lookup");
    let store: CFRetained<SCDynamicStore> = unsafe { SCDynamicStore::new(None, &name, None, ptr::null_mut()) }.ok_or("Failed to create dynamic store for interface.")?;

    // define our gateway IP vectors for retrieving gateway IP addresses of given interface
    let mut ipv4_vec: Vec<Ipv4Addr> = Vec::new();
    let mut ipv6_vec: Vec<Ipv6Addr> = Vec::new();

    // create our IP state keys for dynamic store
    let ipv4_state_key: CFString = CFString::from_static_string("State:/Network/Global/IPv4");
    let ipv6_state_key: CFString = CFString::from_static_string("State:/Network/Global/IPv6");

    // iterate over our state keys and retrieve interface gateway IP addresses
    for state_key in [&ipv4_state_key, &ipv6_state_key] {
        if let Some(state_value) = SCDynamicStoreCopyValue(store.as_deref(), state_key) {
            if let Ok(state_dict) = state_value.downcast::<CFDictionary>() {
                // get primary interface name of current state
                let primary_interface: Option<String> = state_dict
                    .get(&CFString::from_static_string("PrimaryInterface")).and_then(|v| v.downcast::<CFString>()).map(|s| s.to_string());

                // check if primary interface name matches given interface
                if primary_interface.as_deref() == Some(interface) {
                    // get state router for extracting gateway IP addresses
                    if let Some(router) = state_dict
                        .get(&CFString::from_static_string("Router")).and_then(|v| v.downcast::<CFString>())
                    {
                        // create router IP address from state router without interface suffix
                        let router_ip: &str = router.to_string().split('%').next().ok_or("Failed to parse router IP address.")?;

                        // parse router IP address and check its version and add to our matching vector
                        if let Ok(ip) = router_ip.parse::<Ipv4Addr>() {
                            ipv4_vec.push(ip);
                        }
                        else if let Ok(ip) = router_ip.parse::<Ipv6Addr>() {
                            ipv6_vec.push(ip);
                        }
                    }
                }
            }
        }
    }

    // check that both ip vectors are not empty and return given interface gateway IP addresses
    if ipv4_vec.is_empty() && ipv6_vec.is_empty() {
        Err("No default gateway found for given interface.".into())
    }
    else {
        Ok((ipv4_vec, ipv6_vec))
    }
}