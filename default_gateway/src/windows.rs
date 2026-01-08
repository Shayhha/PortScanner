use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_GATEWAY_ADDRESS_LH, GetAdaptersAddresses};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKET_ADDRESS, SOCKADDR_INET};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::error::Error;
use std::ffi::CStr;
use std::ptr;


/**
 * Function for getting default gateway IPv4 and IPv6 addresses for the given interface.
 * Returns tuple of IPv4 and IPv6 vectors, else returns Error if not found given interface.
 */
pub fn get_default_gateway(interface: &str) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), Box<dyn Error>> {
    // define our gateway IP vectors for retrieving gateway IP addresses of given interface
    let mut ipv4_vec: Vec<Ipv4Addr> = Vec::new();
    let mut ipv6_vec: Vec<Ipv6Addr> = Vec::new();

    // define our adapter buffer size for retrieving gateway information
    let mut adapter_buffer_size: u32 = 0u32;
    unsafe {
        // get required adapter buffer size for retrieving gateway IP addresses, if fails we return none
        if GetAdaptersAddresses(AF_UNSPEC as u32, GAA_FLAG_INCLUDE_GATEWAYS, ptr::null_mut(), ptr::null_mut(), &mut adapter_buffer_size) != ERROR_BUFFER_OVERFLOW {
            return Err("Failed to determine adapter buffer size.".into());
        }
    }

    // define our adapter buffer with given buffer size for retrieving gateway information
    let mut adapter_buffer: Vec<u8> = vec![0u8; adapter_buffer_size as usize];
    unsafe {
        // allocate our adapter buffer with gateway adapter data, if fails we return none
        if GetAdaptersAddresses(AF_UNSPEC as u32, GAA_FLAG_INCLUDE_GATEWAYS, ptr::null_mut(), adapter_buffer.as_mut_ptr().cast(), &mut adapter_buffer_size) != NO_ERROR {
            return Err("Failed to retrieve adapter data.".into());
        }
    }

    unsafe {
        // define our adapter linked list and initialize it with our adapter buffer
        let mut adapter: *const IP_ADAPTER_ADDRESSES_LH = adapter_buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();

        // iterate over adapter linked list and retrieve our interface information
        while !adapter.is_null() {
            // define our adapter name pointer for retrieving current adapter name
            let adapter_name_ptr: *mut u8 = (*adapter).AdapterName;

            // check that our adapter name pointer is not null, if so get its name
            if !adapter_name_ptr.is_null() {
                // define our adapter name and initialize it from our adapter name pointer
                let adapter_name = CStr::from_ptr(adapter_name_ptr as *mut i8).to_string_lossy();

                // check if given interface guid contains adapter name guid, if so we get gateway IP addresses
                if interface.to_ascii_lowercase().contains(&adapter_name.to_ascii_lowercase()) {
                    // define our gateway linked list and initialize it with our adapter gateway address
                    let mut gateway: *mut IP_ADAPTER_GATEWAY_ADDRESS_LH = (*adapter).FirstGatewayAddress;

                    // iterate over gateway linked list and retrieve our interface gateway IP addresses
                    while !gateway.is_null() {
                        // define our socket address and ip for getting our gateway IP addresses
                        let socket_address: &SOCKET_ADDRESS = &(*gateway).Address;
                        let socket_address_ip: Option<&SOCKADDR_INET> = socket_address.lpSockaddr.cast::<SOCKADDR_INET>().as_ref();

                        // if we received valid IP address we check its version and add to our matching vector
                        if let Some(socket_address_ip) = socket_address_ip {
                            match socket_address_ip.si_family as u16 {
                                AF_INET => {
                                    ipv4_vec.push(Ipv4Addr::from(socket_address_ip.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()));
                                }
                                AF_INET6 => {
                                    ipv6_vec.push(Ipv6Addr::from(socket_address_ip.Ipv6.sin6_addr.u.Byte));
                                }
                                _ => {}
                            }
                        }

                        gateway = (*gateway).Next; //iterate gateway linked list
                    }

                    break; //break when found matching interface
                }
            }

            adapter = (*adapter).Next; //iterate adapter linked list
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