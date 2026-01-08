use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_route::{RouteNetlinkMessage, link::{LinkMessage, LinkAttribute}, route::{RouteMessage, RouteAttribute, RouteAddress}};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::error::Error;


/**
 * Helper function for handling netlink messages from socket, calling handler for each netlink message payload received.
 * Stops processing when the handler returns false, a Done/Error payload received, or an I/O/deserialization error occurs.
 */
fn handle_netlink_messages(socket: &Socket, mut handler: impl FnMut(RouteNetlinkMessage) -> bool) {
    // define receiving buffer for netlink messages and finish flag
    const RECV_BUFFER_SIZE: usize = 8192;
    let mut recv_buffer: Vec<u8> = vec![0u8; RECV_BUFFER_SIZE];
    let mut finish: bool = false;

    // listen for incoming netlink messages and handle them according to given handler
    while !finish {
        // clear our receive buffer for reading next netlink message
        recv_buffer.clear();
        recv_buffer.reserve(RECV_BUFFER_SIZE);

        // define receive offset and size based on received stream size from netlink
        let mut recv_offset: usize = 0;
        let recv_size: usize = match socket.recv(&mut recv_buffer, 0) {
            Ok(size) => size,
            Err(_) => break
        };

        // if netlink stream is empty we break and finish
        if recv_size == 0 {
            break;
        }

        // define receive slice for retrieving given netlink messages from stream
        let recv_slice: &[u8] = &recv_buffer[..recv_size];

        // handle netlink messages from given stream until we handled all stream messages
        while recv_offset < recv_size {
            // get current netlink message from our receive slice, if failed we break and finish
            let message: NetlinkMessage<RouteNetlinkMessage> = match NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_slice[recv_offset..]) {
                Ok(message) => message,
                Err(_) => {
                    finish = true;
                    break;
                }
            };

            // define message size from given message header and check if size is valid, if not we break and finish
            let message_size: usize = message.header.length as usize;
            if message_size == 0 || message_size > recv_size - recv_offset {
                finish = true;
                break;
            }

            // use given handler for handling netlink messages, if done we break and finish
            match message.payload {
                NetlinkPayload::InnerMessage(inner_message) => {
                    if !handler(inner_message) {
                        finish = true;
                        break;
                    }
                },
                NetlinkPayload::Done(_) | NetlinkPayload::Error(_) => {
                    finish = true;
                    break;
                },
                _ => {}
            }

        // increment receive offset for next message in stream
        recv_offset += message_size;
        }
    }
}


/**
 * Helper function for getting interface index for the given interface.
 * Returns interface index, else returns Error if not found given interface.
 */
fn get_interface_index(interface: &str) -> Result<u32, Box<dyn Error>> {
    // create new netlink socket and bind to an address for sending and receiving netlink messages
    let mut socket: Socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind(&SocketAddr::new(0, 0))?;

    // define our interface index we need to retrieve using netlink
    let mut interface_index: Option<u32> = None;

    // create link message for retrieving interface index using netlink
    let mut link_message: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::from(RouteNetlinkMessage::GetLink(LinkMessage::default()));
    link_message.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    link_message.finalize();

    // create link message buffer and send it to netlink for fetching index
    let mut link_message_buffer: Vec<u8> = vec![0u8; link_message.buffer_len()];
    link_message.serialize(&mut link_message_buffer);
    socket.send(&link_message_buffer, 0)?;

    // wait for message response from netlink and get our interface index
    handle_netlink_messages(&socket, |inner_message: RouteNetlinkMessage| {
        if let RouteNetlinkMessage::NewLink(link) = inner_message {
            // iterate over each link attribute and find interface name
            for link_attr in link.attributes {
                if let LinkAttribute::IfName(name) = link_attr {
                    // if name matches our interface name, save index and finish
                    if name == interface {
                        interface_index = Some(link.header.index);
                        return false;
                    }
                }
            }
        }
        true
    });

    // check that we found interface index and return our interface index
    if let Some(interface_index) = interface_index {
        Ok(interface_index)
    }
    else {
        Err("No index found for given interface.".into())
    }
}


/**
 * Helper function for getting default gateway IPv4 and IPv6 addresses for the given interface.
 * Returns tuple of IPv4 and IPv6 vectors, else returns Error if not found given interface.
 */
fn get_interface_default_gateway(interface_index: u32) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), Box<dyn Error>> {
    // create new netlink socket and bind to an address for sending and receiving netlink messages
    let mut socket: Socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind(&SocketAddr::new(0, 0))?;

    // define our gateway IP vectors for retrieving gateway IP addresses of given interface
    let mut ipv4_vec: Vec<Ipv4Addr> = Vec::new();
    let mut ipv6_vec: Vec<Ipv6Addr> = Vec::new();

    // create route message for retrieving interface default gateway IP addresses using netlink
    let mut route_message: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(RouteMessage::default()));
    route_message.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    route_message.finalize();

    // create route message buffer and send it to netlink for fetching IP addresses
    let mut route_message_buffer: Vec<u8> = vec![0u8; route_message.buffer_len()];
    route_message.serialize(&mut route_message_buffer);
    socket.send(&route_message_buffer, 0)?;

    // wait for message response from netlink and get our gateway IP addresses
    handle_netlink_messages(&socket, |inner_message: RouteNetlinkMessage| {
        if let RouteNetlinkMessage::NewRoute(route) = inner_message {
            // if not default route we continue to next message in stream
            if route.header.destination_prefix_length != 0 {
                return true;
            }

            // define our default gateway IP addresses and index
            let mut gateway_ipv4: Option<Ipv4Addr> = None;
            let mut gateway_ipv6: Option<Ipv6Addr> = None;
            let mut gateway_index: Option<u32> = None;

            // iterate over each route attribute and find gateway IP addresses and index
            for route_attr in route.attributes {
                match route_attr {
                    RouteAttribute::Gateway(RouteAddress::Inet(ip)) => gateway_ipv4 = Some(ip),
                    RouteAttribute::Gateway(RouteAddress::Inet6(ip)) => gateway_ipv6 = Some(ip),
                    RouteAttribute::Oif(index) => gateway_index = Some(index),
                    _ => {}
                }
            }

            // check if gateway index matches our interface index, if so add gateway IP addresses to our vectors
            if gateway_index == Some(interface_index) {
                if let Some(gateway_ipv4) = gateway_ipv4 {
                    ipv4_vec.push(gateway_ipv4);
                }
                if let Some(gateway_ipv6) = gateway_ipv6 {
                    ipv6_vec.push(gateway_ipv6);
                }
            }
        }
        true
    });

    // check that both ip vectors are not empty and return given interface gateway IP addresses
    if ipv4_vec.is_empty() && ipv6_vec.is_empty() {
        Err("No default gateway found for given interface.".into())
    }
    else {
        Ok((ipv4_vec, ipv6_vec))
    }
}


/**
 * Function for getting default gateway IPv4 and IPv6 addresses for the given interface.
 * Returns tuple of IPv4 and IPv6 vectors, else returns Error if not found given interface.
 */
pub fn get_default_gateway(interface: &str) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), Box<dyn Error>> {
    // resolve index for given interface for retrieving default gateway IP addresses
    let interface_index: u32 = get_interface_index(interface)?;

    // retrieve interface default gateway IP addresses with its ip vectors
    let (ipv4_vec, ipv6_vec) = get_interface_default_gateway(interface_index)?;

    // return interface default gateway IP addresses 
    Ok((ipv4_vec, ipv6_vec))
}