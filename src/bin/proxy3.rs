use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::{Packet, PacketSize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};

fn main() -> io::Result<()> {
    // 创建原始套接字
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::TCP), // 监听TCP包
    )?;

    // 绑定到所有接口
    let address: SocketAddr = "0.0.0.0:9000".parse().unwrap();
    socket.bind(&address.into())?;

    // let mut buffer = [0u8; 65535];
    let mut buffer = vec![MaybeUninit::<u8>::uninit(); 1024];
    loop {
        let size = socket.recv(&mut buffer)?;

        if size >= 20 {
            let buffer: Vec<u8> = buffer
                .iter()
                .map(|uninit| unsafe { uninit.assume_init() })
                .collect();

            let ip_packet = Ipv4Packet::new(&buffer).unwrap();
            if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                    if tcp_packet.get_destination() == 9000 {
                        println!("收到IP数据包：");
                        println!("源地址:\t {}", ip_packet.get_source());
                        println!("目标地址:\t {}", ip_packet.get_destination());
                        println!(
                            "协议类型:\t {:?}",
                            ip_packet.get_next_level_protocol().to_string()
                        );
                        println!("TCP源端口:\t {}", tcp_packet.get_source());
                        println!("TCP目标端口:\t {}", tcp_packet.get_destination());
                        println!("TCP 序列号:\t {}", tcp_packet.get_sequence());
                        println!("TCP 确认号:\t {}", tcp_packet.get_acknowledgement());
                        println!("TCP flag:\t {}", tcp_packet.get_flags());
                        println!("TCP Options:\t {:?}", tcp_packet.get_options());
                        println!("TCP Data length:\t {:?}", tcp_packet.payload().len());

                        // 模拟响应（例如：回应一个 SYN-ACK 包）
                        if tcp_packet.get_flags() == 2 {
                            // SYN 包
                            let response_packet = create_syn_ack_response(&ip_packet, &tcp_packet)?;
                            let address =
                                format!("{}:{}", ip_packet.get_source(), tcp_packet.get_source());
                            let address: SocketAddr = address.parse().unwrap();
                            println!("address:{}", address);
                            socket.send_to(&response_packet, &SockAddr::from(address))?;
                            println!("响应 SYN-ACK 数据包。");
                        }
                    }
                }
            }
        } else {
            println!("捕获到未知数据包");
        }
    }
}

/// 创建 SYN-ACK 数据包作为响应
fn create_syn_ack_response(ip_packet: &Ipv4Packet, tcp_packet: &TcpPacket) -> io::Result<Vec<u8>> {
    let mut tcp_buffer = vec![0u8; tcp_packet.packet_size()];
    // 创建 TCP 响应
    // 这里创建一个简单的 SYN-ACK 包，注意这里你可能需要根据实际需要设置更详细的字段
    let mut new_tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    new_tcp_packet.set_source(tcp_packet.get_destination());
    new_tcp_packet.set_destination(tcp_packet.get_source());
    new_tcp_packet.set_flags(0x12); // 设置 SYN 和 ACK 标志
    new_tcp_packet.set_sequence(tcp_packet.get_acknowledgement());
    new_tcp_packet.set_acknowledgement(tcp_packet.get_sequence() + 1);

    // 创建 IP 响应包
    let mut ip_buffer =
        vec![0u8; (ip_packet.get_header_length() * 4) as usize + new_tcp_packet.packet_size()];
    let mut new_ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    new_ip_packet.set_source(ip_packet.get_destination());
    new_ip_packet.set_destination(ip_packet.get_source());
    new_ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);

    Ok(new_ip_packet.packet().to_vec())
}
