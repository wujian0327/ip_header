use std::net::Ipv4Addr;

use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::udp::MutableUdpPacket;
use pnet::transport::{TransportChannelType::Layer3, transport_channel};


fn main() {
    // 创建原始套接字通道
    let (mut tx, _) =
        transport_channel(4096, Layer3(IpNextHeaderProtocols::Udp)).expect("无法创建通道");

    // 构造 UDP 头部
    let dst_port = 8001;
    let src_port = 54321;
    // let dst_addr: Ipv4Addr = "222.20.126.106".parse().unwrap();
    let dst_addr: Ipv4Addr = "127.0.0.1".parse().unwrap();

    // 负载数据
    let payload = b"Hello, Biaoshi!";
    let udp_header_len = 8; // UDP 头部固定 8 字节
    let udp_total_len = udp_header_len + payload.len();
    let mut udp_buffer = vec![0u8; udp_total_len];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();

    udp_packet.set_source(src_port);
    udp_packet.set_destination(dst_port);
    udp_packet.set_length(udp_total_len as u16);
    udp_packet.set_payload(payload);

    // 构造 IP 头部
    let ip_header_len = 28;
    let mut ip_buffer = vec![0u8; ip_header_len + udp_total_len];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();

    ip_packet.set_version(4);
    ip_packet.set_header_length(7);
    ip_packet.set_total_length((ip_header_len + udp_total_len) as u16);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_packet.set_source(std::net::Ipv4Addr::new(172, 30, 73, 89));
    ip_packet.set_destination(dst_addr);
    ip_packet.set_payload(udp_packet.packet());

    let options_buf = ip_packet.get_options_raw_mut();
    options_buf.clone_from_slice(&[0x79, 0x08, 0x12, 0x34, 0x56, 0x78, 0x99, 0x99]);

    // 合并 IP 头部和 UDP 数据包
    ip_packet.set_payload(&udp_buffer);

    // 发送数据包
    tx.send_to(&ip_packet, std::net::IpAddr::V4(dst_addr))
        .expect("发送失败");
    println!("UDP 数据包已发送！");
}
