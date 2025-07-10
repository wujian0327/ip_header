use std::net::Ipv4Addr;

use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4OptionPacket, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
use pnet::transport::{TransportChannelType::Layer3, transport_channel};

fn main() {
    // 创建原始套接字通道
    let (mut tx, _) =
        transport_channel(4096, Layer3(IpNextHeaderProtocols::Tcp)).expect("无法创建通道");

    // 构造 TCP 头部
    let dst_port = 8001;
    let src_port = 54321;
    // let dst_addr: Ipv4Addr = "222.20.126.106".parse().unwrap();
    let from_addr: Ipv4Addr = "172.23.25.59".parse().unwrap();
    let dst_addr: Ipv4Addr = "106.54.227.154".parse().unwrap();

    // 负载数据
    let payload = b"Hello, Biaoshi!";
    let tcp_header_len = 32;
    let tcp_total_len = tcp_header_len + payload.len();
    let mut tcp_buffer = vec![0u8; tcp_total_len];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

    tcp_packet.set_source(src_port);
    tcp_packet.set_destination(dst_port);
    tcp_packet.set_sequence(0);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(8);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(65535);
    tcp_packet.set_urgent_ptr(0);
    tcp_packet.set_payload(payload);

    let options_buf = tcp_packet.get_options_raw_mut();
    options_buf.clone_from_slice(&[
        253, 12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
    ]);

    let check = tcp_checksum(from_addr, dst_addr, tcp_packet.packet());
    tcp_packet.set_checksum(check);

    // 构造 IP 头部
    let ip_header_len = 20;
    let mut ip_buffer = vec![0u8; ip_header_len + tcp_total_len];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();

    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length((ip_header_len + tcp_total_len) as u16);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(std::net::Ipv4Addr::new(172, 23, 25, 59).into());
    ip_packet.set_destination(dst_addr);
    ip_packet.set_payload(tcp_packet.packet());

    // 合并 IP 头部和 TCP 数据包
    ip_packet.set_payload(&tcp_buffer);

    // 发送数据包
    tx.send_to(&ip_packet, std::net::IpAddr::V4(dst_addr))
        .expect("发送失败");
    println!("TCP 数据包已发送！");
}

/// 计算 TCP 校验和
///
/// # 参数
/// - `source_ip`: 源 IP 地址
/// - `dest_ip`: 目标 IP 地址
/// - `tcp_segment`: TCP 段数据 (包括头部和负载)
///
/// # 返回
/// 计算得到的 16 位校验和
pub fn tcp_checksum(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum = 0u32;

    // 1. 添加伪首部 (pseudo-header)
    // 源地址 (32位)
    sum += u32::from_be_bytes(source_ip.octets()) >> 16;
    sum += u32::from_be_bytes(source_ip.octets()) & 0xFFFF;

    // 目标地址 (32位)
    sum += u32::from_be_bytes(dest_ip.octets()) >> 16;
    sum += u32::from_be_bytes(dest_ip.octets()) & 0xFFFF;

    // 协议类型 (8位) + 保留 (8位) + TCP 长度 (16位)
    let tcp_length = tcp_segment.len() as u16;
    sum += (6u32 << 16) + u32::from(tcp_length);

    // 2. 添加 TCP 头部和数据
    let mut i = 0;
    while i < tcp_segment.len() {
        // 如果是最后一个字节且数据长度为奇数，补零
        if i == tcp_segment.len() - 1 {
            sum += u32::from(tcp_segment[i]) << 8;
        } else {
            sum += u32::from(u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]));
        }
        i += 2;
    }

    // 3. 将高16位加到低16位，直到没有进位
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    // 4. 取反得到校验和
    !sum as u16
}
