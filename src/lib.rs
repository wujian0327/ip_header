use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use rand::Rng;
use rand::distributions::Alphanumeric;
use std::net::Ipv4Addr;

pub mod entity;

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

pub fn modify_tcp_options(
    origin_tcp_packet: TcpPacket,
    from_addr: Ipv4Addr,
    to_addr: Ipv4Addr,
    mark_id: String,
) -> Vec<u8> {
    // 获取原始的 TCP 各个字段
    let origin_packet = origin_tcp_packet.packet();
    let origin_payload = origin_tcp_packet.payload();

    //新增options字段
    let mut options_buf = Vec::from(&[253, 12]);
    options_buf.extend_from_slice(mark_id.as_bytes());
    options_buf.extend_from_slice(&*origin_tcp_packet.get_options_raw().to_vec());

    // 计算新的 TCP 头部长度
    let new_header_len = 20 + options_buf.len();
    let total_len = new_header_len + origin_payload.len();

    // 创建一个新的 MutableTcpPacket, 加上需要增加的 options 字段长度
    let mut buffer = vec![0u8; total_len];
    let mut new_tcp_packet_mut = MutableTcpPacket::new(&mut buffer).unwrap();

    // 复制 TCP 头部信息，复制除Options之外的字段
    new_tcp_packet_mut.packet_mut()[..20].copy_from_slice(&origin_packet[..20]);

    // 复制并扩展选项字段
    new_tcp_packet_mut.set_data_offset(origin_tcp_packet.get_data_offset() + 3);
    new_tcp_packet_mut
        .get_options_raw_mut()
        .copy_from_slice(&options_buf);

    // 将原始数据（如果有）复制到新的 TCP 包中
    new_tcp_packet_mut.set_payload(origin_payload);

    //重新计算checksum
    new_tcp_packet_mut.set_checksum(0);
    let check = tcp_checksum(from_addr, to_addr, new_tcp_packet_mut.packet());
    new_tcp_packet_mut.set_checksum(check);

    // 返回新的TCP 数据流
    new_tcp_packet_mut.packet().to_vec()
}

pub fn generate_mark_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect()
}
