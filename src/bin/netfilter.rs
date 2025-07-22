use std::net::Ipv4Addr;

use ip_header::modify_tcp_options;
use nfq::{Queue, Verdict};
use pnet::packet::ipv4::checksum;
use pnet::packet::{
    MutablePacket, Packet,
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::TcpPacket,
};

fn main() -> std::io::Result<()> {
    let mut queue = Queue::open()?;
    queue.bind(0)?;
    queue.set_recv_conntrack(0, true)?;
    queue.set_recv_security_context(0, true)?;
    queue.set_recv_uid_gid(0, true)?;
    loop {
        let mut msg = queue.recv()?;
        let payload = msg.get_payload().to_vec();
        let ip_packet = match Ipv4Packet::new(&payload) {
            Some(ip_packet) => ip_packet,
            None => {
                eprintln!("Not IP Packet");
                continue;
            }
        };
        let tcp_packet = match TcpPacket::new(ip_packet.payload()) {
            Some(tcp_packet) => tcp_packet,
            None => {
                eprintln!("Not TCP Packet");
                continue;
            }
        };

        let local_addr: Ipv4Addr = ip_packet.get_source();
        let dest_addr: Ipv4Addr = ip_packet.get_destination();
        // 修改 TCP 选项
        let new_tcp_packet = modify_tcp_options(tcp_packet, local_addr, dest_addr);

        // 重新构造IP数据包
        let ip_header_len = ip_packet.get_header_length() as usize * 4;
        let ip_packet_size = ip_header_len + new_tcp_packet.len();
        let mut ip_buffer = vec![0u8; ip_packet_size];
        let mut new_ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
        // 复制ip的前 20 个字节到 ip_buffer
        new_ip_packet.packet_mut()[0..ip_header_len].copy_from_slice(&payload[0..ip_header_len]);
        // 修改header部分字段
        new_ip_packet.set_total_length(ip_packet_size as u16);
        new_ip_packet.set_checksum(0);
        let checksum = checksum(&new_ip_packet.to_immutable());
        new_ip_packet.set_checksum(checksum);
        new_ip_packet.set_payload(&*new_tcp_packet);

        let ip_packet = new_ip_packet.packet().to_vec();
        msg.set_payload(ip_packet);
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;
    }
}
