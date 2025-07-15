use std::net::Ipv4Addr;

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
