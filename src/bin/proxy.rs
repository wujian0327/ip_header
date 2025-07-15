use anyhow::Result;
use ip_header::tcp_checksum;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::{MutablePacket, Packet, tcp::TcpPacket};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn handle_connection(mut client: TcpStream) -> Result<()> {
    let (mut client_reader, mut client_writer) = client.split();

    // 读取客户端数据流
    let mut buffer = vec![0u8; 4096];
    let len = client_reader.read(&mut buffer).await?;

    if len > 0 {
        // 解析 TCP/IP 包
        let ip_packet = Ipv4Packet::new(&buffer).unwrap();
        let tcp_packet = TcpPacket::new(&buffer[ip_packet.get_header_length() as usize..]).unwrap();
        let from_ip = ip_packet.get_source();
        let from_port = tcp_packet.get_source();
        let dest_ip = ip_packet.get_destination();
        let dest_port = tcp_packet.get_destination();

        // 修改 TCP 选项（如果需要）
        let new_tcp_packet = modify_tcp_options(tcp_packet, from_ip, dest_ip);

        let from_addr = format!("{}:{}", from_ip, from_port);
        println!("From addr: {}", from_addr);
        // 连接到目标服务器
        let target_addr = format!("{}:{}", dest_ip, dest_port);
        println!("Target addr: {}", target_addr);
        let mut target = TcpStream::connect(target_addr).await?;
        let (mut target_reader, mut target_writer) = target.split();

        // 将修改后的数据包转发给目标服务器
        target_writer.write_all(&*new_tcp_packet).await?;

        // 接收目标服务器的响应
        target_reader.read_exact(&mut buffer).await?;

        // 转发响应到客户端
        client_writer.write_all(&buffer).await?;
    }

    Ok(())
}

fn modify_tcp_options(
    origin_tcp_packet: TcpPacket,
    from_addr: Ipv4Addr,
    to_addr: Ipv4Addr,
) -> Vec<u8> {
    // 获取原始的 TCP 各个字段
    let origin_packet = origin_tcp_packet.packet();
    let origin_payload = origin_tcp_packet.payload();

    //新增options字段
    let mut options_buf = Vec::from(&[
        253, 12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
    ]);
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
    new_tcp_packet_mut
        .get_options_raw_mut()
        .copy_from_slice(&options_buf);

    new_tcp_packet_mut.set_data_offset(origin_tcp_packet.get_reserved() + 3);

    //重新计算checksum
    new_tcp_packet_mut.set_checksum(0);
    let check = tcp_checksum(from_addr, to_addr, new_tcp_packet_mut.packet());
    new_tcp_packet_mut.set_checksum(check);

    // 将原始数据（如果有）复制到新的 TCP 包中
    new_tcp_packet_mut.set_payload(origin_payload);

    // 返回新的TCP 数据流
    new_tcp_packet_mut.packet().to_vec()
}

async fn run_proxy(listen_addr: String) -> Result<()> {
    let listener = TcpListener::bind(listen_addr.clone()).await?;
    println!("Listening on: {}", listen_addr);

    loop {
        let (client, _) = listener.accept().await?;
        println!("Accepted connection from: {}", client.peer_addr()?);

        // 处理每个连接，目标地址是传入的
        tokio::spawn(handle_connection(client));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let listen_addr = "127.0.0.1:9000"; // 代理监听的地址

    run_proxy(listen_addr.to_string()).await?;
    Ok(())
}
