use anyhow::Result;
use ip_header::modify_tcp_options;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
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
