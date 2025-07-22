use anyhow::Result;
use ip_header::modify_tcp_options;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::{Packet, PacketSize};
use pnet::transport::{TransportChannelType::Layer3, ipv4_packet_iter, transport_channel};
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    let local_addr: Ipv4Addr = "172.20.223.162".parse()?;
    let local_port = 9000;
    let dest_addr: Ipv4Addr = "106.54.227.154".parse()?;
    let dest_port = 8001;

    tokio::spawn(run_tcp_listener(local_port));

    // 创建原始套接字通道，用于捕获 IP 数据包
    // let (mut tx, mut rx) =
    //     transport_channel(4096, Layer3(IpNextHeaderProtocols::Ipv4)).expect("无法创建通道");
    // let mut rx_iter = ipv4_packet_iter(&mut rx);

    // 获取本地的网络接口
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| {
            iface.is_up() && iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .expect("未找到可用的网络接口");

    println!("监听接口: {}", interface.name);

    // 创建数据通道
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("未实现的通道类型"),
        Err(e) => panic!("创建通道失败: {}", e),
    };
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                // 只处理 IPv4 数据包
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip_packet) = Ipv4Packet::new(ethernet.payload()) {
                        if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                                if tcp_packet.get_destination() == local_port {
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
                                    // 修改 TCP 选项
                                    let from_ip = ip_packet.get_source();
                                    let dest_ip = ip_packet.get_destination();
                                    let new_tcp_packet = modify_tcp_options(
                                        tcp_packet, local_addr, dest_addr, local_port, dest_port,
                                    );
                                    // 重新构造IP数据包
                                    let ip_size = (ip_packet.get_header_length() * 4) as usize
                                        + new_tcp_packet.len();
                                    let mut ip_buffer = vec![0u8; ip_size];
                                    let mut new_ip_packet =
                                        MutableIpv4Packet::new(&mut ip_buffer).unwrap();
                                    new_ip_packet.set_version(ip_packet.get_version());
                                    new_ip_packet.set_header_length(ip_packet.get_header_length());
                                    new_ip_packet.set_total_length(ip_size as u16);
                                    new_ip_packet.set_ttl(64);
                                    new_ip_packet
                                        .set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                                    new_ip_packet.set_source(local_addr);
                                    new_ip_packet.set_destination(dest_ip);
                                    new_ip_packet.set_payload(&*new_tcp_packet);

                                    match tx
                                        .send_to(new_ip_packet.payload(), Some(interface.clone()))
                                        .unwrap()
                                    {
                                        Ok(_) => {
                                            println!("转发成功");
                                        }
                                        Err(_) => {
                                            println!("转发失败");
                                        }
                                    };
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // loop {
    //     // 接收数据包
    //     let (ip_packet, _ip_addr) = rx_iter.next().expect("无法读取数据包");
    //     println!("收到TCP数据包：");
    //     println!("源地址:\t {}", ip_packet.get_source());
    //     println!("目标地址:\t {}", ip_packet.get_destination());
    //     println!("协议类型:\t {:?}", ip_packet.get_next_level_protocol());
    //     // 如果是 TCP 数据包，可以进一步解析
    //     if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
    //         if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
    //             println!("TCP源端口:\t {}", tcp_packet.get_source());
    //             println!("TCP目标端口:\t {}", tcp_packet.get_destination());
    //             println!("TCP 序列号:\t {}", tcp_packet.get_sequence());
    //             println!("TCP 确认号:\t {}", tcp_packet.get_acknowledgement());
    //             println!("TCP flag:\t {}", tcp_packet.get_flags());
    //             println!("TCP Options:\t {:?}", tcp_packet.get_options());
    //             println!("TCP Data length:\t {:?}", tcp_packet.payload().len());
    //             if tcp_packet.get_destination() == local_port {
    //                 // 修改 TCP 选项
    //                 let from_ip = ip_packet.get_source();
    //                 let dest_ip = ip_packet.get_destination();
    //                 let new_tcp_packet = modify_tcp_options(tcp_packet, from_ip, dest_ip);
    //                 // 重新构造IP数据包
    //                 let ip_size = ip_packet.get_header_length() as usize + new_tcp_packet.len();
    //                 let mut ip_buffer = vec![0u8; ip_size];
    //                 let mut new_ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    //                 new_ip_packet.set_version(ip_packet.get_version());
    //                 new_ip_packet.set_header_length(ip_packet.get_header_length());
    //                 new_ip_packet.set_total_length(ip_size as u16);
    //                 new_ip_packet.set_ttl(64);
    //                 new_ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    //                 new_ip_packet.set_source(local_addr);
    //                 new_ip_packet.set_destination(dest_ip);
    //                 new_ip_packet.set_payload(&*new_tcp_packet);
    //
    //                 tx.send_to(new_ip_packet, IpAddr::from(dest_ip)).unwrap();
    //             }
    //         }
    //     }
    // }
}

async fn run_tcp_listener(local_port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", local_port);
    let listener = TcpListener::bind(addr.clone()).await?;
    println!("服务器正在监听 {}", addr.to_string());

    loop {
        let (socket, _addr) = listener.accept().await?;
        tokio::spawn(handle_connection(socket));
    }
}

async fn handle_connection(mut socket: TcpStream) {
    // 创建一个缓冲区
    let mut buffer = vec![0u8; 1024];

    loop {
        // 异步读取数据
        match socket.read(&mut buffer).await {
            Ok(0) => {
                // 客户端关闭了连接
                println!("客户端关闭了连接");
                break;
            }
            Ok(n) => {
                // 打印接收到的数据
                println!("tokio 接收到数据: {:?}", &buffer[..n]);
                // 异步写回客户端
                // 先等待
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                let response = b"HTTP/1.1 200 OK\r\n\r\nHello from proxy!";
                if let Err(e) = socket.write_all(response).await {
                    println!("写回数据时发生错误: {}", e);
                    break;
                }
            }
            Err(e) => {
                println!("读取数据时发生错误: {}", e);
                break;
            }
        }
    }
}
