use std::net::Ipv4Addr;

use anyhow::Result;
use httparse::Request;
use ip_header::entity::mark_body;
use ip_header::{generate_mark_id, modify_tcp_options};
use nfq::{Queue, Verdict};
use pnet::packet::ipv4::checksum;
use pnet::packet::{
    MutablePacket, Packet,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::TcpPacket,
};
use rand::Rng;
use rand::distributions::Alphanumeric;
use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Iden, Set};

struct mark {
    mark_id: String,
    mark_body: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let db = Database::connect("mysql://root:123456@localhost:3306/mark").await?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<mark>(1000);

    // 数据库插入任务
    let db_clone = db.clone();
    tokio::spawn(async move {
        while let Some(mark) = rx.recv().await {
            insert_mysql(db_clone.clone(), mark.mark_id, mark.mark_body).await;
        }
    });

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

        let dest_addr: Ipv4Addr = ip_packet.get_destination();
        //  如果是 loopback 地址，直接放行，不写数据库
        if dest_addr.is_loopback() || dest_addr.is_private() {
            msg.set_verdict(Verdict::Accept);
            queue.verdict(msg)?;
            continue;
        }

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
        let mark_id: String = generate_mark_id();
        let new_tcp_packet = modify_tcp_options(tcp_packet, local_addr, dest_addr, mark_id.clone());

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
        msg.set_payload(ip_packet.clone());
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;

        let mark = mark {
            mark_id,
            mark_body: ip_packet,
        };
        tx.send(mark).await?;
    }
}

async fn insert_mysql(db: DatabaseConnection, mark_id: String, ip_packet: Vec<u8>) {
    let ip_packet = match Ipv4Packet::new(&ip_packet) {
        Some(ip_packet) => ip_packet,
        None => return,
    };
    let tcp_packet = match TcpPacket::new(ip_packet.payload()) {
        Some(tcp_packet) => tcp_packet,
        None => return,
    };
    let mut new_record = mark_body::ActiveModel {
        id: Default::default(),
        mark_id: Set(mark_id),
        ip_source: Set(ip_packet.get_source().to_string()),
        ip_destination: Set(ip_packet.get_destination().to_string()),
        ip_header_length: Set(Some(ip_packet.get_header_length() as i32)),
        ip_options: Set(Some(format!("{:?}", ip_packet.get_options()))),
        tcp_source: Set(Some(tcp_packet.get_source() as i32)),
        tcp_destination: Set(Some(tcp_packet.get_destination() as i32)),
        tcp_ack: Set(Some(tcp_packet.get_acknowledgement() as u32)),
        tcp_seq: Set(Some(tcp_packet.get_sequence() as u32)),
        tcp_offset: Set(Some(tcp_packet.get_data_offset() as i32)),
        tcp_flag: Set(Some(tcp_packet.get_flags() as i32)),
        tcp_options: Set(Some(format!("{:?}", tcp_packet.get_options()))),
        is_http: Set(Some(i8::from(false))),
        http_method: Set(Some("".to_string())),
        http_path: Set(Some("".to_string())),
        http_headers: Set(Some("".to_string())),
        create_by: Set(Some("admin".to_owned())),
        create_time: Default::default(),
        update_by: Set(Some("admin".to_owned())),
        update_time: Default::default(),
    };

    // 判断 HTTP
    let tcp_payload = tcp_packet.payload();
    if !tcp_payload.is_empty() {
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = Request::new(&mut headers);
        if let Ok(httparse::Status::Complete(_)) = req.parse(tcp_payload) {
            let headers_string = req
                .headers
                .iter()
                .map(|h| {
                    let value = std::str::from_utf8(h.value).unwrap_or("");
                    format!("{}: {}", h.name, value)
                })
                .collect::<Vec<String>>()
                .join("\r\n");
            new_record.is_http = Set(Some(i8::from(true)));
            new_record.http_method = Set(Some(req.method.unwrap_or("").to_string()));
            new_record.http_path = Set(Some(req.path.unwrap_or("").to_string()));
            new_record.http_headers = Set(Some(headers_string));
        }
    }

    // 插入数据
    let res = new_record.insert(&db).await;
    println!("Inserted: {:?}", res);
}
