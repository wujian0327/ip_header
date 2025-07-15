use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task;

#[tokio::main]
async fn main() -> io::Result<()> {
    // 创建并绑定 TCP 监听器到本地地址
    let listener = TcpListener::bind("0.0.0.0:8001").await?;
    println!("Listening on 0.0.0.0:8001");

    // 无限循环，接受客户端连接
    loop {
        let (mut socket, _) = listener.accept().await?;
        println!("New connection established.");

        // 使用异步任务处理每个连接
        task::spawn(async move {
            let mut buffer = [0u8; 1024];

            loop {
                // 从 socket 读取数据
                match socket.read(&mut buffer).await {
                    Ok(0) => {
                        // 客户端关闭连接，退出循环
                        println!("Connection closed.");
                        break;
                    }
                    Ok(n) => {
                        // 打印接收到的数据
                        let data = String::from_utf8_lossy(&buffer[..n]);
                        println!("Received: {}", data);
                    }
                    Err(e) => {
                        // 错误处理
                        eprintln!("Error reading from socket: {}", e);
                        break;
                    }
                }
            }
        });
    }
}
