use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize, Debug)]
struct MyData {
    name: String,
    age: u32,
}

#[tokio::main]
async fn main() -> Result<(), reqwest::Error> {
    // 创建一个 HTTP 客户端
    let client = Client::new();

    // 创建一个结构体实例，并将其序列化为 JSON
    let data = MyData {
        name: "Alice".to_string(),
        age: 30,
    };

    // 发送一个 POST 请求，并附带 JSON 数据
    let res = client
        .post("http://127.0.0.1:8001/json") // 替换为你想发送请求的 URL
        .json(&data) // 将结构体序列化为 JSON 发送
        .send()
        .await?;

    // 检查响应状态
    if res.status().is_success() {
        println!("Successfully sent the data!");
    } else {
        println!("Failed to send the data. Status: {}", res.status());
    }

    // 解析并打印响应体
    let body = res.text().await?;
    println!("Response body: {}", body);

    Ok(())
}
