use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, Reply};

#[derive(Serialize, Deserialize, Debug)]
struct MyData {
    name: String,
    age: u32,
}

// 定义响应数据结构
#[derive(Debug, Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

// 处理 POST /json 路由
async fn create_user(data: MyData) -> Result<impl Reply, Rejection> {
    println!("Received data: {:?}", data);

    let response = ApiResponse {
        success: true,
        message: "".to_string(),
    };

    Ok(warp::reply::json(&response))
}

// 处理 GET /health 路由
async fn health_check() -> Result<impl Reply, Rejection> {
    Ok(warp::reply::json(&ApiResponse {
        success: true,
        message: "Server is healthy".to_string(),
    }))
}

#[tokio::main]
async fn main() {
    let create_user_route = warp::path!("json")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(create_user);

    let health_route = warp::path!("health")
        .and(warp::get())
        .and_then(health_check);

    // 组合所有路由
    let routes = create_user_route
        .or(health_route)
        .with(warp::cors().allow_any_origin());

    println!("Server started at http://0.0.0.0:8001");
    warp::serve(routes).run(([0, 0, 0, 0], 8001)).await;
}
