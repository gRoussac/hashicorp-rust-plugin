use casper_vault_plugin::SecretKey;
use futures::executor::block_on;
use kv::kv_server::{Kv, KvServer};
use tonic::{transport::Server, Request, Response, Status};

pub mod kv {
    include!("kv.rs");
}

#[derive(Default)]
struct KVServicer;

#[tonic::async_trait]
impl Kv for KVServicer {
    async fn get(
        &self,
        request: Request<kv::GetRequest>,
    ) -> Result<Response<kv::GetResponse>, Status> {
        let filename = format!("kv_{}", request.get_ref().key);
        match std::fs::read_to_string(filename) {
            Ok(value) => {
                let response = kv::GetResponse { value };
                Ok(Response::new(response))
            }
            Err(_) => Err(Status::not_found("Key not found")),
        }
    }

    async fn put(&self, request: Request<kv::PutRequest>) -> Result<Response<kv::Empty>, Status> {
        // Generate the key
        let cleaned_key = SecretKey::generate_ed25519().unwrap().to_pem().unwrap();

        // Write the cleaned key to a file
        let filename = format!("kv_{}", cleaned_key);
        std::fs::write(filename, request.get_ref().key.as_bytes())
            .map_err(|_| Status::internal("Failed to write to file"))?;

        Ok(Response::new(kv::Empty {}))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start the gRPC server
    let addr = "[::1]:1234".parse()?;
    let kv_servicer = KVServicer;

    // Create a HealthServicer
    let (_, health_service) = tonic_health::server::health_reporter();

    // Spawn the gRPC server in a separate task
    tokio::spawn(async move {
        Server::builder()
            .add_service(KvServer::new(kv_servicer))
            .add_service(health_service)
            .serve(addr)
            .await
            .unwrap();
    });

    // Output handshake information
    println!("1|1|tcp|127.0.0.1:1234|grpc");

    // Block until the server completes
    block_on(tokio::signal::ctrl_c()).unwrap();

    Ok(())
}
