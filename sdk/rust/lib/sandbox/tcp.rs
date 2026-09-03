//! Guest-originated TCP streams.
//!
//! This module exposes the agent protocol's TCP tunnel as a normal Tokio
//! byte stream. The destination is resolved and connected inside the guest;
//! no guest port is published on the host.

use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use microsandbox_protocol::{
    message::MessageType,
    tcp::{TcpClose, TcpClosed, TcpConnect, TcpConnected, TcpData, TcpEof, TcpFailed},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use crate::{
    MicrosandboxError, MicrosandboxResult, Sandbox,
    agent::AgentClient,
    error::{Operation, UnsupportedReason},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default deadline for connecting to a TCP destination from inside the guest.
pub const DEFAULT_GUEST_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const GUEST_TCP_BUFFER_SIZE: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An ordered byte stream connected from inside a sandbox guest.
///
/// The stream implements Tokio's [`AsyncRead`] and [`AsyncWrite`] traits. Dropping
/// it aborts the local relay and sends a best-effort close to the guest agent.
/// The destination is never exposed as a listening port on the host.
pub struct GuestTcpStream {
    stream: DuplexStream,
    connection: Option<GuestTcpConnection>,
}

struct GuestTcpConnection {
    id: u32,
    client: Arc<AgentClient>,
    relay: tokio::task::JoinHandle<()>,
    closed: Arc<AtomicBool>,
}

//--------------------------------------------------------------------------------------------------
// Methods: Sandbox
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Connect to a TCP destination from inside this sandbox guest.
    ///
    /// This uses the authenticated agent tunnel and does not publish the
    /// destination port. Network policy configured for the sandbox remains in
    /// force. Use `127.0.0.1` to reach a service bound only inside the guest.
    pub async fn connect_guest_tcp(
        &self,
        host: impl Into<String>,
        port: u16,
    ) -> MicrosandboxResult<GuestTcpStream> {
        self.connect_guest_tcp_with_timeout(host, port, DEFAULT_GUEST_TCP_CONNECT_TIMEOUT)
            .await
    }

    /// Connect to a TCP destination from inside this sandbox guest with a deadline.
    pub async fn connect_guest_tcp_with_timeout(
        &self,
        host: impl Into<String>,
        port: u16,
        timeout: Duration,
    ) -> MicrosandboxResult<GuestTcpStream> {
        let host = host.into();
        super::validate_hostname(Some(&host))?;
        if port == 0 {
            return Err(MicrosandboxError::InvalidConfig(
                "guest TCP destination port must be non-zero".to_string(),
            ));
        }
        if timeout.is_zero() {
            return Err(MicrosandboxError::InvalidConfig(
                "guest TCP connect timeout must be non-zero".to_string(),
            ));
        }

        let client = Arc::new(
            super::fs::agent::connect_agent_with_timeout(
                self.backend().as_ref(),
                self.name(),
                timeout,
            )
            .await?,
        );
        if !client.supports(MessageType::TcpConnect) {
            return Err(MicrosandboxError::unsupported(
                Operation::SandboxConnectGuestTcp,
                UnsupportedReason::NotAvailable(
                    "restart the sandbox with a runtime that supports guest TCP streams"
                        .to_string(),
                ),
            ));
        }

        let request = TcpConnect {
            host: host.clone(),
            port,
            // Preserve the framed TCP transport and its pre-bulk wire shape.
            bulk: None,
        };
        let (id, mut messages) =
            match tokio::time::timeout(timeout, client.stream(MessageType::TcpConnect, &request))
                .await
            {
                Ok(result) => result?,
                Err(_) => {
                    return Err(MicrosandboxError::GuestTcpConnectTimeout {
                        host,
                        port,
                        timeout,
                    });
                }
            };

        let first = match tokio::time::timeout(timeout, messages.recv()).await {
            Ok(Some(message)) => message,
            Ok(None) => {
                return Err(MicrosandboxError::GuestTcpConnect {
                    host,
                    port,
                    reason: "agent stream closed before the connection result".to_string(),
                });
            }
            Err(_) => {
                let _ = client.send(id, MessageType::TcpClose, &TcpClose {}).await;
                return Err(MicrosandboxError::GuestTcpConnectTimeout {
                    host,
                    port,
                    timeout,
                });
            }
        };

        match first.t {
            MessageType::TcpConnected => {
                let _: TcpConnected = first.payload()?;
            }
            MessageType::TcpFailed => {
                let failed: TcpFailed = first.payload()?;
                return Err(MicrosandboxError::GuestTcpConnect {
                    host,
                    port,
                    reason: failed.error,
                });
            }
            other => {
                let _ = client.send(id, MessageType::TcpClose, &TcpClose {}).await;
                return Err(MicrosandboxError::GuestTcpConnect {
                    host,
                    port,
                    reason: format!("unexpected agent response {}", other.as_str()),
                });
            }
        }

        Ok(GuestTcpStream::start(id, client, messages))
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: GuestTcpStream
//--------------------------------------------------------------------------------------------------

impl GuestTcpStream {
    fn start(
        id: u32,
        client: Arc<AgentClient>,
        messages: tokio::sync::mpsc::Receiver<microsandbox_protocol::message::Message>,
    ) -> Self {
        let (stream, relay_stream) = tokio::io::duplex(GUEST_TCP_BUFFER_SIZE);
        let closed = Arc::new(AtomicBool::new(false));
        let relay = tokio::spawn(relay_guest_tcp(
            id,
            Arc::clone(&client),
            messages,
            relay_stream,
            Arc::clone(&closed),
        ));
        Self {
            stream,
            connection: Some(GuestTcpConnection {
                id,
                client,
                relay,
                closed,
            }),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for GuestTcpStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GuestTcpStream")
            .field("connected", &self.connection.is_some())
            .finish_non_exhaustive()
    }
}

impl AsyncRead for GuestTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for GuestTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

impl Drop for GuestTcpStream {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        connection.relay.abort();
        if connection.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = connection
                    .client
                    .send(connection.id, MessageType::TcpClose, &TcpClose {})
                    .await;
            });
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn relay_guest_tcp(
    id: u32,
    client: Arc<AgentClient>,
    mut messages: tokio::sync::mpsc::Receiver<microsandbox_protocol::message::Message>,
    relay_stream: DuplexStream,
    closed: Arc<AtomicBool>,
) {
    let (mut application_reader, mut application_writer) = tokio::io::split(relay_stream);
    let mut buffer = vec![0_u8; GUEST_TCP_BUFFER_SIZE];
    let mut application_eof = false;
    let mut guest_eof = false;
    let mut guest_closed = false;

    loop {
        tokio::select! {
            read = application_reader.read(&mut buffer), if !application_eof => {
                match read {
                    Ok(0) => {
                        application_eof = true;
                        if client.send(id, MessageType::TcpEof, &TcpEof {}).await.is_err() {
                            break;
                        }
                    }
                    Ok(length) => {
                        if client
                            .send(
                                id,
                                MessageType::TcpData,
                                &TcpData { data: buffer[..length].to_vec() },
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "guest TCP application stream read failed");
                        break;
                    }
                }
            }
            message = messages.recv() => {
                let Some(message) = message else {
                    break;
                };
                match message.t {
                    MessageType::TcpData if !guest_eof => {
                        match message.payload::<TcpData>() {
                            Ok(data) if application_writer.write_all(&data.data).await.is_ok() => {}
                            Ok(_) => break,
                            Err(error) => {
                                tracing::warn!(%error, "guest TCP data frame could not be decoded");
                                break;
                            }
                        }
                    }
                    MessageType::TcpEof => {
                        if let Err(error) = message.payload::<TcpEof>() {
                            tracing::warn!(%error, "guest TCP EOF frame could not be decoded");
                        }
                        guest_eof = true;
                        let _ = application_writer.shutdown().await;
                    }
                    MessageType::TcpClosed => {
                        if let Err(error) = message.payload::<TcpClosed>() {
                            tracing::warn!(%error, "guest TCP close frame could not be decoded");
                        }
                        guest_closed = true;
                        break;
                    }
                    MessageType::TcpFailed => {
                        match message.payload::<TcpFailed>() {
                            Ok(failed) => tracing::debug!(reason = %failed.error, "guest TCP stream failed"),
                            Err(error) => tracing::warn!(%error, "guest TCP failure frame could not be decoded"),
                        }
                        guest_closed = true;
                        break;
                    }
                    other => {
                        tracing::warn!(message_type = other.as_str(), "unexpected guest TCP frame");
                        break;
                    }
                }
            }
        }

        if application_eof && guest_eof {
            break;
        }
    }

    let _ = application_writer.shutdown().await;
    if !guest_closed {
        let _ = client.send(id, MessageType::TcpClose, &TcpClose {}).await;
    }
    closed.store(true, Ordering::Release);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn duplex_side_preserves_order_and_half_close() {
        let (mut exposed, mut relay) = tokio::io::duplex(32);

        exposed.write_all(b"request").await.unwrap();
        exposed.shutdown().await.unwrap();

        let mut request = Vec::new();
        relay.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");

        relay.write_all(b"response").await.unwrap();
        relay.shutdown().await.unwrap();

        let mut response = Vec::new();
        exposed.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
    }
}
