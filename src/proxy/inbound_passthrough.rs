// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::net::SocketAddr;

use tokio::net::TcpStream;
use tracing::{error, info, trace, warn, Instrument};

use crate::metrics::traffic;
use crate::metrics::traffic::Reporter;
use crate::proxy::outbound::OutboundConnection;
use crate::proxy::{util, ProxyInputs};
use crate::proxy::{Error, TraceParent};
use crate::rbac;
use crate::{proxy, socket};

pub(super) struct InboundPassthrough {
    listener: crate::extensions::WrappedTcpListener,
    pi: ProxyInputs,
}

impl InboundPassthrough {
    pub(super) async fn new(mut pi: ProxyInputs) -> Result<InboundPassthrough, Error> {
        let listener = pi
            .cfg
            .extensions
            .bind(
                pi.cfg.inbound_plaintext_addr,
                crate::extensions::ListenerType::InboundPassthrough,
            )
            .await
            .map_err(|e| Error::Bind(pi.cfg.inbound_plaintext_addr, e))?;
        let transparent = super::maybe_set_transparent(&pi, listener.as_ref())?;
        // Override with our explicitly configured setting
        pi.cfg.enable_original_source = Some(transparent);

        info!(
            address=%listener.as_ref().local_addr().unwrap(),
            component="inbound plaintext",
            transparent,
            "listener established",
        );
        Ok(InboundPassthrough { listener, pi })
    }

    #[cfg(test)]
    pub(super) fn address(&self) -> SocketAddr {
        self.listener.as_ref().local_addr().unwrap()
    }

    pub(super) async fn run(self) {
        loop {
            // Asynchronously wait for an inbound socket.
            let socket = self.listener.accept().await;
            let pi = self.pi.clone();
            match socket {
                Ok((stream, remote)) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_inbound_plaintext(
                            pi.clone(),
                            socket::to_canonical(remote),
                            stream,
                        )
                        .await
                        {
                            warn!(source=%socket::to_canonical(remote), component="inbound plaintext", "proxying failed: {}", e)
                        }
                    }.in_current_span());
                }
                Err(e) => {
                    if util::is_runtime_shutdown(&e) {
                        return;
                    }
                    error!("Failed TCP handshake {}", e);
                }
            }
        }
    }

    async fn proxy_inbound_plaintext(
        pi: ProxyInputs,
        source: SocketAddr,
        mut inbound: TcpStream,
    ) -> Result<(), Error> {
        let orig = orig_dst_addr_or_default(&inbound);
        if Some(orig.ip()) == pi.cfg.local_ip {
            return Err(Error::SelfCall);
        }
        info!(%source, destination=%orig, component="inbound plaintext", "accepted connection");
        let Some(upstream) = pi.workloads.fetch_workload(&orig.ip()).await else {
            return Err(Error::UnknownDestination(orig.ip()))
        };
        if !upstream.waypoint_addresses.is_empty() {
            // This is an inbound request not over HBONE, but we have a waypoint.
            // The request needs to go through the waypoint for policy enforcement.
            // This can happen from clients that are not part of the mesh; they won't know to send
            // to the waypoint.
            // To handle this, we forward it to the waypoint ourselves, which will hairpin back to us.
            let mut oc = OutboundConnection {
                pi: pi.clone(),
                id: TraceParent::new(),
            };
            // Spoofing the source IP only works when the destination or the source are on our node.
            // In this case, the source and the destination might both be remote, so we need to disable it.
            oc.pi.cfg.enable_original_source = Some(false);
            return oc.proxy_to(inbound, source.ip(), orig, false).await;
        }

        // We enforce RBAC only for non-hairpin cases. This is because we may not be able to properly
        // enforce the policy (for example, if it has L7 attributes), while waypoint will.
        // Instead, we skip enforcement and forward to the waypoint to enforce.
        // On the inbound HBONE side, we will validate it came from the waypoint (and therefor had enforcemen).
        let conn = rbac::Connection {
            src_identity: None,
            src_ip: source.ip(),
            dst: orig,
        };
        if !pi.workloads.assert_rbac(&conn).await {
            info!(%conn, "RBAC rejected");
            return Ok(());
        }
        let source_ip = super::get_original_src_from_stream(&inbound);
        let orig_src = pi
            .cfg
            .enable_original_source
            .unwrap_or_default()
            .then_some(source_ip)
            .flatten();
        trace!(%source, destination=%orig, component="inbound plaintext", "connect to {orig:?} from {orig_src:?}");
        let mut outbound = pi
            .cfg
            .extensions
            .connect(
                orig_src,
                orig,
                crate::extensions::UpstreamDestination::UpstreamServer,
            )
            .await?;
        trace!(%source, destination=%orig, component="inbound plaintext", "connected");

        // Find source info. We can lookup by XDS or from connection attributes
        let source_workload = if let Some(source_ip) = source_ip {
            pi.workloads.fetch_workload(&source_ip).await
        } else {
            None
        };
        let derived_source = traffic::DerivedWorkload {
            identity: conn.src_identity,
            // TODO: use baggage for the rest
            ..Default::default()
        };
        let connection_metrics = traffic::ConnectionOpen {
            reporter: Reporter::destination,
            source: source_workload,
            derived_source: Some(derived_source),
            destination: Some(upstream.clone()),
            connection_security_policy: traffic::SecurityPolicy::unknown,
            destination_service: None,
            destination_service_namespace: None,
            destination_service_name: None,
        };
        let _connection_close = pi
            .metrics
            .increment_defer::<_, traffic::ConnectionClose>(&connection_metrics);
        let transferred_bytes = traffic::BytesTransferred::from(&connection_metrics);
        proxy::relay(outbound.as_mut(), &mut inbound, &pi.metrics, transferred_bytes).await?;
        info!(%source, destination=%orig, component="inbound plaintext", "connection complete");
        Ok(())
    }
}

#[cfg(not(test))]
fn orig_dst_addr_or_default(stream: &tokio::net::TcpStream) -> std::net::SocketAddr {
    socket::orig_dst_addr_or_default(stream)
}

#[cfg(test)]
fn orig_dst_addr_or_default(_: &tokio::net::TcpStream) -> std::net::SocketAddr {
    "127.0.0.1:8182".parse().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::{identity, workload};
    use crate::identity::mock::CaClient as MockCaClient;
    use bytes::Bytes;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::workload::WorkloadInformation;

    #[tokio::test]
    async fn extension_on_for_inbound_passthrough() {
        use std::sync::atomic::Ordering;
        let ext: crate::extensions::mock::MockExtension = Default::default();
        let state = ext.state.clone();
        let duration = Duration::from_secs(10);
        let time_conv = crate::time::Converter::new();
        let mock_ca_client = MockCaClient::new(identity::mock::ClientConfig {
            cert_lifetime: duration,
            time_conv: time_conv.clone(),
            ..Default::default()
        });
        let cfg = Config {
            extensions: crate::extensions::ExtensionManager::new(Some(Box::new(ext))),
            inbound_plaintext_addr: "127.0.0.1:0".parse().unwrap(),
            ..crate::config::parse_config(None).unwrap()
        };
        let source = XdsWorkload {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            address: Bytes::copy_from_slice(&[127, 0, 0, 1]),
            node: "local-node".to_string(),
            ..Default::default()
        };
        let xds = XdsWorkload {
            address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
            ..Default::default()
        };
        let wl = workload::WorkloadStore::test_store(vec![source, xds]).unwrap();

        let wi = WorkloadInformation {
            info: Arc::new(Mutex::new(wl)),
            demand: None,
        };
        let pi = ProxyInputs {
            cert_manager: Box::new(mock_ca_client),
            workloads: wi,
            hbone_port: 15008,
            cfg,
            metrics: Arc::new(Default::default()),
        };
        let inbound = InboundPassthrough::new(pi).await.unwrap();
        let addr = inbound.address();

        tokio::spawn(inbound.run());

        let _s = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::net::TcpStream::connect(addr).await
        })
        .await
        .expect("timeout waiting for pre connect")
        .expect("failed to connect");

        // test that eventual (i.e. 1s) we get the metric incremented
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while state.on_pre_connect.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timeout waiting for pre connect");

        assert_eq!(state.on_pre_connect.load(Ordering::SeqCst), 1);
    }
}
