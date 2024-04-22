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

use super::{Error, SocketFactory};
use bytes::Bytes;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper::http::{Request, Response};
use std::time::Duration;

use std::collections::hash_map::DefaultHasher;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, AtomicU16, Ordering};
use std::sync::Arc;

use tokio::sync::watch;
use tokio::task;

use tokio::sync::Mutex;
use tracing::{debug, error, trace};

use crate::config;
use crate::identity::{Identity, SecretManager};

use flurry;

use pingora_pool;

// A relatively nonstandard HTTP/2 connection pool designed to allow multiplexing proxied workload connections
// over a (smaller) number of HTTP/2 mTLS tunnels.
//
// The following invariants apply to this pool:
// - Every workload (inpod mode) gets its own connpool.
// - Every unique src/dest key gets their own dedicated connections inside the pool.
// - Every unique src/dest key gets 1-n dedicated connections, where N is (currently) unbounded but practically limited
//   by flow control throttling.
#[derive(Clone)]
pub struct WorkloadHBONEPool {
    state: Arc<PoolState>,
    pool_watcher: watch::Receiver<bool>,
}

// PoolState is effectively the gnarly inner state stuff that needs thread/task sync, and should be wrapped in a Mutex.
struct PoolState {
    pool_notifier: watch::Sender<bool>, // This is already impl clone? rustc complains that it isn't, tho
    timeout_tx: watch::Sender<bool>, // This is already impl clone? rustc complains that it isn't, tho
    // this is effectively just a convenience data type - a rwlocked hashmap with keying and LRU drops
    // and has no actual hyper/http/connection logic.
    connected_pool: Arc<pingora_pool::ConnectionPool<ConnClient>>,
    // this must be an atomic/concurrent-safe list-of-locks, so we can lock per-key, not globally, and avoid holding up all conn attempts
    established_conn_writelock: flurry::HashMap<u64, Option<Arc<Mutex<()>>>>,
    close_pollers: futures::stream::FuturesUnordered<task::JoinHandle<()>>,
    pool_unused_release_timeout: Duration,
    // This is merely a counter to track the overall number of conns this pool spawns
    // to ensure we get unique poolkeys-per-new-conn, it is not a limit
    pool_global_conn_count: AtomicI32,
    max_streamcount: u16,
    spawner: ConnSpawner,
}

struct ConnSpawner {
    cfg: config::Config,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    cert_manager: Arc<SecretManager>,
    timeout_rx: watch::Receiver<bool>,
}

// Does nothing but spawn new conns when asked
impl ConnSpawner {
    async fn new_pool_conn(
        &self,
        key: WorkloadKey,
    ) -> Result<http2::SendRequest<Empty<Bytes>>, Error> {
        debug!("spawning new pool conn for key {:#?}", key);
        let clone_key = key.clone();
        let mut c_builder = http2::Builder::new(crate::hyper_util::TokioExecutor);
        let builder = c_builder
            .initial_stream_window_size(self.cfg.window_size)
            .max_frame_size(self.cfg.frame_size)
            .initial_connection_window_size(self.cfg.connection_window_size);

        let local = self
            .cfg
            .enable_original_source
            .unwrap_or_default()
            .then_some(key.src);
        let cert = self.cert_manager.fetch_certificate(&key.src_id).await?;
        let connector = cert.outbound_connector(key.dst_id)?;
        let tcp_stream =
            super::freebind_connect(local, key.dst, self.socket_factory.as_ref()).await?;
        tcp_stream.set_nodelay(true)?; // TODO: this is backwards of expectations
        let tls_stream = connector.connect(tcp_stream).await?;
        let (request_sender, connection) = builder
            .handshake(::hyper_util::rt::TokioIo::new(tls_stream))
            .await
            .map_err(Error::HttpHandshake)?;

        // spawn a task to poll the connection and drive the HTTP state
        // if we got a drain for that connection, respect it in a race
        // it is important to have a drain here, or this connection will never terminate
        let mut driver_drain = self.timeout_rx.clone();
        tokio::spawn(async move {
            debug!("starting a connection driver for {:?}", clone_key);
            tokio::select! {
                    _ = driver_drain.changed() => {
                        debug!("draining outer HBONE connection {:?}", clone_key);
                    }
                    res = connection=> {
                        match res {
                            Err(e) => {
                                error!("Error in HBONE connection handshake: {:?}", e);
                            }
                            Ok(_) => {
                                debug!("done with HBONE connection handshake: {:?}", res);
                            }
                        }
                    }
            }
        });

        Ok(request_sender)
    }
}

impl PoolState {
    // This simply puts the connection back into the inner pool,
    // and sets up a timed popper, which will resolve
    // - when this reference is popped back out of the inner pool (doing nothing)
    // - when this reference is evicted from the inner pool (doing nothing)
    // - when the timeout_idler is drained (will pop)
    // - when the timeout is hit (will pop)
    //
    // Idle poppers are safe to invoke if the conn they are popping is already gone
    // from the inner queue, so we will start one for every insert, let them run or terminate on their own,
    // and poll them to completion on shutdown - any duplicates from repeated checkouts/checkins of the same conn
    // will simply resolve as a no-op in order.
    //
    // Note that "idle" in the context of this pool means "no one has asked for it or dropped it in X time, so prune it".
    //
    // Pruning the idle connection from the pool does not close it - it simply ensures the pool stops holding a ref.
    // hyper self-closes client conns when all refs are dropped and streamcount is 0, so pool consumers must
    // drop their checked out conns and/or terminate their streams as well.
    //
    // Note that this simply removes the client ref from this pool - if other things hold client/streamrefs refs,
    // they must also drop those before the underlying connection is fully closed.
    fn checkin_conn(&self, conn: ConnClient, pool_key: pingora_pool::ConnectionMeta) {
        let (evict, pickup) = self.connected_pool.put(&pool_key, conn);
        let rx = self.spawner.timeout_rx.clone();
        let pool_ref = self.connected_pool.clone();
        let pool_key_ref = pool_key.clone();
        let release_timeout = self.pool_unused_release_timeout;
        self.close_pollers.push(tokio::spawn(async move {
            debug!(
                "starting an idle timeout for connection {:#?}",
                pool_key_ref
            );
            pool_ref
                .idle_timeout(&pool_key_ref, release_timeout, evict, rx, pickup)
                .await;
            debug!(
                "connection {:#?} was removed/checked out/timed out of the pool",
                pool_key_ref
            )
        }));
        let _ = self.pool_notifier.send(true);
    }

    // Since we are using a hash key to do lookup on the inner pingora pool, do a get guard
    // to make sure what we pull out actually deep-equals the workload_key, to avoid *sigh* crossing the streams.
    fn guarded_get(
        &self,
        hash_key: &u64,
        workload_key: &WorkloadKey,
    ) -> Result<Option<ConnClient>, Error> {
        match self.connected_pool.get(hash_key) {
            None => Ok(None),
            Some(conn) => match Self::enforce_key_integrity(conn, workload_key) {
                Err(e) => Err(e),
                Ok(conn) => Ok(Some(conn)),
            },
        }
    }

    // Just for safety's sake, since we are using a hash thanks to pingora supporting arbitrary Eq, Hash
    // types, do a deep equality test before returning the conn, returning an error if the conn's key does
    // not equal the provided key
    //
    // this is a final safety check for collisions, we will throw up our hands and refuse to return the conn
    fn enforce_key_integrity(
        conn: ConnClient,
        expected_key: &WorkloadKey,
    ) -> Result<ConnClient, Error> {
        match conn.is_for_workload(expected_key) {
            Ok(()) => Ok(conn),
            Err(e) => Err(e),
        }
    }

    async fn start_conn_if_win_writelock(
        &self,
        workload_key: &WorkloadKey,
        pool_key: &pingora_pool::ConnectionMeta,
    ) -> Option<ConnClient> {
        let inner_conn_lock = {
            trace!("getting keyed lock out of lockmap");
            let guard = self.established_conn_writelock.guard();

            let exist_conn_lock = self
                .established_conn_writelock
                .get(&pool_key.key, &guard)
                .unwrap();
            trace!("got keyed lock out of lockmap");
            exist_conn_lock.as_ref().unwrap().clone()
        };

        trace!("attempting to win connlock for wl key {:#?}", workload_key);

        let inner_lock = inner_conn_lock.try_lock();
        match inner_lock {
            Ok(_guard) => {
                // BEGIN take inner writelock
                debug!("nothing else is creating a conn and we won the lock, make one");
                match self.spawner.new_pool_conn(workload_key.clone()).await {
                    Ok(pool_conn) => {
                        let client = ConnClient {
                            sender: pool_conn,
                            stream_count: Arc::new(AtomicU16::new(0)),
                            stream_count_max: self.max_streamcount,
                            wl_key: workload_key.clone(),
                        };

                        debug!(
                            "checking in new conn for key {:#?} with pk {:#?}",
                            workload_key, pool_key
                        );
                        self.checkin_conn(client.clone(), pool_key.clone());
                        Some(client)
                    }
                    Err(e) => {
                        error!("could not spawn new conn, got {e}");
                        None
                    }
                }
                // END take inner writelock
            }
            Err(_) => {
                debug!(
                    "did not win connlock for wl key {:#?}, something else has it",
                    workload_key
                );
                None
            }
        }
    }

    // Does an initial, naive check to see if a conn exists for this key.
    //
    // If it does, WRITELOCK the mutex for that key, clone (or create), check in the clone,
    // and return the other reference for use.
    //
    // Otherwise, return None.
    //
    // It is important that the *initial* check here is authoritative, hence the locks, as
    // we must know if this is a connection for a key *nobody* has tried to start yet,
    // or if other things have already established conns for this key.
    //
    // This is so we can backpressure correctly if 1000 tasks all demand a new connection
    // to the same key at once, and not eagerly open 1000 tunnel connections.
    async fn checkout_conn_under_writelock(
        &self,
        workload_key: &WorkloadKey,
        pool_key: &pingora_pool::ConnectionMeta,
    ) -> Result<Option<ConnClient>, Error> {
        let found_conn = {
            trace!("pool connect outer map - take guard");
            let guard = self.established_conn_writelock.guard();

            trace!("pool connect outer map - check for keyed mutex");
            let exist_conn_lock = self.established_conn_writelock.get(&pool_key.key, &guard);
            exist_conn_lock.and_then(|e_conn_lock| e_conn_lock.clone())
        };
        match found_conn {
            Some(exist_conn_lock) => {
                debug!("checkout - found mutex for key, waiting for writelock");
                let _conn_lock = exist_conn_lock.as_ref().lock().await;

                trace!(
                    "checkout - got writelock for conn with key {:#?} and hash {:#?}",
                    workload_key,
                    pool_key.key
                );
                let result = match self.guarded_get(&pool_key.key, workload_key)? {
                    Some(e_conn) => {
                        trace!("checkout - got existing conn for key {:#?}", workload_key);
                        if e_conn.at_max_streamcount() {
                            debug!("got conn for wl key {:#?}, but streamcount is maxed, spawning new conn to replace using pool key {:#?}", workload_key, pool_key);
                            let pool_conn = self.spawner.new_pool_conn(workload_key.clone()).await;
                            let r_conn = ConnClient {
                                sender: pool_conn?,
                                stream_count: Arc::new(AtomicU16::new(0)),
                                stream_count_max: self.max_streamcount,
                                wl_key: workload_key.clone(),
                            };
                            self.checkin_conn(r_conn.clone(), pool_key.clone());
                            Some(r_conn)
                        } else {
                            debug!("checking existing conn for key {:#?} back in", pool_key);
                            self.checkin_conn(e_conn.clone(), pool_key.clone());
                            Some(e_conn)
                        }
                    }
                    None => None,
                };

                Ok(result)
            }
            None => Ok(None),
        }
    }
}

// When the Arc-wrapped PoolState is finally dropped, trigger the drain,
// which will terminate all connection driver spawns, as well as cancel all outstanding eviction timeout spawns
impl Drop for PoolState {
    fn drop(&mut self) {
        debug!("poolstate dropping, stopping all connection drivers and cancelling all outstanding eviction timeout spawns");
        let _ = self.timeout_tx.send(true);
    }
}

impl WorkloadHBONEPool {
    // Creates a new pool instance, which should be owned by a single proxied workload.
    // The pool will watch the provided drain signal and drain itself when notified.
    // Callers should then be safe to drop() the pool instance.
    pub fn new(
        cfg: crate::config::Config,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        cert_manager: Arc<SecretManager>,
    ) -> WorkloadHBONEPool {
        let (timeout_tx, timeout_rx) = watch::channel(false);
        let (timeout_send, timeout_recv) = watch::channel(false);
        let max_count = cfg.pool_max_streams_per_conn;
        let pool_duration = cfg.pool_unused_release_timeout;

        let spawner = ConnSpawner {
            cfg,
            socket_factory,
            cert_manager,
            timeout_rx: timeout_recv.clone(),
        };

        // This is merely a counter to track the overall number of conns this pool spawns
        // to ensure we get unique poolkeys-per-new-conn, it is not a limit
        debug!("constructing pool with {:#?} streams per conn", max_count);

        Self {
            state: Arc::new(PoolState {
                pool_notifier: timeout_tx,
                timeout_tx: timeout_send,
                // timeout_rx: timeout_recv,
                // the number here is simply the number of unique src/dest keys
                // the pool is expected to track before the inner hashmap resizes.
                connected_pool: Arc::new(pingora_pool::ConnectionPool::new(500)),
                established_conn_writelock: flurry::HashMap::new(),
                close_pollers: futures::stream::FuturesUnordered::new(),
                pool_unused_release_timeout: pool_duration,
                pool_global_conn_count: AtomicI32::new(0),
                max_streamcount: max_count,
                spawner,
            }),
            pool_watcher: timeout_rx,
        }
    }

    // Obtain a pooled connection. Will prefer to retrieve an existing conn from the pool, but
    // if none exist, or the existing conn is maxed out on streamcount, will spawn a new one,
    // even if it is to the same dest+port.
    //
    // If many `connects` request a connection to the same dest at once, all will wait until exactly
    // one connection is created, before deciding if they should create more or just use that one.
    pub async fn connect(&mut self, workload_key: WorkloadKey) -> Result<ConnClient, Error> {
        trace!("pool connect START");
        // TODO BML this may not be collision resistant/slow. It should be resistant enough for workloads tho.
        // We are doing a deep-equals check at the end to mitigate any collisions, will see about bumping Pingora
        let mut s = DefaultHasher::new();
        workload_key.hash(&mut s);
        let hash_key = s.finish();
        let pool_key = pingora_pool::ConnectionMeta::new(
            hash_key,
            self.state
                .pool_global_conn_count
                .fetch_add(1, Ordering::SeqCst),
        );
        // First, see if we can naively just check out a connection.
        // This should be the common case, except for the first establishment of a new connection/key.
        // This will be done under outer readlock (nonexclusive)/inner keyed writelock (exclusive).
        //
        // It is important that the *initial* check here is authoritative, hence the locks, as
        // we must know if this is a connection for a key *nobody* has tried to start yet,
        // or if other things have already established conns for this key.
        //
        // This is so we can backpressure correctly if 1000 tasks all demand a new connection
        // to the same key at once, and not eagerly open 1000 tunnel connections.
        let existing_conn = self
            .state
            .checkout_conn_under_writelock(&workload_key, &pool_key)
            .await?;

        // Early return, no need to do anything else
        if existing_conn.is_some() {
            debug!("initial attempt - found existing conn, done");
            return Ok(existing_conn.unwrap());
        }

        // We couldn't get a conn. This means either nobody has tried to establish any conns for this key yet,
        // or they have, but no conns are currently available
        // (because someone else has checked all of them out and not put any back yet)
        //
        // So, we will take a nonexclusive readlock on the lockmap, to see if an inner lock
        // exists for our key.
        //
        // If not, we insert one.
        {
            debug!(
                "didn't find a connection for key {:#?}, making sure lockmap has entry",
                hash_key
            );
            let guard = self.state.established_conn_writelock.guard();
            match self.state.established_conn_writelock.try_insert(
                hash_key,
                Some(Arc::new(Mutex::new(()))),
                &guard,
            ) {
                Ok(_) => {
                    debug!("inserting conn mutex for key {:#?} into lockmap", hash_key);
                }
                Err(_) => {
                    debug!("already have conn for key {:#?} in lockmap", hash_key);
                }
            }
        }

        // If we get here, it means the following are true:
        // 1. We have a guaranteed sharded mutex in the outer map for our current key.
        // 2. We can now, under readlock(nonexclusive) in the outer map, attempt to
        // take the inner writelock for our specific key (exclusive).
        //
        // This doesn't block other tasks spawning connections against other keys, but DOES block other
        // tasks spawning connections against THIS key - which is what we want.

        // NOTE: The inner, key-specific mutex is a tokio::async::Mutex, and not a stdlib sync mutex.
        // these differ from the stdlib sync mutex in that they are (slightly) slower
        // (they effectively sleep the current task) and they can be held over an await.
        // The tokio docs (rightly) advise you to not use these,
        // because holding a lock over an await is a great way to create deadlocks if the await you
        // hold it over does not resolve.
        //
        // HOWEVER. Here we know this connection will either establish or timeout
        // and we WANT other tasks to go back to sleep if a task is already trying to create a new connection for this key.
        //
        // So the downsides are actually useful (we WANT task contention -
        // to block other parallel tasks from trying to spawn a connection for this key if we are already doing so)
        trace!("fallback attempt - trying win win connlock");
        let res = match self
            .state
            .start_conn_if_win_writelock(&workload_key, &pool_key)
            .await
        {
            Some(client) => client,
            None => {
                debug!("we didn't win the lock, something else is creating a conn, wait for it");
                // If we get here, it means the following are true:
                // 1. At one point, there was a preexisting conn in the pool for this key.
                // 2. When we checked, we got nothing for that key.
                // 3. We could not get the exclusive inner writelock to add a new one for this key.
                // 4. Someone else got the exclusive inner writelock, and is adding a new one for this key.
                //
                // So, loop and wait for the pool_watcher to tell us a new conn was enpooled,
                // so we can pull it out and check it.
                loop {
                    match self.pool_watcher.changed().await {
                        Ok(_) => {
                            trace!(
                                "notified a new conn was enpooled, checking for hash {:#?}",
                                hash_key
                            );
                            // Notifier fired, try and get a conn out for our key.
                            let existing_conn = self
                                .state
                                .checkout_conn_under_writelock(&workload_key, &pool_key)
                                .await?;
                            match existing_conn {
                                None => {
                                    trace!("woke up on pool notification, but didn't find a conn for {:#?} yet", hash_key);
                                    continue;
                                }
                                Some(e_conn) => {
                                    debug!("found existing conn after waiting");
                                    break e_conn;
                                }
                            }
                        }
                        Err(_) => {
                            return Err(Error::WorkloadHBONEPoolDraining);
                        }
                    }
                }
            }
        };
        Ok(res)
    }
}

#[derive(Debug, Clone)]
// A sort of faux-client, that represents a single checked-out 'request sender' which might
// send requests over some underlying stream using some underlying http/2 client
pub struct ConnClient {
    sender: http2::SendRequest<Empty<Bytes>>,
    stream_count: Arc<AtomicU16>, // the current streamcount for this client conn.
    stream_count_max: u16,        // the max streamcount associated with this client.
    // A WL key may have many clients, but every client has no more than one WL key
    wl_key: WorkloadKey, // the WL key associated with this client.
}

impl ConnClient {
    pub fn at_max_streamcount(&self) -> bool {
        let curr_count = self.stream_count.load(Ordering::Relaxed);
        trace!("checking streamcount: {curr_count}");
        if curr_count >= self.stream_count_max {
            return true;
        }
        false
    }

    pub fn send_request(
        &mut self,
        req: Request<Empty<Bytes>>,
    ) -> impl Future<Output = hyper::Result<Response<Incoming>>> {
        // TODO should we enforce streamcount per-sent-request? This would be slow.
        self.stream_count.fetch_add(1, Ordering::Relaxed);
        self.sender.send_request(req)
    }

    pub fn is_for_workload(&self, wl_key: &WorkloadKey) -> Result<(), crate::proxy::Error> {
        if !(self.wl_key == *wl_key) {
            Err(crate::proxy::Error::Generic(
                "fetched connection does not match workload key!".into(),
            ))
        } else {
            Ok(())
        }
    }
}

// This is currently only for debugging
impl Drop for ConnClient {
    fn drop(&mut self) {
        trace!(
            "dropping ConnClient for key {:#?} with streamcount: {:?} / {:?}",
            self.wl_key,
            self.stream_count,
            self.stream_count_max
        )
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct WorkloadKey {
    pub src_id: Identity,
    pub dst_id: Vec<Identity>,
    // In theory we can just use src,dst,node. However, the dst has a check that
    // the L3 destination IP matches the HBONE IP. This could be loosened to just assert they are the same identity maybe.
    pub dst: SocketAddr,
    // Because we spoof the source IP, we need to key on this as well. Note: for in-pod its already per-pod
    // pools anyways.
    pub src: IpAddr,
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::time::Instant;

    use crate::identity;

    use drain::Watch;
    use futures_util::StreamExt;
    use hyper::body::Incoming;

    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::task::{self};
    use tokio::time::sleep;

    #[cfg(tokio_unstable)]
    use tracing::Instrument;

    use ztunnel::test_helpers::*;

    use super::*;

    #[tokio::test]
    async fn test_pool_reuses_conn_for_same_key() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 6,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));

        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client1 = spawn_client(pool.clone(), key1.clone(), server_addr, 2).await;
        let client2 = spawn_client(pool.clone(), key1.clone(), server_addr, 2).await;
        let client3 = spawn_client(pool.clone(), key1, server_addr, 2).await;

        assert!(client1.is_ok());
        assert!(client2.is_ok());
        assert!(client3.is_ok());

        server_drain_signal.drain().await;
        drop(pool);
        server_handle.await.unwrap();
        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 1, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok());
        assert!(client3.is_ok());
    }

    #[tokio::test]
    async fn test_pool_does_not_reuse_conn_for_diff_key() {
        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        // crate::telemetry::setup_logging();

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 10,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let key2 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 3]),
            dst: server_addr,
        };

        let client1 = spawn_client(pool.clone(), key1, server_addr, 2).await;
        let client2 = spawn_client(pool.clone(), key2, server_addr, 2).await;

        server_drain_signal.drain().await;
        drop(pool);

        server_handle.await.unwrap();

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 2, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok()); // expect this to panic - we used a new key
    }

    #[tokio::test]
    async fn test_pool_respects_per_conn_stream_limit() {
        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 3,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client1 = spawn_client(pool.clone(), key1.clone(), server_addr, 4).await;
        let client2 = spawn_client(pool.clone(), key1, server_addr, 2).await;

        server_drain_signal.drain().await;
        drop(pool);

        server_handle.await.unwrap();

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 2, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok()); // expect this to panic - same key, but stream limit of 3
    }

    #[tokio::test]
    async fn test_pool_handles_many_conns_per_key() {
        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 2,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));

        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client1 = spawn_client(pool.clone(), key1.clone(), server_addr, 4).await;
        let client2 = spawn_client(pool.clone(), key1.clone(), server_addr, 4).await;

        drop(pool);
        server_drain_signal.drain().await;

        server_handle.await.unwrap();

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 2, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok());
    }

    #[tokio::test]
    async fn test_pool_100_clients_streamexhaust() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 50,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client_count = 100;
        let mut count = 0u32;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;
            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }
        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        drop(pool);
        server_drain_signal.drain().await;
        server_handle.await.unwrap();

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 4, "actual conncount was {real_conncount}");
    }

    #[tokio::test]
    async fn test_pool_100_clients_singleconn() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 1000,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client_count = 100;
        let mut count = 0u32;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;
            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }
        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        drop(pool);

        server_drain_signal.drain().await;
        server_handle.await.unwrap();

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 1, "actual conncount was {real_conncount}");
    }

    #[tokio::test]
    async fn test_pool_100_clients_100_srcs() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 100,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let client_count = 100;
        let mut count = 0u8;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;

            let key1 = WorkloadKey {
                src_id: Identity::default(),
                dst_id: vec![Identity::default()],
                src: IpAddr::from([127, 0, 0, count]),
                dst: server_addr,
            };
            // key1.src = IpAddr::from([127, 0, 0, count]);

            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }

        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        drop(pool);

        server_drain_signal.drain().await;
        server_handle.await.unwrap();

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(
            real_conncount == 100,
            "actual conncount was {real_conncount}"
        );
    }

    #[tokio::test]
    async fn test_pool_1000_clients_3_srcs() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 1000,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let mut key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 1]),
            dst: server_addr,
        };

        let client_count = 100;
        let mut count = 0u32;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;
            if count % 2 == 0 {
                debug!("using key 2");
                key1.src = IpAddr::from([127, 0, 0, 4]);
            } else if count % 3 == 0 {
                debug!("using key 3");
                key1.src = IpAddr::from([127, 0, 0, 6]);
            } else {
                debug!("using key 1");
                key1.src = IpAddr::from([127, 0, 0, 2]);
            }

            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }
        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        drop(pool);

        server_drain_signal.drain().await;
        server_handle.await.unwrap();

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 3, "actual conncount was {real_conncount}");
    }

    #[tokio::test]
    async fn test_pool_1000_clients_3_srcs_drops_after_timeout() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 1000,
            pool_unused_release_timeout: Duration::from_secs(2),
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let mut key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 1]),
            dst: server_addr,
        };

        let client_count = 100;
        let mut count = 0u32;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;
            if count % 2 == 0 {
                debug!("using key 2");
                key1.src = IpAddr::from([127, 0, 0, 4]);
            } else if count % 3 == 0 {
                debug!("using key 3");
                key1.src = IpAddr::from([127, 0, 0, 6]);
            } else {
                debug!("using key 1");
                key1.src = IpAddr::from([127, 0, 0, 2]);
            }

            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }
        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        let before_conncount = conn_counter.load(Ordering::Relaxed);
        let before_dropcount = conn_drop_counter.load(Ordering::Relaxed);
        assert!(
            before_conncount == 3,
            "actual before conncount was {before_conncount}"
        );
        assert!(
            before_dropcount == 0,
            "actual before dropcount was {before_dropcount}"
        );

        // Attempt to wait long enough for pool conns to timeout+evict
        sleep(Duration::from_secs(2)).await;

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        let real_dropcount = conn_drop_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 3, "actual conncount was {real_conncount}");
        assert!(real_dropcount == 3, "actual dropcount was {real_dropcount}");

        server_drain_signal.drain().await;
        server_handle.await.unwrap();
        drop(pool);
    }

    #[tokio::test]
    async fn test_pool_100_clients_evicts_but_does_not_close_active_conn() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let conn_drop_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (server_addr, server_handle) = spawn_server(
            server_drain,
            conn_counter.clone(),
            conn_drop_counter.clone(),
        )
        .await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 50,
            pool_unused_release_timeout: Duration::from_secs(2),
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client_count = 100;
        let mut count = 0u32;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;
            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }

        let (client_stop_signal, client_stop) = drain::channel();
        let persist_res =
            spawn_persistent_client(pool.clone(), key1.clone(), server_addr, client_stop);

        //loop thru the nonpersistent clients and wait for them to finish
        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        let before_conncount = conn_counter.load(Ordering::Relaxed);
        let before_dropcount = conn_drop_counter.load(Ordering::Relaxed);
        assert!(
            before_conncount == 4,
            "actual before conncount was {before_conncount}"
        );
        assert!(
            before_dropcount == 0,
            "actual before dropcount was {before_dropcount}"
        );

        // Attempt to wait long enough for pool conns to timeout+evict
        sleep(Duration::from_secs(2)).await;

        let real_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(real_conncount == 4, "actual conncount was {real_conncount}");
        // At this point, we should still have one conn that hasn't been dropped
        // because we haven't ended the persistent client
        let real_dropcount = conn_drop_counter.load(Ordering::Relaxed);
        assert!(real_dropcount == 3, "actual dropcount was {real_dropcount}");
        client_stop_signal.drain().await;
        assert!(persist_res.await.is_ok(), "PERSIST CLIENT ERROR");

        sleep(Duration::from_secs(2)).await;

        let after_conncount = conn_counter.load(Ordering::Relaxed);
        assert!(
            after_conncount == 4,
            "after conncount was {after_conncount}"
        );
        let after_dropcount = conn_drop_counter.load(Ordering::Relaxed);
        assert!(
            after_dropcount == 4,
            "after dropcount was {after_dropcount}"
        );
        server_drain_signal.drain().await;
        server_handle.await.unwrap();

        drop(pool);
    }

    fn spawn_client(
        mut pool: WorkloadHBONEPool,
        key: WorkloadKey,
        remote_addr: SocketAddr,
        req_count: u32,
    ) -> task::JoinHandle<()> {
        tokio::spawn(async move {
            let req = || {
                hyper::Request::builder()
                    .uri(format!("{remote_addr}"))
                    .method(hyper::Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .body(Empty::<Bytes>::new())
                    .unwrap()
            };

            let start = Instant::now();

            let mut c1 = pool
                .connect(key.clone())
                // needs tokio_unstable, but useful
                // .instrument(tracing::debug_span!("client_tid", tid=%tokio::task::id()))
                .await
                .unwrap();
            debug!(
                "client spent {}ms waiting for conn",
                start.elapsed().as_millis()
            );

            let mut count = 0u32;
            loop {
                count += 1;
                let res = c1.send_request(req()).await;

                if res.is_err() {
                    panic!("SEND ERR: {:#?} sendcount {count}", res);
                } else if res.unwrap().status() != 200 {
                    panic!("CLIENT RETURNED ERROR")
                }

                if count >= req_count {
                    debug!("CLIENT DONE");
                    break;
                }
            }
        })
    }

    fn spawn_persistent_client(
        mut pool: WorkloadHBONEPool,
        key: WorkloadKey,
        remote_addr: SocketAddr,
        stop: Watch,
    ) -> task::JoinHandle<()> {
        tokio::spawn(async move {
            let req = || {
                hyper::Request::builder()
                    .uri(format!("{remote_addr}"))
                    .method(hyper::Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .body(Empty::<Bytes>::new())
                    .unwrap()
            };

            let start = Instant::now();

            let mut c1 = pool
                .connect(key.clone())
                // needs tokio_unstable, but useful
                // .instrument(tracing::debug_span!("client_tid", tid=%tokio::task::id()))
                .await
                .unwrap();
            debug!(
                "client spent {}ms waiting for conn",
                start.elapsed().as_millis()
            );

            let mut count = 0u32;
            // send forever, once we get a conn, until someone signals us to stop
            let send_loop = async move {
                loop {
                    count += 1;
                    let res = c1.send_request(req()).await;
                    if res.is_err() {
                        panic!("SEND ERR: {:#?} sendcount {count}", res);
                    } else if res.unwrap().status() != 200 {
                        panic!("CLIENT RETURNED ERROR")
                    }
                }
            };

            tokio::select! {
                _ = send_loop => {}
                _ = stop.signaled() => {
                    debug!("GOT STOP PERSISTENT CLIENT");
                }
            };
        })
    }

    async fn spawn_server(
        stop: Watch,
        conn_count: Arc<AtomicU32>,
        conn_drop_count: Arc<AtomicU32>,
    ) -> (SocketAddr, task::JoinHandle<()>) {
        // We'll bind to 127.0.0.1:3000
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let test_cfg = test_config();
        async fn hello_world(req: Request<Incoming>) -> Result<Response<Empty<Bytes>>, Infallible> {
            debug!("hello world: received request");
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let (mut ri, mut wi) =
                            tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
                        // Signal we are the waypoint so tests can validate this
                        wi.write_all(b"waypoint\n").await.unwrap();
                        tcp::handle_stream(tcp::Mode::ReadWrite, &mut ri, &mut wi).await;
                    }
                    Err(e) => panic!("No upgrade {e}"),
                }
            });
            Ok::<_, Infallible>(Response::new(http_body_util::Empty::<Bytes>::new()))
        }

        // We create a TcpListener and bind it to 127.0.0.1:3000
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();

        let certs = crate::tls::mock::generate_test_certs(
            &Identity::default().into(),
            Duration::from_secs(0),
            Duration::from_secs(100),
        );
        let acceptor = crate::tls::mock::MockServerCertProvider::new(certs);
        let mut tls_stream = crate::hyper_util::tls_server(acceptor, listener);

        let srv_handle = tokio::spawn(async move {
            // We start a loop to continuously accept incoming connections
            // and also count them
            let movable_count = conn_count.clone();
            let movable_drop_count = conn_drop_count.clone();
            let accept = async move {
                loop {
                    let stream = tls_stream.next().await.unwrap();
                    movable_count.fetch_add(1, Ordering::Relaxed);
                    let dcount = movable_drop_count.clone();
                    debug!("bump serverconn");

                    // Spawn a tokio task to serve multiple connections concurrently
                    tokio::task::spawn(async move {
                        // Finally, we bind the incoming connection to our `hello` service
                        if let Err(err) = crate::hyper_util::http2_server()
                            .initial_stream_window_size(test_cfg.window_size)
                            .initial_connection_window_size(test_cfg.connection_window_size)
                            .max_frame_size(test_cfg.frame_size)
                            // 64KB max; default is 16MB driven from Golang's defaults
                            // Since we know we are going to recieve a bounded set of headers, more is overkill.
                            .max_header_list_size(65536)
                            .serve_connection(
                                hyper_util::rt::TokioIo::new(stream),
                                service_fn(hello_world),
                            )
                            .await
                        {
                            println!("Error serving connection: {:?}", err);
                        }
                        dcount.fetch_add(1, Ordering::Relaxed);
                    });
                }
            };
            tokio::select! {
                _ = accept => {}
                _ = stop.signaled() => {
                    debug!("GOT STOP SERVER");
                }
            };
        });

        (bound_addr, srv_handle)
    }
}
