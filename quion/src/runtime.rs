//! Runtime scheduling boundary used by endpoint drivers.

use std::{future::Future, pin::Pin, time::Duration};

use crate::ConnectionError;

/// Boxed runtime future.
pub type RuntimeFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Minimal scheduling operations required by a QUIC runtime driver.
///
/// UDP readiness remains owned by the endpoint driver, while this trait keeps
/// task spawning, timer waits, and cooperative yielding independent from
/// protocol state. A future `runtime-smol` implementation can implement this
/// boundary without changing the sans-I/O core or public stream futures.
pub trait Runtime: Send + Sync + 'static {
    /// Spawns a detached driver task.
    fn spawn(&self, future: RuntimeFuture<'static>) -> Result<(), ConnectionError>;

    /// Returns a future that completes after `duration`.
    fn sleep(&self, duration: Duration) -> RuntimeFuture<'_>;

    /// Returns a cooperative scheduler yield.
    fn yield_now(&self) -> RuntimeFuture<'_>;
}

/// Tokio implementation of the runtime scheduling boundary.
#[cfg(feature = "runtime-tokio")]
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioRuntime;

#[cfg(feature = "runtime-tokio")]
impl Runtime for TokioRuntime {
    fn spawn(&self, future: RuntimeFuture<'static>) -> Result<(), ConnectionError> {
        tokio::runtime::Handle::try_current()
            .map_err(|error| ConnectionError::Runtime(error.to_string()))?
            .spawn(future);
        Ok(())
    }

    fn sleep(&self, duration: Duration) -> RuntimeFuture<'_> {
        Box::pin(tokio::time::sleep(duration))
    }

    fn yield_now(&self) -> RuntimeFuture<'_> {
        Box::pin(tokio::task::yield_now())
    }
}

#[cfg(all(test, feature = "runtime-tokio"))]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn tokio_runtime_spawns_sleeps_and_yields() {
        let runtime = TokioRuntime;
        let completed = Arc::new(AtomicBool::new(false));
        let task_completed = completed.clone();
        runtime
            .spawn(Box::pin(async move {
                task_completed.store(true, Ordering::Release);
            }))
            .unwrap();
        runtime.yield_now().await;
        assert!(completed.load(Ordering::Acquire));
        runtime.sleep(Duration::ZERO).await;
    }
}
