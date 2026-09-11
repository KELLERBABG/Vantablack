/// Session Guard — Replay Protection
///
/// Re-exports from the L6 layer. This file exists so that the session
/// module can provide a clean API surface for session management while
/// keeping the replay guard in its own logical location.
pub use crate::ghost::layers::l6_session::SessionGuard;