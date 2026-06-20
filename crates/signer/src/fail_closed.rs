/// Provides the fail-closed sentinel value for boundary conditions.
///
/// When a gate or window machine encounters an unknown state, it must choose a
/// safe default.  Implementing this trait codifies PRD §6.3: unknown → denied.
pub trait FailClosedDefault {
    /// The type of the fail-closed value.
    type Out;

    /// The fail-closed value to use when a boundary condition is unknown.
    ///
    /// `where Self: Sized` keeps this static method off the vtable so the trait
    /// stays dyn-compatible (callers invoke it monomorphically, e.g.
    /// `<bool as FailClosedDefault>::default_when_unknown()`).
    fn default_when_unknown() -> Self::Out
    where
        Self: Sized;
}

impl FailClosedDefault for bool {
    type Out = bool;

    fn default_when_unknown() -> bool {
        false
    }
}
