use core::mem::take;
use std::sync::Arc;

use super::{hookify, BoxedHook, HookEnv, HookRegistry, SubproofVerifier};

/// Context to run a program inside SP1.
#[derive(Clone, Default)]
pub struct SphinxContext<'a> {
    /// The registry of hooks invokable from inside SP1.
    /// `None` denotes the default list of hooks.
    pub hook_registry: Option<HookRegistry<'a>>,
    pub subproof_verifier: Option<Arc<dyn SubproofVerifier + 'a>>,
}

#[derive(Clone, Default)]
pub struct SphinxContextBuilder<'a> {
    no_default_hooks: bool,
    hook_registry_entries: Vec<(u32, BoxedHook<'a>)>,
    subproof_verifier: Option<Arc<dyn SubproofVerifier + 'a>>,
}

impl<'a> SphinxContext<'a> {
    /// Create a new context builder. See [SP1ContextBuilder] for more details.
    pub fn builder() -> SphinxContextBuilder<'a> {
        SphinxContextBuilder::new()
    }
}

impl<'a> SphinxContextBuilder<'a> {
    /// Create a new [`SP1ContextBuilder`].
    ///
    /// Prefer using [`SP1Context::builder`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Build and return the [SP1Context].
    ///
    /// Clears and resets the builder, allowing it to be reused.
    pub fn build(&mut self) -> SphinxContext<'a> {
        // If hook_registry_entries is nonempty or no_default_hooks true,
        // indicating a non-default value of hook_registry.
        let hook_registry =
            (!self.hook_registry_entries.is_empty() || self.no_default_hooks).then(|| {
                let mut table = if take(&mut self.no_default_hooks) {
                    Default::default()
                } else {
                    HookRegistry::default().table
                };
                // Allows overwriting default hooks.
                table.extend(take(&mut self.hook_registry_entries));
                HookRegistry { table }
            });
        let subproof_verifier = take(&mut self.subproof_verifier);
        SphinxContext {
            hook_registry,
            subproof_verifier,
        }
    }

    /// Add a runtime [Hook](super::Hook) into the context.
    ///
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    pub fn hook(
        &mut self,
        fd: u32,
        f: impl FnMut(HookEnv<'_, '_>, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
    ) -> &mut Self {
        self.hook_registry_entries.push((fd, hookify(f)));
        self
    }

    /// Avoid registering the default hooks in the runtime.
    ///
    /// It is not necessary to call this to override hooks --- instead, simply
    /// register a hook with the same value of `fd` by calling [`Self::hook`].
    pub fn without_default_hooks(&mut self) -> &mut Self {
        self.no_default_hooks = true;
        self
    }

    /// Add a subproof verifier.
    ///
    /// The verifier is used to sanity check `verify_sp1_proof` during runtime.
    pub fn subproof_verifier(
        &mut self,
        subproof_verifier: Arc<dyn SubproofVerifier + 'a>,
    ) -> &mut Self {
        self.subproof_verifier = Some(subproof_verifier);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::runtime::{DefaultSubproofVerifier, SphinxContext};

    #[test]
    fn defaults() {
        let SphinxContext {
            hook_registry,
            subproof_verifier,
        } = SphinxContext::builder().build();
        assert!(hook_registry.is_none());
        assert!(subproof_verifier.is_none());
    }

    #[test]
    fn without_default_hooks() {
        let SphinxContext { hook_registry, .. } =
            SphinxContext::builder().without_default_hooks().build();
        assert!(hook_registry.unwrap().table.is_empty());
    }

    #[test]
    fn with_custom_hook() {
        let SphinxContext { hook_registry, .. } =
            SphinxContext::builder().hook(30, |_, _| vec![]).build();
        assert!(hook_registry.unwrap().table.contains_key(&30));
    }

    #[test]
    fn without_default_hooks_with_custom_hook() {
        let SphinxContext { hook_registry, .. } = SphinxContext::builder()
            .without_default_hooks()
            .hook(30, |_, _| vec![])
            .build();
        assert_eq!(
            &hook_registry.unwrap().table.into_keys().collect::<Vec<_>>(),
            &[30]
        );
    }

    #[test]
    fn subproof_verifier() {
        let SphinxContext {
            subproof_verifier, ..
        } = SphinxContext::builder()
            .subproof_verifier(Arc::new(DefaultSubproofVerifier::new()))
            .build();
        assert!(subproof_verifier.is_some());
    }
}
