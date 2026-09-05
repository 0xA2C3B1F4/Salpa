//! Concrete Trussed platform and synchronous syscall glue.

use trussed::{
    Platform, Service,
    backend::Dispatch,
    pipe::ServiceEndpoint,
    platform::{Syscall, UserInterface},
};

use super::{rng::HardwareRng, storage::FilesystemSet};

pub struct EspPlatform<'a, UI> {
    rng: HardwareRng,
    store: FilesystemSet<'a>,
    user_interface: UI,
}

impl<'a, UI> EspPlatform<'a, UI> {
    pub const fn new(rng: HardwareRng, store: FilesystemSet<'a>, user_interface: UI) -> Self {
        Self {
            rng,
            store,
            user_interface,
        }
    }
}

impl<'a, UI: UserInterface> Platform for EspPlatform<'a, UI> {
    type R = HardwareRng;
    type S = FilesystemSet<'a>;
    type UI = UI;

    fn rng(&mut self) -> &mut Self::R {
        &mut self.rng
    }

    fn store(&self) -> Self::S {
        self.store
    }

    fn user_interface(&mut self) -> &mut Self::UI {
        &mut self.user_interface
    }
}

pub struct InlineSyscall<'a, P, D>
where
    P: Platform,
    D: Dispatch,
{
    service: Service<P, D>,
    endpoint: ServiceEndpoint<'a, D::BackendId, D::Context>,
}

impl<'a, P, D> InlineSyscall<'a, P, D>
where
    P: Platform,
    D: Dispatch,
{
    pub const fn new(
        service: Service<P, D>,
        endpoint: ServiceEndpoint<'a, D::BackendId, D::Context>,
    ) -> Self {
        Self { service, endpoint }
    }
}

impl<P, D> Syscall for InlineSyscall<'_, P, D>
where
    P: Platform,
    D: Dispatch,
{
    fn syscall(&mut self) {
        self.service
            .process(core::slice::from_mut(&mut self.endpoint));
    }
}
