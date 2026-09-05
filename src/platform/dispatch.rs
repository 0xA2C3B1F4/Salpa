//! Trussed extension routing required by the FIDO authenticator.

use trussed::{
    Platform,
    backend::{Backend, BackendId},
    serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
    service::ServiceResources,
    types::Context,
};
use trussed_core::{
    Error,
    api::{Reply, Request, reply, request},
};
use trussed_fs_info::FsInfoExtension;
use trussed_hkdf::HkdfExtension;
use trussed_staging::{StagingBackend, StagingContext};

#[derive(Clone, Copy, Debug)]
pub enum FidoBackendId {
    Staging,
}

#[derive(Clone, Copy, Debug)]
pub enum FidoExtensionId {
    FsInfo,
    Hkdf,
}

impl From<FidoExtensionId> for u8 {
    fn from(value: FidoExtensionId) -> Self {
        match value {
            FidoExtensionId::FsInfo => 0,
            FidoExtensionId::Hkdf => 1,
        }
    }
}

impl TryFrom<u8> for FidoExtensionId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::FsInfo),
            1 => Ok(Self::Hkdf),
            _ => Err(Error::FunctionNotSupported),
        }
    }
}

#[derive(Debug, Default)]
pub struct FidoDispatch {
    staging: StagingBackend,
}

impl ExtensionId<FsInfoExtension> for FidoDispatch {
    type Id = FidoExtensionId;
    const ID: Self::Id = FidoExtensionId::FsInfo;
}

impl ExtensionId<HkdfExtension> for FidoDispatch {
    type Id = FidoExtensionId;
    const ID: Self::Id = FidoExtensionId::Hkdf;
}

impl ExtensionDispatch for FidoDispatch {
    type BackendId = FidoBackendId;
    type Context = StagingContext;
    type ExtensionId = FidoExtensionId;

    fn core_request<P: Platform>(
        &mut self,
        _backend: &Self::BackendId,
        ctx: &mut Context<Self::Context>,
        request: &Request,
        resources: &mut ServiceResources<P>,
    ) -> Result<Reply, Error> {
        self.staging
            .request(&mut ctx.core, &mut ctx.backends, request, resources)
    }

    fn extension_request<P: Platform>(
        &mut self,
        _backend: &Self::BackendId,
        extension: &Self::ExtensionId,
        ctx: &mut Context<Self::Context>,
        request: &request::SerdeExtension,
        resources: &mut ServiceResources<P>,
    ) -> Result<reply::SerdeExtension, Error> {
        match extension {
            FidoExtensionId::FsInfo => {
                <StagingBackend as ExtensionImpl<FsInfoExtension>>::extension_request_serialized(
                    &mut self.staging,
                    &mut ctx.core,
                    &mut ctx.backends,
                    request,
                    resources,
                )
            }
            FidoExtensionId::Hkdf => {
                <StagingBackend as ExtensionImpl<HkdfExtension>>::extension_request_serialized(
                    &mut self.staging,
                    &mut ctx.core,
                    &mut ctx.backends,
                    request,
                    resources,
                )
            }
        }
    }
}

pub static FIDO_BACKENDS: [BackendId<FidoBackendId>; 2] =
    [BackendId::Core, BackendId::Custom(FidoBackendId::Staging)];
