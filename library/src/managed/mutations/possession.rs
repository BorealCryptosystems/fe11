// SPDX-License-Identifier: Apache-2.0
//! Unpublished storage for one durable destination reservation.
use super::{Destination, Reservation};
use crate::{
    registry::{Activity, WritePermit},
    symmetric::memory::Credit,
};
use std::sync::Arc;

mod generation;
mod prepaid;
mod readers;
mod storage;

pub(crate) struct PreparedRetention {
    pub(super) keys: Vec<Destination>,
    pub(super) activities: Vec<Arc<Activity>>,
    pub(super) writers: Vec<WritePermit>,
    pub(super) metadata: Credit,
}
