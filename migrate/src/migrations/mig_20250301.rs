use fiber::{store::migration::Migration, Error};
use indicatif::ProgressBar;
use rocksdb::ops::Iterate;
use rocksdb::ops::Put;
use rocksdb::DB;
use std::sync::Arc;
use tracing::info;

const MIGRATION_DB_VERSION: &str = "20250301103033";

pub use fiber_v031::fiber::channel::{
    RevocationData as RevocationDataV031, SettlementData as SettlementDataV031,
};
pub use fiber_v031::watchtower::ChannelData as ChannelDataV031;

use crate::util::convert;
pub use fiber::invoice::Attribute as AttributeV041;
pub use fiber::invoice::CkbInvoice as CkbInvoiceV041;
pub use fiber::invoice::InvoiceData as InvoiceDataV041;

pub use fiber_v040::invoice::Attribute as AttributeV040;
pub use fiber_v040::invoice::CkbInvoice as CkbInvoiceV040;

fn convert_attr(old_attr: &AttributeV040) -> AttributeV041 {
    match old_attr {
        AttributeV040::FinalHtlcTimeout(v) => AttributeV041::FinalHtlcTimeout(*v),
        AttributeV040::FinalHtlcMinimumExpiryDelta(v) => {
            AttributeV041::FinalHtlcMinimumExpiryDelta(*v)
        }
        AttributeV040::ExpiryTime(v) => AttributeV041::ExpiryTime(*v),
        AttributeV040::Description(v) => AttributeV041::Description(v.clone()),
        AttributeV040::FallbackAddr(v) => AttributeV041::FallbackAddr(v.clone()),
        AttributeV040::UdtScript(v) => AttributeV041::UdtScript(convert(v)),
        AttributeV040::PayeePublicKey(v) => AttributeV041::PayeePublicKey(convert(v)),
        AttributeV040::HashAlgorithm(v) => AttributeV041::HashAlgorithm(convert(v)),
        AttributeV040::Feature(v) => AttributeV041::Feature(*v),
    }
}

fn convert_invoice(old_invoice: &CkbInvoiceV040) -> CkbInvoiceV041 {
    let new_invoice = CkbInvoiceV041 {
        currency: convert(old_invoice.currency),
        amount: old_invoice.amount,
        signature: convert(old_invoice.signature.clone()),
        data: InvoiceDataV041 {
            timestamp: old_invoice.data.timestamp,
            payment_hash: convert(old_invoice.data.payment_hash),
            attrs: old_invoice
                .data
                .attrs
                .iter()
                .map(|attr| convert_attr(attr))
                .collect(),
        },
    };
    new_invoice
}

pub struct MigrationObj {
    version: String,
}

impl MigrationObj {
    pub fn new() -> Self {
        Self {
            version: MIGRATION_DB_VERSION.to_string(),
        }
    }
}

impl Migration for MigrationObj {
    fn migrate(
        &self,
        db: Arc<DB>,
        _pb: Arc<dyn Fn(u64) -> ProgressBar + Send + Sync>,
    ) -> Result<Arc<DB>, Error> {
        info!(
            "MigrationObj::migrate to {} ...........",
            MIGRATION_DB_VERSION
        );

        const CKB_INVOICE_PREFIX: u8 = 32;
        let prefix = vec![CKB_INVOICE_PREFIX];

        for (k, v) in db
            .prefix_iterator(prefix.as_slice())
            .take_while(move |(col_key, _)| col_key.starts_with(prefix.as_slice()))
        {
            let old_invoice: CkbInvoiceV040 =
                bincode::deserialize(&v).expect("deserialize to old channel data");

            eprintln!("old_invoice: {:?}", old_invoice.payment_hash());
            old_invoice.check_signature().unwrap();
            eprintln!("old_attrs: {:?}", old_invoice.data.attrs);

            let new_invoice = convert_invoice(&old_invoice);
            eprintln!("new_invoice: {:?}", new_invoice.payment_hash());

            let new_invoice_bytes =
                bincode::serialize(&new_invoice).expect("serialize to new invoice");

            db.put(k, new_invoice_bytes).expect("save new invoice");
        }
        Ok(db)
    }

    fn version(&self) -> &str {
        &self.version
    }
}
