// HTTP operations on MessageBoxClient — implemented in Task 2.
use bsv::wallet::interfaces::WalletInterface;
use crate::client::MessageBoxClient;

impl<W: WalletInterface + Clone + 'static + Send + Sync> MessageBoxClient<W> {}
