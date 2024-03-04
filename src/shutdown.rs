use tokio::sync::{mpsc, watch};

#[derive(Debug)]
pub struct Sender {
    notify: watch::Sender<()>,
    process_tx: mpsc::Sender<()>,
    process_rx: mpsc::Receiver<()>,
}

impl Sender {
    pub fn new() -> Self {
        let (notify, _) = watch::channel(());
        let (process_tx, process_rx) = mpsc::channel(1);

        Self {
            notify,
            process_tx,
            process_rx,
        }
    }

    pub fn subscribe(&self) -> Receiver {
        Receiver {
            notify: self.notify.subscribe(),
            _handle: self.process_tx.clone(),
        }
    }

    pub async fn shutdown(mut self) {
        let _ = self.notify.send(());

        drop(self.process_tx);
        let _ = self.process_rx.recv().await;
    }
}

impl Default for Sender {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct Receiver {
    notify: watch::Receiver<()>,
    _handle: mpsc::Sender<()>,
}

impl Receiver {
    pub async fn recv(&mut self) {
        let _ = self.notify.changed().await;
    }
}
