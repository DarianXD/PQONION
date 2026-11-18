//! Incadrarea celulelor peste un flux de octeti.
//!
//! # Generic peste transport
//!
//! Tot ce urmeaza lucreaza cu `AsyncRead + AsyncWrite`. Astazi transportul e
//! `TcpStream`; cand adaugam `rustls`, devine `TlsStream<TcpStream>` fara nicio
//! modificare aici. Asta e singurul motiv pentru care stratul asta e generic —
//! nu din dragoste pentru abstractii.
//!
//! # Ce apara plafonul de buffer
//!
//! Un peer poate trimite antetul unei celule variabile care declara 16 KB si
//! apoi sa taca. Fara plafon si fara timeout, fiecare conexiune ostila ar bloca
//! memorie la nesfarsit. [`MAX_BUFFER`] limiteaza cat acumulam inainte sa
//! renuntam.
//!
//! Celula fixa are 514 octeti, cea variabila cel mult `5 + 2 + 16384`. Plafonul
//! e putin peste maximul legitim, ca sa nu respingem trafic valid.

use std::io;

use pqo_wire::Cell;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Cat acumulam intr-un buffer de citire inainte sa consideram peer-ul ostil.
pub const MAX_BUFFER: usize = 32 * 1024;

/// Cat citim odata din socket.
const READ_CHUNK: usize = 8 * 1024;

/// Un flux de celule peste un transport oarecare.
pub struct CellStream<S> {
    inner: S,
    buf: Vec<u8>,
    /// Cati octeti de la inceputul lui `buf` au fost deja consumati.
    start: usize,
    /// Zona in care citim din socket inainte sa mutam in `buf`.
    ///
    /// Exista din motive de **cancel-safety**, nu de performanta. Vezi nota de
    /// la [`CellStream::read_cell`].
    scratch: Vec<u8>,
}

impl<S> core::fmt::Debug for CellStream<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CellStream({} octeti in buffer)", self.buf.len() - self.start)
    }
}

impl<S> CellStream<S> {
    pub fn new(inner: S) -> Self {
        CellStream {
            inner,
            buf: Vec::with_capacity(READ_CHUNK),
            start: 0,
            scratch: vec![0u8; READ_CHUNK],
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Compacteaza bufferul, mutand octetii neconsumati la inceput.
    ///
    /// Se face doar cand partea consumata devine semnificativa: altfel am muta
    /// memorie la fiecare celula, ceea ce ar domina costul pe calea fierbinte.
    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start > READ_CHUNK {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }
}

impl<S: AsyncRead + Unpin> CellStream<S> {
    /// Citeste urmatoarea celula.
    ///
    /// Intoarce `Ok(None)` cand peer-ul a inchis curat conexiunea la granita
    /// dintre celule. Inchiderea in mijlocul unei celule e eroare: altfel un
    /// atacator ar putea trunchia un handshake fara sa fie observat.
    ///
    /// # Cancel-safety
    ///
    /// Aceasta functie e sigura la anulare: daca viitorul e abandonat la
    /// mijloc — cum se intampla in fiecare iteratie de `tokio::select!` — starea
    /// interna ramane consistenta si niciun octet citit din socket nu se pierde.
    ///
    /// Proprietatea nu e gratuita. Prima versiune facea `buf.resize()` inainte
    /// de `await` si `buf.truncate()` dupa. Anularea intre cele doua lasa in
    /// buffer octeti de umplutura pe care nu i-a scris nimeni. `Cell::decode` ii
    /// citea ca pe o celula PADDING perfect valida de 514 octeti si inghitea
    /// date reale — dupa care fluxul se desincroniza si canalul cadea.
    ///
    /// Simptomul era „extinderea de circuit esueaza uneori". Cauza era la trei
    /// straturi distanta. De aceea citim intai intr-o zona separata si mutam in
    /// buffer abia dupa ce `await` a intors: pana atunci nu s-a modificat nimic.
    pub async fn read_cell(&mut self) -> io::Result<Option<Cell>> {
        loop {
            match Cell::decode(&self.buf[self.start..]) {
                Ok(Some((cell, n))) => {
                    self.start += n;
                    self.compact();
                    return Ok(Some(cell));
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("celula invalida: {e}"),
                    ))
                }
            }

            if self.buf.len() - self.start >= MAX_BUFFER {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "celula incompleta peste plafonul de buffer",
                ));
            }

            // Imprumuturi disjuncte pe campuri, ca sa putem citi in `scratch`
            // fara sa atingem `buf` inainte ca `await` sa intoarca.
            let CellStream {
                inner,
                buf,
                scratch,
                ..
            } = self;
            let n = inner.read(scratch).await?;
            // De aici incolo nu mai exista punct de anulare.
            buf.extend_from_slice(&scratch[..n]);

            if n == 0 {
                return if self.start == self.buf.len() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "conexiune inchisa in mijlocul unei celule",
                    ))
                };
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> CellStream<S> {
    pub async fn write_cell(&mut self, cell: &Cell) -> io::Result<()> {
        let mut out = Vec::with_capacity(cell.encoded_len());
        cell.encode(&mut out);
        self.inner.write_all(&out).await
    }

    /// Scrie mai multe celule cu un singur apel de sistem.
    pub async fn write_cells(&mut self, cells: &[Cell]) -> io::Result<()> {
        if cells.is_empty() {
            return Ok(());
        }
        let total: usize = cells.iter().map(|c| c.encoded_len()).sum();
        let mut out = Vec::with_capacity(total);
        for c in cells {
            c.encode(&mut out);
        }
        self.inner.write_all(&out).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_wire::{ChanCmd, CircId};
    use tokio::io::duplex;

    fn fixa(circ: u32, marca: u8) -> Cell {
        Cell::fixed(CircId(circ), ChanCmd::Relay, &[marca; 100]).unwrap()
    }

    fn variabila(n: usize) -> Cell {
        Cell::var(CircId(7), ChanCmd::Create2, vec![0xAB; n]).unwrap()
    }

    #[tokio::test]
    async fn roundtrip_o_celula() {
        let (a, b) = duplex(4096);
        let mut w = CellStream::new(a);
        let mut r = CellStream::new(b);

        let c = fixa(5, 0x11);
        w.write_cell(&c).await.unwrap();
        assert_eq!(r.read_cell().await.unwrap().unwrap(), c);
    }

    #[tokio::test]
    async fn celule_lipite_intr_o_singura_scriere() {
        let (a, b) = duplex(65536);
        let mut w = CellStream::new(a);
        let mut r = CellStream::new(b);

        let cells: Vec<Cell> = (0..10).map(|i| fixa(i, i as u8)).collect();
        w.write_cells(&cells).await.unwrap();
        for c in &cells {
            assert_eq!(&r.read_cell().await.unwrap().unwrap(), c);
        }
    }

    #[tokio::test]
    async fn celula_variabila_impartita_pe_bucati() {
        // Cazul care rupe implementarile naive: o celula sosita in fragmente.
        let (mut a, b) = duplex(64);
        let mut r = CellStream::new(b);

        let c = variabila(2432);
        let mut buf = Vec::new();
        c.encode(&mut buf);

        let scriitor = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for bucata in buf.chunks(37) {
                a.write_all(bucata).await.unwrap();
                tokio::task::yield_now().await;
            }
            a.flush().await.unwrap();
        });

        assert_eq!(r.read_cell().await.unwrap().unwrap(), c);
        scriitor.await.unwrap();
    }

    #[tokio::test]
    async fn amestec_de_celule_fixe_si_variabile() {
        let (a, b) = duplex(65536);
        let mut w = CellStream::new(a);
        let mut r = CellStream::new(b);

        let cells = vec![
            fixa(1, 1),
            variabila(1312),
            fixa(2, 2),
            variabila(10),
            fixa(3, 3),
        ];
        w.write_cells(&cells).await.unwrap();
        for c in &cells {
            assert_eq!(&r.read_cell().await.unwrap().unwrap(), c);
        }
    }

    #[tokio::test]
    async fn inchidere_curata_la_granita() {
        let (a, b) = duplex(4096);
        let mut w = CellStream::new(a);
        let mut r = CellStream::new(b);

        w.write_cell(&fixa(1, 1)).await.unwrap();
        drop(w);
        assert!(r.read_cell().await.unwrap().is_some());
        assert!(
            r.read_cell().await.unwrap().is_none(),
            "inchiderea la granita e normala"
        );
    }

    #[tokio::test]
    async fn trunchiere_in_mijlocul_unei_celule_e_eroare() {
        let (mut a, b) = duplex(4096);
        let mut r = CellStream::new(b);

        let c = fixa(1, 1);
        let mut buf = Vec::new();
        c.encode(&mut buf);
        tokio::io::AsyncWriteExt::write_all(&mut a, &buf[..100])
            .await
            .unwrap();
        drop(a);

        let e = r.read_cell().await.unwrap_err();
        assert_eq!(
            e.kind(),
            io::ErrorKind::UnexpectedEof,
            "trunchierea nu are voie sa treaca drept inchidere curata"
        );
    }

    #[tokio::test]
    async fn comanda_invalida_e_eroare() {
        let (mut a, b) = duplex(4096);
        let mut r = CellStream::new(b);
        let mut rau = vec![0, 0, 0, 1, 200];
        rau.extend_from_slice(&[0u8; 509]);
        tokio::io::AsyncWriteExt::write_all(&mut a, &rau)
            .await
            .unwrap();
        assert_eq!(
            r.read_cell().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn lungime_variabila_absurda_e_eroare() {
        // Antet care pretinde 65535 de octeti: `Cell::decode` respinge imediat,
        // fara sa alocam nimic.
        let (mut a, b) = duplex(4096);
        let mut r = CellStream::new(b);
        tokio::io::AsyncWriteExt::write_all(&mut a, &[0, 0, 0, 1, ChanCmd::Certs as u8, 0xFF, 0xFF])
            .await
            .unwrap();
        assert_eq!(
            r.read_cell().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn bufferul_nu_creste_nelimitat() {
        // Peer care trimite gunoi care nu formeaza niciodata o celula completa.
        // Antetul e valid (celula fixa), dar nu vin niciodata destui octeti.
        let (mut a, b) = duplex(1024);
        let mut r = CellStream::new(b);

        let scriitor = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut antet = vec![0, 0, 0, 1, ChanCmd::Certs as u8, 0x3F, 0xFF];
            antet.resize(7 + 100, 0);
            let _ = a.write_all(&antet).await;
            // Apoi tacem, dar tinem conexiunea deschisa.
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        });

        // Citirea nu se termina, dar nici nu aloca peste plafon: verificam ca
        // apelul se blocheaza in loc sa creasca memoria.
        let r = tokio::time::timeout(std::time::Duration::from_millis(100), r.read_cell()).await;
        assert!(r.is_err(), "citirea trebuie sa astepte, nu sa aloce la infinit");
        scriitor.abort();
    }

    #[tokio::test]
    async fn citirea_e_sigura_la_anulare() {
        // Regresia care a spart prima versiune a stivei de retea.
        //
        // `pump` ruleaza `read_cell` intr-un `tokio::select!`, deci viitorul e
        // anulat de fiecare data cand cealalta ramura castiga. Daca `read_cell`
        // modifica bufferul inainte de `await`, anularea lasa in el octeti pe
        // care nu i-a scris nimeni.
        //
        // Aici anulam citirea de sute de ori la mijloc si verificam ca toate
        // celulele ajung intacte si in ordine.
        let (a, b) = duplex(65536);
        let mut w = CellStream::new(a);
        let mut r = CellStream::new(b);

        let scriitor = tokio::spawn(async move {
            for i in 0..200u32 {
                w.write_cell(&fixa(i, (i % 251) as u8)).await.unwrap();
                tokio::task::yield_now().await;
            }
            drop(w);
        });

        let mut primite = 0u32;
        loop {
            // Timeout foarte scurt: anuleaza `read_cell` in mijloc, repetat.
            match tokio::time::timeout(std::time::Duration::from_nanos(1), r.read_cell()).await {
                Ok(Ok(Some(c))) => {
                    assert_eq!(
                        c.circ(),
                        CircId(primite),
                        "celula {primite} a sosit stricata sau in alta ordine"
                    );
                    primite += 1;
                }
                Ok(Ok(None)) => break,
                Ok(Err(e)) => panic!("flux corupt dupa anulare: {e}"),
                // Anulare: reluam. Nimic nu are voie sa se piarda.
                Err(_) => continue,
            }
        }
        assert_eq!(primite, 200, "s-au pierdut celule la anulare");
        scriitor.await.unwrap();
    }

    #[tokio::test]
    async fn trafic_sustinut_nu_lasa_reziduuri() {
        let (a, b) = duplex(65536);
        let mut w = CellStream::new(a);
        let mut r = CellStream::new(b);

        let scriitor = tokio::spawn(async move {
            for i in 0..500u32 {
                w.write_cell(&fixa(i, (i % 251) as u8)).await.unwrap();
            }
            w.flush().await.unwrap();
            drop(w);
        });

        for i in 0..500u32 {
            let c = r.read_cell().await.unwrap().unwrap();
            assert_eq!(c.circ(), CircId(i));
        }
        assert!(r.read_cell().await.unwrap().is_none());
        // Bufferul trebuie sa fie compactat, nu sa fi crescut cu 500 de celule.
        assert!(
            r.buf.capacity() < 100 * 1024,
            "bufferul a crescut necontrolat: {}",
            r.buf.capacity()
        );
        scriitor.await.unwrap();
    }
}
