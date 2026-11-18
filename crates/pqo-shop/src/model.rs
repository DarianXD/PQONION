//! Modelul de domeniu al magazinului.
//!
//! Fara I/O si fara HTTP: doar reguli de afacere. Stratul de deasupra le traduce
//! in coduri de stare.
//!
//! # Versionare
//!
//! Fiecare resursa modificabila are un contor de revizie. El devine `ETag`, si e
//! ce face posibile actualizarile concurente sigure: doi clienti care modifica
//! acelasi cos in acelasi timp nu se suprascriu tacit — al doilea primeste 412.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Cate articole distincte incap intr-un cos.
pub const MAX_ARTICOLE: usize = 50;
/// Cate bucati dintr-un produs se pot comanda odata.
pub const MAX_CANTITATE: u32 = 99;

/// Ce fel de jucarie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Categorie {
    /// Pistol cu bile de spuma.
    Spuma,
    /// Pistol cu apa.
    Apa,
    /// Blaster cu lumini si sunete.
    Blaster,
    /// Accesorii: tinte, munitie, tocuri.
    Accesorii,
}

impl Categorie {
    pub fn din_text(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "spuma" => Some(Categorie::Spuma),
            "apa" => Some(Categorie::Apa),
            "blaster" => Some(Categorie::Blaster),
            "accesorii" => Some(Categorie::Accesorii),
            _ => None,
        }
    }
}

/// Un produs din catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Produs {
    pub id: String,
    pub nume: String,
    pub categorie: Categorie,
    /// Pretul in bani, nu in lei.
    ///
    /// Niciodata in virgula mobila: `0.1 + 0.2 != 0.3`, iar o eroare de
    /// rotunjire intr-un total de comanda e o eroare de bani reali.
    pub pret_bani: u64,
    pub stoc: u32,
    pub descriere: String,
    /// Varsta minima recomandata de producator.
    pub varsta_minima: u8,
}

/// Un articol dintr-un cos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Articol {
    pub produs: String,
    pub cantitate: u32,
}

/// Un cos de cumparaturi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Cos {
    pub id: String,
    pub articole: Vec<Articol>,
    pub total_bani: u64,
    /// Creste la fiecare modificare. Devine `ETag`.
    #[serde(skip)]
    pub revizie: u64,
}

/// In ce stadiu e o comanda.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StareComanda {
    Plasata,
    Expediata,
    Anulata,
}

/// O comanda plasata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Comanda {
    pub id: String,
    pub articole: Vec<Articol>,
    pub total_bani: u64,
    pub stare: StareComanda,
    pub creata_la: u64,
}

/// De ce a esuat o operatie.
///
/// Enumerarea e a **domeniului**, nu a protocolului: stratul HTTP o traduce in
/// coduri de stare. Daca ar contine coduri HTTP, modelul ar deveni imposibil de
/// refolosit in alt transport si greu de testat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EroareDomeniu {
    ProdusNecunoscut(String),
    CosNecunoscut(String),
    ComandaNecunoscuta(String),
    /// Cantitatea ceruta depaseste stocul disponibil.
    StocInsuficient {
        produs: String,
        cerut: u32,
        disponibil: u32,
    },
    CantitateInvalida(u32),
    CosPlin,
    CosGol,
    /// Revizia trimisa de client nu mai e cea curenta.
    ConflictDeRevizie {
        asteptata: u64,
        actuala: u64,
    },
}

impl core::fmt::Display for EroareDomeniu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use EroareDomeniu::*;
        match self {
            ProdusNecunoscut(id) => write!(f, "produsul {id} nu exista"),
            CosNecunoscut(id) => write!(f, "cosul {id} nu exista"),
            ComandaNecunoscuta(id) => write!(f, "comanda {id} nu exista"),
            StocInsuficient {
                produs,
                cerut,
                disponibil,
            } => write!(
                f,
                "stoc insuficient pentru {produs}: cerute {cerut}, disponibile {disponibil}"
            ),
            CantitateInvalida(n) => write!(f, "cantitate invalida: {n}"),
            CosPlin => write!(f, "cosul are prea multe articole distincte"),
            CosGol => write!(f, "cosul e gol"),
            ConflictDeRevizie {
                asteptata,
                actuala,
            } => write!(
                f,
                "resursa a fost modificata: astepta revizia {asteptata}, e {actuala}"
            ),
        }
    }
}

impl std::error::Error for EroareDomeniu {}

/// Starea magazinului.
///
/// In memorie, si asta e o alegere: un magazin demonstrativ care ar scrie pe disc
/// ar lasa urme pe serverul care gazduieste serviciul ascuns. Comenzile dispar la
/// repornire, ceea ce pentru o demonstratie e o proprietate, nu o limitare.
#[derive(Debug)]
pub struct Magazin {
    produse: BTreeMap<String, Produs>,
    cosuri: BTreeMap<String, Cos>,
    comenzi: BTreeMap<String, Comanda>,
    /// Contor pentru identificatori. Nu e criptografic: identificatorii de cos si
    /// de comanda **nu sunt secrete**, sunt doar unici.
    urmator: u64,
    /// Ceas injectat, ca testele sa fie deterministe.
    acum: u64,
}

impl Default for Magazin {
    fn default() -> Self {
        Self::new()
    }
}

impl Magazin {
    pub fn new() -> Self {
        Magazin {
            produse: BTreeMap::new(),
            cosuri: BTreeMap::new(),
            comenzi: BTreeMap::new(),
            urmator: 1,
            acum: 0,
        }
    }

    /// Magazinul de demonstratie, cu catalog predefinit.
    pub fn demonstrativ() -> Self {
        let mut m = Magazin::new();
        let catalog = [
            ("p-001", "Blaster Vortex 6", Categorie::Spuma, 12_900, 40, "Sase bile de spuma, bataie 10 m.", 6),
            ("p-002", "Blaster Vortex 12", Categorie::Spuma, 21_500, 25, "Incarcator rotativ, doisprezece proiectile.", 8),
            ("p-003", "Aqua Splash Mini", Categorie::Apa, 4_500, 120, "Rezervor 250 ml, pentru cei mici.", 3),
            ("p-004", "Aqua Splash Pro", Categorie::Apa, 9_900, 60, "Rezervor 1.2 l, pompa cu doua trepte.", 6),
            ("p-005", "Nebula Blaster LED", Categorie::Blaster, 15_000, 18, "Lumini si sunete, fara proiectile.", 4),
            ("p-006", "Set 100 bile spuma", Categorie::Accesorii, 3_200, 200, "Compatibil cu seria Vortex.", 3),
            ("p-007", "Tinta pliabila", Categorie::Accesorii, 6_800, 35, "Cinci zone de punctaj, se strange in geanta.", 5),
            ("p-008", "Toc de umar", Categorie::Accesorii, 5_400, 0, "Reglabil. Momentan indisponibil.", 6),
        ];
        for (id, nume, cat, pret, stoc, desc, varsta) in catalog {
            m.produse.insert(
                id.to_string(),
                Produs {
                    id: id.to_string(),
                    nume: nume.to_string(),
                    categorie: cat,
                    pret_bani: pret,
                    stoc,
                    descriere: desc.to_string(),
                    varsta_minima: varsta,
                },
            );
        }
        m
    }

    /// Fixeaza ceasul, pentru teste.
    pub fn cu_ceas(mut self, t: u64) -> Self {
        self.acum = t;
        self
    }

    fn id_nou(&mut self, prefix: &str) -> String {
        let n = self.urmator;
        self.urmator += 1;
        format!("{prefix}-{n:06}")
    }

    // -----------------------------------------------------------------------
    // Produse
    // -----------------------------------------------------------------------

    /// Produsele, filtrate si paginate.
    ///
    /// Intoarce si numarul total, pentru ca un client are nevoie de el ca sa stie
    /// cate pagini exista. Fara el ar trebui sa ceara pagini pana primeste una
    /// goala.
    pub fn produse(
        &self,
        categorie: Option<Categorie>,
        doar_in_stoc: bool,
        offset: usize,
        limita: usize,
    ) -> (Vec<&Produs>, usize) {
        let toate: Vec<&Produs> = self
            .produse
            .values()
            .filter(|p| categorie.map_or(true, |c| p.categorie == c))
            .filter(|p| !doar_in_stoc || p.stoc > 0)
            .collect();
        let total = toate.len();
        let pagina = toate.into_iter().skip(offset).take(limita).collect();
        (pagina, total)
    }

    pub fn produs(&self, id: &str) -> Option<&Produs> {
        self.produse.get(id)
    }

    // -----------------------------------------------------------------------
    // Cosuri
    // -----------------------------------------------------------------------

    pub fn cos_nou(&mut self) -> String {
        let id = self.id_nou("cos");
        self.cosuri.insert(
            id.clone(),
            Cos {
                id: id.clone(),
                articole: Vec::new(),
                total_bani: 0,
                revizie: 1,
            },
        );
        id
    }

    pub fn cos(&self, id: &str) -> Option<&Cos> {
        self.cosuri.get(id)
    }

    /// Fixeaza cantitatea unui produs in cos.
    ///
    /// **Idempotenta** e intentionata: `PUT` cu aceeasi cantitate de doua ori are
    /// acelasi efect ca o data. De aceea nu exista „adauga inca unul" — clientul
    /// spune ce cantitate vrea, nu cu cat sa creasca. Altfel o cerere repetata
    /// dupa un timeout ar dubla comanda.
    pub fn seteaza_cantitate(
        &mut self,
        cos_id: &str,
        produs_id: &str,
        cantitate: u32,
        revizie_asteptata: Option<u64>,
    ) -> Result<&Cos, EroareDomeniu> {
        if cantitate == 0 || cantitate > MAX_CANTITATE {
            return Err(EroareDomeniu::CantitateInvalida(cantitate));
        }
        let produs = self
            .produse
            .get(produs_id)
            .ok_or_else(|| EroareDomeniu::ProdusNecunoscut(produs_id.to_string()))?
            .clone();
        if produs.stoc < cantitate {
            return Err(EroareDomeniu::StocInsuficient {
                produs: produs_id.to_string(),
                cerut: cantitate,
                disponibil: produs.stoc,
            });
        }

        let cos = self
            .cosuri
            .get_mut(cos_id)
            .ok_or_else(|| EroareDomeniu::CosNecunoscut(cos_id.to_string()))?;
        verifica_revizie(cos.revizie, revizie_asteptata)?;

        match cos.articole.iter_mut().find(|a| a.produs == produs_id) {
            Some(a) => a.cantitate = cantitate,
            None => {
                if cos.articole.len() >= MAX_ARTICOLE {
                    return Err(EroareDomeniu::CosPlin);
                }
                cos.articole.push(Articol {
                    produs: produs_id.to_string(),
                    cantitate,
                });
            }
        }
        cos.revizie += 1;
        self.recalculeaza(cos_id);
        Ok(self.cosuri.get(cos_id).expect("cosul exista"))
    }

    /// Scoate un produs din cos.
    pub fn scoate_articol(
        &mut self,
        cos_id: &str,
        produs_id: &str,
        revizie_asteptata: Option<u64>,
    ) -> Result<(), EroareDomeniu> {
        let cos = self
            .cosuri
            .get_mut(cos_id)
            .ok_or_else(|| EroareDomeniu::CosNecunoscut(cos_id.to_string()))?;
        verifica_revizie(cos.revizie, revizie_asteptata)?;

        let inainte = cos.articole.len();
        cos.articole.retain(|a| a.produs != produs_id);
        // `DELETE` e idempotent: sa stergi ceva ce nu exista nu e o eroare.
        // Revizia creste doar daca s-a schimbat ceva, altfel un client care
        // repeta cererea ar invalida ETag-ul altcuiva degeaba.
        if cos.articole.len() != inainte {
            cos.revizie += 1;
            self.recalculeaza(cos_id);
        }
        Ok(())
    }

    fn recalculeaza(&mut self, cos_id: &str) -> u64 {
        let total: u64 = self
            .cosuri
            .get(cos_id)
            .map(|c| {
                c.articole
                    .iter()
                    .map(|a| {
                        self.produse
                            .get(&a.produs)
                            .map(|p| p.pret_bani * a.cantitate as u64)
                            .unwrap_or(0)
                    })
                    .sum()
            })
            .unwrap_or(0);
        if let Some(c) = self.cosuri.get_mut(cos_id) {
            c.total_bani = total;
        }
        total
    }

    // -----------------------------------------------------------------------
    // Comenzi
    // -----------------------------------------------------------------------

    /// Transforma un cos in comanda si scade stocul.
    ///
    /// Stocul se verifica **din nou** aici, nu doar la adaugarea in cos: intre
    /// cele doua momente poate trece oricat, iar altcineva poate fi cumparat
    /// ultimele bucati. O verificare doar la adaugare ar permite vanzarea
    /// aceluiasi obiect de doua ori.
    pub fn plaseaza_comanda(&mut self, cos_id: &str) -> Result<&Comanda, EroareDomeniu> {
        let cos = self
            .cosuri
            .get(cos_id)
            .ok_or_else(|| EroareDomeniu::CosNecunoscut(cos_id.to_string()))?
            .clone();
        if cos.articole.is_empty() {
            return Err(EroareDomeniu::CosGol);
        }
        for a in &cos.articole {
            let p = self
                .produse
                .get(&a.produs)
                .ok_or_else(|| EroareDomeniu::ProdusNecunoscut(a.produs.clone()))?;
            if p.stoc < a.cantitate {
                return Err(EroareDomeniu::StocInsuficient {
                    produs: a.produs.clone(),
                    cerut: a.cantitate,
                    disponibil: p.stoc,
                });
            }
        }
        // Abia acum modificam ceva: daca vreun articol ar fi esuat, stocul ar fi
        // ramas scazut pentru cele dinainte.
        for a in &cos.articole {
            if let Some(p) = self.produse.get_mut(&a.produs) {
                p.stoc -= a.cantitate;
            }
        }

        let id = self.id_nou("cmd");
        let c = Comanda {
            id: id.clone(),
            articole: cos.articole.clone(),
            total_bani: cos.total_bani,
            stare: StareComanda::Plasata,
            creata_la: self.acum,
        };
        self.comenzi.insert(id.clone(), c);
        // Cosul dispare: a devenit comanda. Altfel un client l-ar putea trimite
        // a doua oara.
        self.cosuri.remove(cos_id);
        Ok(self.comenzi.get(&id).expect("tocmai inserata"))
    }

    pub fn comanda(&self, id: &str) -> Option<&Comanda> {
        self.comenzi.get(id)
    }

    pub fn numar_comenzi(&self) -> usize {
        self.comenzi.len()
    }
}

fn verifica_revizie(actuala: u64, asteptata: Option<u64>) -> Result<(), EroareDomeniu> {
    match asteptata {
        Some(r) if r != actuala => Err(EroareDomeniu::ConflictDeRevizie {
            asteptata: r,
            actuala,
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogul_demonstrativ_e_coerent() {
        let m = Magazin::demonstrativ();
        let (toate, total) = m.produse(None, false, 0, 100);
        assert_eq!(total, 8);
        assert_eq!(toate.len(), 8);
        // Preturile sunt in bani, deci intregi.
        assert!(toate.iter().all(|p| p.pret_bani > 0));
        // Un produs e fara stoc, ca sa putem testa cazul.
        assert_eq!(toate.iter().filter(|p| p.stoc == 0).count(), 1);
    }

    #[test]
    fn filtrarea_si_paginarea() {
        let m = Magazin::demonstrativ();
        let (acc, total) = m.produse(Some(Categorie::Accesorii), false, 0, 100);
        assert_eq!(total, 3);
        assert!(acc.iter().all(|p| p.categorie == Categorie::Accesorii));

        // Paginare: totalul ramane cel filtrat, nu cel al paginii.
        let (pagina, total) = m.produse(None, false, 2, 3);
        assert_eq!(pagina.len(), 3);
        assert_eq!(total, 8, "totalul e al colectiei, nu al paginii");

        // Dincolo de sfarsit: pagina goala, nu eroare.
        let (goala, _) = m.produse(None, false, 100, 10);
        assert!(goala.is_empty());

        // Doar ce e in stoc.
        let (in_stoc, total) = m.produse(None, true, 0, 100);
        assert_eq!(total, 7);
        assert!(in_stoc.iter().all(|p| p.stoc > 0));
    }

    #[test]
    fn cos_complet() {
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        assert_eq!(m.cos(&cos).unwrap().total_bani, 0);

        m.seteaza_cantitate(&cos, "p-001", 2, None).unwrap();
        assert_eq!(m.cos(&cos).unwrap().total_bani, 2 * 12_900);

        m.seteaza_cantitate(&cos, "p-006", 1, None).unwrap();
        assert_eq!(m.cos(&cos).unwrap().total_bani, 2 * 12_900 + 3_200);
        assert_eq!(m.cos(&cos).unwrap().articole.len(), 2);
    }

    #[test]
    fn setarea_cantitatii_e_idempotenta() {
        // Proprietatea care face `PUT` sigur la reincercare. Daca ar fi
        // „adauga", o cerere repetata dupa un timeout ar dubla comanda.
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        m.seteaza_cantitate(&cos, "p-001", 3, None).unwrap();
        let dupa_prima = m.cos(&cos).unwrap().clone();
        m.seteaza_cantitate(&cos, "p-001", 3, None).unwrap();
        let dupa_a_doua = m.cos(&cos).unwrap();
        assert_eq!(dupa_prima.articole, dupa_a_doua.articole);
        assert_eq!(dupa_prima.total_bani, dupa_a_doua.total_bani);
    }

    #[test]
    fn stergerea_e_idempotenta() {
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        m.seteaza_cantitate(&cos, "p-001", 1, None).unwrap();
        let r1 = m.cos(&cos).unwrap().revizie;

        m.scoate_articol(&cos, "p-001", None).unwrap();
        let r2 = m.cos(&cos).unwrap().revizie;
        assert!(r2 > r1);

        // A doua stergere nu e eroare si nu mai schimba revizia.
        m.scoate_articol(&cos, "p-001", None).unwrap();
        assert_eq!(m.cos(&cos).unwrap().revizie, r2);
    }

    #[test]
    fn revizia_creste_la_fiecare_modificare() {
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        let r0 = m.cos(&cos).unwrap().revizie;
        m.seteaza_cantitate(&cos, "p-001", 1, None).unwrap();
        let r1 = m.cos(&cos).unwrap().revizie;
        m.seteaza_cantitate(&cos, "p-002", 1, None).unwrap();
        let r2 = m.cos(&cos).unwrap().revizie;
        assert!(r0 < r1 && r1 < r2);
    }

    #[test]
    fn conflictul_de_revizie_e_detectat() {
        // Doi clienti modifica acelasi cos. Al doilea trebuie sa afle.
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        let r = m.cos(&cos).unwrap().revizie;

        m.seteaza_cantitate(&cos, "p-001", 1, Some(r)).unwrap();

        // Al doilea client are inca revizia veche.
        let e = m.seteaza_cantitate(&cos, "p-002", 1, Some(r)).unwrap_err();
        assert!(matches!(e, EroareDomeniu::ConflictDeRevizie { .. }));
    }

    #[test]
    fn stocul_e_verificat_la_adaugare() {
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        let e = m.seteaza_cantitate(&cos, "p-008", 1, None).unwrap_err();
        assert!(matches!(e, EroareDomeniu::StocInsuficient { .. }));
    }

    #[test]
    fn stocul_e_verificat_din_nou_la_comanda() {
        // Intre adaugarea in cos si plasarea comenzii poate trece oricat.
        // O verificare doar la adaugare ar permite vanzarea de doua ori.
        let mut m = Magazin::demonstrativ();
        let cos_a = m.cos_nou();
        let cos_b = m.cos_nou();
        // Stocul lui p-005 e 18.
        m.seteaza_cantitate(&cos_a, "p-005", 18, None).unwrap();
        m.seteaza_cantitate(&cos_b, "p-005", 18, None).unwrap();

        m.plaseaza_comanda(&cos_a).unwrap();
        let e = m.plaseaza_comanda(&cos_b).unwrap_err();
        assert!(
            matches!(e, EroareDomeniu::StocInsuficient { .. }),
            "al doilea cos nu mai are ce cumpara"
        );
    }

    #[test]
    fn comanda_esuata_nu_scade_stocul_partial() {
        // Verificarea completa se face inainte de orice modificare.
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        m.seteaza_cantitate(&cos, "p-001", 2, None).unwrap();
        m.seteaza_cantitate(&cos, "p-005", 18, None).unwrap();

        // Golim stocul lui p-005 printr-o alta comanda.
        let alt = m.cos_nou();
        m.seteaza_cantitate(&alt, "p-005", 18, None).unwrap();
        m.plaseaza_comanda(&alt).unwrap();

        let stoc_p001 = m.produs("p-001").unwrap().stoc;
        assert!(m.plaseaza_comanda(&cos).is_err());
        assert_eq!(
            m.produs("p-001").unwrap().stoc,
            stoc_p001,
            "stocul primului articol nu are voie sa scada daca al doilea esueaza"
        );
    }

    #[test]
    fn cosul_dispare_dupa_comanda() {
        // Altfel un client l-ar putea trimite de doua ori.
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        m.seteaza_cantitate(&cos, "p-003", 1, None).unwrap();
        m.plaseaza_comanda(&cos).unwrap();
        assert!(m.cos(&cos).is_none());
        assert!(matches!(
            m.plaseaza_comanda(&cos).unwrap_err(),
            EroareDomeniu::CosNecunoscut(_)
        ));
    }

    #[test]
    fn cosul_gol_nu_devine_comanda() {
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        assert_eq!(m.plaseaza_comanda(&cos).unwrap_err(), EroareDomeniu::CosGol);
    }

    #[test]
    fn comanda_pastreaza_totalul_si_scade_stocul() {
        let mut m = Magazin::demonstrativ().cu_ceas(1_700_000_000);
        let cos = m.cos_nou();
        m.seteaza_cantitate(&cos, "p-001", 2, None).unwrap();
        let stoc_inainte = m.produs("p-001").unwrap().stoc;

        let c = m.plaseaza_comanda(&cos).unwrap().clone();
        assert_eq!(c.total_bani, 2 * 12_900);
        assert_eq!(c.stare, StareComanda::Plasata);
        assert_eq!(c.creata_la, 1_700_000_000);
        assert_eq!(m.produs("p-001").unwrap().stoc, stoc_inainte - 2);
        assert_eq!(m.numar_comenzi(), 1);
    }

    #[test]
    fn cantitatile_invalide_sunt_respinse() {
        let mut m = Magazin::demonstrativ();
        let cos = m.cos_nou();
        assert!(matches!(
            m.seteaza_cantitate(&cos, "p-001", 0, None).unwrap_err(),
            EroareDomeniu::CantitateInvalida(0)
        ));
        assert!(matches!(
            m.seteaza_cantitate(&cos, "p-001", MAX_CANTITATE + 1, None)
                .unwrap_err(),
            EroareDomeniu::CantitateInvalida(_)
        ));
    }

    #[test]
    fn identificatorii_sunt_unici() {
        let mut m = Magazin::demonstrativ();
        let a = m.cos_nou();
        let b = m.cos_nou();
        assert_ne!(a, b);
    }

    #[test]
    fn categoriile_se_parseaza_insensibil_la_capitalizare() {
        assert_eq!(Categorie::din_text("SPUMA"), Some(Categorie::Spuma));
        assert_eq!(Categorie::din_text("apa"), Some(Categorie::Apa));
        assert_eq!(Categorie::din_text("aiurea"), None);
    }
}
