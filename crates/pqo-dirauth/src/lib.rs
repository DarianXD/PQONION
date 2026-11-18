//! Autoritatea de director: fuziunea voturilor intr-un consens.
//!
//! # Invariantul care conteaza
//!
//! **Toate autoritatile trebuie sa produca exact aceiasi octeti** pornind de la
//! aceeasi multime de voturi. Nu "acelasi continut" — aceiasi octeti. Daca doua
//! autoritati calculeaza consensuri care difera cu un singur caracter,
//! semnaturile lor se aplica pe documente diferite si niciun client nu poate
//! atinge pragul.
//!
//! De aici decurg toate regulile de mai jos. Fiecare loc unde ar putea aparea
//! ambiguitate — egalitati la mediana, voturi contradictorii asupra unei adrese,
//! ordinea de iterare — trebuie sa aiba o regula de departajare deterministica.
//! Iterarea peste un `HashMap` e interzisa in acest modul din exact acest motiv:
//! ordinea ei depinde de o samanta aleatoare per proces.
//!
//! # Regulile de fuziune
//!
//! | Ce | Regula |
//! |---|---|
//! | Includerea unui releu | apare in cel putin `n/2 + 1` voturi |
//! | Banda | mediana valorilor votate (cea de jos la numar par), plafonata |
//! | Adresa si portul | perechea majoritara; la egalitate, cea mai mica lexicografic |
//! | Fiecare flag | setat de cel putin `m/2 + 1` din voturile care listeaza releul |
//! | `pq_full` | ca un flag |
//! | Parametri | mediana, daca cel putin `n/2 + 1` autoritati l-au votat |
//! | Valabilitate | mediana fiecarui camp |
//! | Ordine | relee dupa fingerprint, parametri dupa nume, semnaturi dupa fingerprint |
//!
//! # Ce nu face
//!
//! Nu masoara banda. Foloseste valoarea auto-raportata de releu, plafonata prin
//! [`MAX_SELF_REPORTED_BW`]. Intr-un deployment real asta e exploatabil: un releu
//! isi declara o banda uriasa, primeste trafic disproportionat si vede mai multe
//! circuite. Tor rezolva prin masurare distribuita (`sbws`). De documentat in
//! lucrare ca limitare cunoscuta, nu de ascuns.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use pqo_dirproto::netdoc::{Consensus, Fingerprint, Flags, RelayStatus, Validity, Vote, ALL_FLAGS};

/// Construieste un vot din descriptorii colectati.
///
/// Autoritatea nu masoara nimic: preia ce a declarat fiecare releu, plafoneaza
/// banda si atribuie flag-urile pe care le poate deduce. Ce **nu** poate deduce:
///
/// - `Fast` si `Stable` ar cere masuratori in timp; le acordam tuturor.
/// - `Guard` ar cere istoric de disponibilitate; il acordam tuturor.
/// - `Exit` se deduce din politica declarata in descriptor.
/// - `HSDir` ar cere sa stim daca releul chiar stocheaza; il acordam tuturor.
///
/// Consecinta, de documentat: un releu nou primeste imediat aceleasi flag-uri ca
/// unul vechi, deci un adversar poate porni multe relee si ocupa rapid o
/// fractiune mare din retea. Tor cere vechime si masuratori tocmai ca sa
/// incetineasca asta.
pub fn build_vote<S: pqo_crypto::sig::Sig>(
    authority_pk: Vec<u8>,
    validity: Validity,
    params: Vec<(String, i64)>,
    descriptors: &[String],
) -> Vote {
    let mut relays = Vec::new();
    for doc in descriptors {
        // Un descriptor care nu se verifica nu intra in vot. Verificarea se face
        // aici din nou, chiar daca a fost facuta si la primire: votul e ce
        // semnam, deci nu are voie sa contina nimic neverificat.
        let Ok(d) = pqo_dirproto::netdoc::RelayDescriptor::parse_and_verify::<S>(doc) else {
            continue;
        };
        let mut flags = Flags::default();
        for f in ["Valid", "Fast", "Stable", "Guard", "HSDir"] {
            let _ = flags.set(f);
        }
        if !d.exit_ports.is_empty() {
            let _ = flags.set("Exit");
        }
        relays.push(RelayStatus {
            fingerprint: d.fingerprint(),
            address: d.address.clone(),
            or_port: d.or_port,
            bandwidth: d.bandwidth.min(MAX_SELF_REPORTED_BW),
            flags,
            pq_full: d.onion_kem.is_some(),
        });
    }

    let mut v = Vote {
        authority: authority_pk,
        validity,
        params,
        relays,
    };
    v.canonicalize();
    v
}

/// Plafonul pentru banda auto-raportata.
///
/// Nu rezolva problema, doar limiteaza cat de mult poate minti un releu.
pub const MAX_SELF_REPORTED_BW: u64 = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Nu s-a primit niciun vot.
    NoVotes,
    /// Perioadele votate nu se pot fuziona intr-un interval coerent.
    ValidityMismatch,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthError::NoVotes => f.write_str("niciun vot"),
            AuthError::ValidityMismatch => f.write_str("voturile acopera perioade diferite"),
        }
    }
}

impl std::error::Error for AuthError {}

/// Mediana unei liste. La numar par de elemente ia elementul de **jos**.
///
/// Media aritmetica ar fi gresita din doua motive: ar putea produce o valoare pe
/// care n-a votat-o nicio autoritate, si ar fi sensibila la o singura autoritate
/// care voteaza extrem. Mediana e rezistenta pana la jumatate minus unu
/// autoritati ostile.
fn mediana(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[(v.len() - 1) / 2]
}

fn mediana_i64(mut v: Vec<i64>) -> i64 {
    v.sort_unstable();
    v[(v.len() - 1) / 2]
}

/// Valoarea majoritara dintr-o lista, cu departajare lexicografica.
///
/// Departajarea trebuie sa fie totala si deterministica: doua autoritati care
/// vad aceeasi multime de voturi, in orice ordine, aleg la fel.
fn majoritate<T: Ord + Clone>(mut v: Vec<T>) -> T {
    v.sort();
    let mut best = v[0].clone();
    let mut best_n = 0usize;
    let mut i = 0usize;
    while i < v.len() {
        let mut j = i;
        while j < v.len() && v[j] == v[i] {
            j += 1;
        }
        // Comparatie stricta: la egalitate ramane primul, deci cel mai mic.
        if j - i > best_n {
            best_n = j - i;
            best = v[i].clone();
        }
        i = j;
    }
    best
}

/// Calculeaza consensul din voturi.
///
/// Rezultatul nu contine semnaturi; fiecare autoritate isi adauga apoi propria
/// semnatura cu `Consensus::add_signature` si le schimba cu celelalte.
pub fn compute_consensus(votes: &[Vote]) -> Result<Consensus, AuthError> {
    if votes.is_empty() {
        return Err(AuthError::NoVotes);
    }
    let n = votes.len();
    let prag = n / 2 + 1;

    // --- Valabilitate ---
    let validity = Validity {
        valid_after: mediana(votes.iter().map(|v| v.validity.valid_after).collect()),
        fresh_until: mediana(votes.iter().map(|v| v.validity.fresh_until).collect()),
        valid_until: mediana(votes.iter().map(|v| v.validity.valid_until).collect()),
    };
    if !(validity.valid_after < validity.fresh_until && validity.fresh_until <= validity.valid_until)
    {
        return Err(AuthError::ValidityMismatch);
    }

    // --- Parametri ---
    // Numele se colecteaza intr-un vector sortat, nu intr-un set cu ordine de
    // iterare nedeterminista.
    let mut nume: Vec<&str> = votes
        .iter()
        .flat_map(|v| v.params.iter().map(|(k, _)| k.as_str()))
        .collect();
    nume.sort_unstable();
    nume.dedup();

    let mut params = Vec::new();
    for k in nume {
        let valori: Vec<i64> = votes
            .iter()
            .filter_map(|v| v.params.iter().find(|(name, _)| name == k).map(|(_, x)| *x))
            .collect();
        if valori.len() >= prag {
            params.push((k.to_string(), mediana_i64(valori)));
        }
    }

    // --- Relee ---
    let mut fps: Vec<Fingerprint> = votes
        .iter()
        .flat_map(|v| v.relays.iter().map(|r| r.fingerprint))
        .collect();
    fps.sort_unstable();
    fps.dedup();

    let mut relays = Vec::new();
    for fp in fps {
        let vazut: Vec<&RelayStatus> = votes
            .iter()
            .filter_map(|v| v.relays.iter().find(|r| r.fingerprint == fp))
            .collect();
        if vazut.len() < prag {
            continue;
        }
        let prag_relay = vazut.len() / 2 + 1;

        // Adresa si portul se aleg impreuna. Daca le-am alege separat, am putea
        // produce o pereche pe care n-a votat-o nimeni: adresa de la o autoritate
        // si portul de la alta.
        let adresa = majoritate(
            vazut
                .iter()
                .map(|r| (r.address.clone(), r.or_port))
                .collect::<Vec<_>>(),
        );

        let mut flags = Flags::default();
        for (i, name) in ALL_FLAGS.iter().enumerate() {
            if vazut.iter().filter(|r| r.flags.has(name)).count() >= prag_relay {
                flags.0 |= 1 << i;
            }
        }

        relays.push(RelayStatus {
            fingerprint: fp,
            address: adresa.0,
            or_port: adresa.1,
            bandwidth: mediana(vazut.iter().map(|r| r.bandwidth).collect())
                .min(MAX_SELF_REPORTED_BW),
            flags,
            pq_full: vazut.iter().filter(|r| r.pq_full).count() >= prag_relay,
        });
    }

    Ok(Consensus {
        validity,
        params,
        relays,
        signatures: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqo_crypto::sig::{Ed25519, Sig};
    use rand_core::OsRng;

    type S = Ed25519;

    fn releu(id: u8, bw: u64, flags: &[&str], pq: bool) -> RelayStatus {
        RelayStatus {
            fingerprint: [id; 32],
            address: format!("10.0.0.{id}"),
            or_port: 9001,
            bandwidth: bw,
            flags: Flags::from_names(flags.iter().copied()).unwrap(),
            pq_full: pq,
        }
    }

    fn vot(auth: u8, relee: Vec<RelayStatus>, params: Vec<(&str, i64)>) -> Vote {
        let mut v = Vote {
            authority: vec![auth; 32],
            validity: Validity {
                valid_after: 1000,
                fresh_until: 4600,
                valid_until: 11800,
            },
            params: params.into_iter().map(|(k, x)| (k.to_string(), x)).collect(),
            relays: relee,
        };
        v.canonicalize();
        v
    }

    #[test]
    fn releu_sub_prag_nu_intra() {
        let voturi = vec![
            vot(
                1,
                vec![releu(1, 100, &["Fast"], true), releu(7, 5, &[], false)],
                vec![],
            ),
            vot(2, vec![releu(1, 100, &["Fast"], true)], vec![]),
            vot(3, vec![releu(1, 100, &["Fast"], true)], vec![]),
        ];
        let c = compute_consensus(&voturi).unwrap();
        assert_eq!(c.relays.len(), 1);
        assert_eq!(c.relays[0].fingerprint, [1u8; 32]);
    }

    #[test]
    fn banda_e_mediana_nu_media() {
        // 100, 200, 100000: mediana 200, media ar fi ~33000. O singura autoritate
        // care minte nu trebuie sa poata trage rezultatul dupa ea.
        let voturi = vec![
            vot(1, vec![releu(1, 100, &[], false)], vec![]),
            vot(2, vec![releu(1, 200, &[], false)], vec![]),
            vot(3, vec![releu(1, 100_000, &[], false)], vec![]),
        ];
        assert_eq!(compute_consensus(&voturi).unwrap().relays[0].bandwidth, 200);
    }

    #[test]
    fn banda_e_plafonata() {
        let voturi: Vec<_> = (1..=3)
            .map(|i| vot(i, vec![releu(1, u64::MAX, &[], false)], vec![]))
            .collect();
        assert_eq!(
            compute_consensus(&voturi).unwrap().relays[0].bandwidth,
            MAX_SELF_REPORTED_BW
        );
    }

    #[test]
    fn flagurile_cer_majoritate() {
        let voturi = vec![
            vot(1, vec![releu(1, 100, &["Guard", "Fast"], false)], vec![]),
            vot(2, vec![releu(1, 100, &["Guard"], false)], vec![]),
            vot(3, vec![releu(1, 100, &["Guard"], false)], vec![]),
        ];
        let c = compute_consensus(&voturi).unwrap();
        assert!(c.relays[0].flags.has("Guard"), "3 din 3");
        assert!(!c.relays[0].flags.has("Fast"), "1 din 3, sub prag");
    }

    #[test]
    fn pq_full_cere_majoritate() {
        let voturi = vec![
            vot(1, vec![releu(1, 100, &[], true)], vec![]),
            vot(2, vec![releu(1, 100, &[], true)], vec![]),
            vot(3, vec![releu(1, 100, &[], false)], vec![]),
        ];
        assert!(compute_consensus(&voturi).unwrap().relays[0].pq_full);
    }

    #[test]
    fn adresa_si_portul_raman_impreuna() {
        // Doua autoritati zic 10.0.0.1:9001, una zice 10.0.0.9:8888.
        // Rezultatul nu are voie sa fie combinatia 10.0.0.1:8888.
        let mut alt = releu(1, 100, &[], false);
        alt.address = "10.0.0.9".into();
        alt.or_port = 8888;
        let voturi = vec![
            vot(1, vec![releu(1, 100, &[], false)], vec![]),
            vot(2, vec![releu(1, 100, &[], false)], vec![]),
            vot(3, vec![alt], vec![]),
        ];
        let c = compute_consensus(&voturi).unwrap();
        assert_eq!(c.relays[0].address, "10.0.0.1");
        assert_eq!(c.relays[0].or_port, 9001);
    }

    #[test]
    fn parametrii_cer_majoritate_de_autoritati() {
        let voturi = vec![
            vot(1, vec![], vec![("circwindow", 1000), ("obscur", 5)]),
            vot(2, vec![], vec![("circwindow", 1200)]),
            vot(3, vec![], vec![("circwindow", 900)]),
        ];
        let c = compute_consensus(&voturi).unwrap();
        assert_eq!(c.params, vec![("circwindow".to_string(), 1000)]);
    }

    /// Testul central al modulului: ordinea voturilor nu are voie sa conteze.
    #[test]
    fn ordinea_voturilor_nu_schimba_rezultatul() {
        let voturi = vec![
            vot(
                1,
                vec![
                    releu(3, 300, &["Guard"], true),
                    releu(1, 100, &["Fast", "Valid"], false),
                ],
                vec![("a", 1), ("b", 10)],
            ),
            vot(
                2,
                vec![
                    releu(1, 150, &["Fast"], true),
                    releu(2, 200, &["Exit"], false),
                    releu(3, 350, &["Guard", "Stable"], true),
                ],
                vec![("a", 3), ("b", 20)],
            ),
            vot(
                3,
                vec![
                    releu(2, 250, &["Exit", "Valid"], false),
                    releu(3, 320, &["Guard"], true),
                    releu(1, 120, &["Fast", "Valid"], true),
                ],
                vec![("a", 2)],
            ),
        ];

        let referinta = compute_consensus(&voturi).unwrap().body();
        for p in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let perm: Vec<Vote> = p.iter().map(|&i| voturi[i].clone()).collect();
            assert_eq!(
                compute_consensus(&perm).unwrap().body(),
                referinta,
                "permutarea {p:?} a dat alt consens"
            );
        }
    }

    #[test]
    fn iesirea_e_sortata_canonic() {
        let voturi: Vec<_> = (1..=3)
            .map(|a| {
                vot(
                    a,
                    vec![
                        releu(9, 100, &[], false),
                        releu(2, 100, &[], false),
                        releu(5, 100, &[], false),
                    ],
                    vec![("zzz", 1), ("aaa", 2)],
                )
            })
            .collect();
        let c = compute_consensus(&voturi).unwrap();
        let fps: Vec<u8> = c.relays.iter().map(|r| r.fingerprint[0]).collect();
        assert_eq!(fps, vec![2, 5, 9]);
        let nume: Vec<&str> = c.params.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(nume, vec!["aaa", "zzz"]);
    }

    #[test]
    fn o_autoritate_singura_produce_consens_valid() {
        let c = compute_consensus(&[vot(1, vec![releu(1, 100, &["Fast"], true)], vec![])]).unwrap();
        assert_eq!(c.relays.len(), 1);
    }

    #[test]
    fn fara_voturi_e_eroare() {
        assert_eq!(compute_consensus(&[]), Err(AuthError::NoVotes));
    }

    /// Ciclul complet: fiecare autoritate calculeaza consensul independent,
    /// semneaza, si se aduna semnaturile. Toate trebuie sa ajunga la acelasi corp.
    #[test]
    fn ciclu_complet_de_consens() {
        let mut rng = OsRng;
        let chei: Vec<_> = (0..5).map(|_| S::keygen(&mut rng)).collect();
        let publice: Vec<Vec<u8>> = chei.iter().map(|(_, p)| p.clone()).collect();

        let voturi: Vec<Vote> = (0..5)
            .map(|i| {
                let mut v = vot(
                    i as u8,
                    vec![
                        releu(1, 100 + i as u64 * 10, &["Guard", "Fast", "Valid"], true),
                        releu(2, 200, &["Exit", "Valid"], i % 2 == 0),
                    ],
                    vec![("circwindow", 1000)],
                );
                v.authority = publice[i].clone();
                v
            })
            .collect();

        let mut corpuri = Vec::new();
        let mut semnaturi = Vec::new();
        for (sk, pk) in chei.iter() {
            let mut c = compute_consensus(&voturi).unwrap();
            corpuri.push(c.body());
            c.add_signature::<S>(pk, sk);
            semnaturi.push(c.signatures[0].clone());
        }
        assert!(
            corpuri.windows(2).all(|w| w[0] == w[1]),
            "autoritatile au calculat consensuri diferite"
        );

        let mut finalul = compute_consensus(&voturi).unwrap();
        finalul.signatures = semnaturi;
        finalul.signatures.sort_by_key(|(fp, _)| *fp);

        let verificat = Consensus::parse_and_verify::<S>(&finalul.encode(), &publice).unwrap();
        assert_eq!(verificat.relays.len(), 2);
        assert_eq!(verificat.relays[0].bandwidth, 120, "mediana lui 100..140");
        assert!(verificat.relays[1].pq_full, "3 din 5 au votat pq");
    }

    #[test]
    fn votul_se_construieste_din_descriptori() {
        use pqo_crypto::sig::{Ed25519, Sig};
        use pqo_dirproto::netdoc::RelayDescriptor;
        use rand_core::OsRng;

        let mut rng = OsRng;
        let mut docs = Vec::new();
        for i in 0..3u8 {
            let (sk, pk) = Ed25519::keygen(&mut rng);
            let d = RelayDescriptor {
                identity: pk,
                onion_x25519: [i; 32],
                onion_kem: if i == 0 { Some(vec![i; 1184]) } else { None },
                address: format!("10.0.{i}.1"),
                or_port: 9001,
                bandwidth: 5000,
                // Doar ultimul e releu de iesire.
                exit_ports: if i == 2 { vec![80, 443] } else { Vec::new() },
                published: 1_700_000_000,
            };
            docs.push(d.sign::<Ed25519>(&sk));
        }
        // Un document stricat nu are voie sa intre in vot.
        docs.push("gunoi".into());

        let v = build_vote::<Ed25519>(
            vec![1u8; 32],
            Validity {
                valid_after: 1000,
                fresh_until: 4600,
                valid_until: 11800,
            },
            vec![],
            &docs,
        );
        assert_eq!(v.relays.len(), 3, "gunoiul trebuie ignorat");
        assert_eq!(v.relays.iter().filter(|r| r.flags.has("Exit")).count(), 1);
        assert_eq!(v.relays.iter().filter(|r| r.pq_full).count(), 1);
        assert!(v.relays.iter().all(|r| r.flags.has("Valid")));
    }

    #[test]
    fn banda_declarata_e_plafonata_in_vot() {
        use pqo_crypto::sig::{Ed25519, Sig};
        use pqo_dirproto::netdoc::RelayDescriptor;
        use rand_core::OsRng;

        let (sk, pk) = Ed25519::keygen(&mut OsRng);
        let d = RelayDescriptor {
            identity: pk,
            onion_x25519: [1; 32],
            onion_kem: None,
            address: "10.0.0.1".into(),
            or_port: 9001,
            // Un releu care minte.
            bandwidth: u64::MAX,
            exit_ports: Vec::new(),
            published: 1,
        };
        let v = build_vote::<Ed25519>(
            vec![1u8; 32],
            Validity {
                valid_after: 1,
                fresh_until: 2,
                valid_until: 3,
            },
            vec![],
            &[d.sign::<Ed25519>(&sk)],
        );
        assert_eq!(v.relays[0].bandwidth, MAX_SELF_REPORTED_BW);
    }

    #[test]
    fn mediana_ia_elementul_de_jos_la_numar_par() {
        assert_eq!(mediana(vec![10, 20]), 10);
        assert_eq!(mediana(vec![10, 20, 30]), 20);
        assert_eq!(mediana(vec![10, 20, 30, 40]), 20);
    }

    #[test]
    fn majoritatea_departajeaza_lexicografic() {
        assert_eq!(majoritate(vec!["b", "a"]), "a");
        assert_eq!(majoritate(vec!["b", "b", "a"]), "b");
    }
}
