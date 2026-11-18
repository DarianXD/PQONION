//! Un magazin REST demonstrativ, expus ca serviciu ascuns.
//!
//! Exista ca sa arate ca platforma transporta trafic real, nu doar octeti de
//! test. Structura urmeaza acelasi tipar ca restul proiectului:
//!
//! [`model`] — regulile de afacere, fara HTTP.
//! [`http`] — parsare si serializare, fara I/O.
//! [`api`] — semantica REST, ca functie pura `(stare, cerere) -> raspuns`.
//!
//! Serverul propriu-zis e o coaja de vreo suta de linii peste tokio. Tot ce
//! conteaza se testeaza fara socket-uri.

#![forbid(unsafe_code)]

pub mod api;
pub mod http;
pub mod model;

pub use api::trateaza;
pub use http::{Cerere, Metoda, Raspuns};
pub use model::Magazin;
