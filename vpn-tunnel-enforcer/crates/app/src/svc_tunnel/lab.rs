//! WP-12 lab (feature `lab`; a production build has none of this): opens the lab gate from the
//! record in the data dir (`vpnte_engine::lab`, logged there) and hands the tunnel the mihomo
//! engine with a private dir for its run homes. Without the record every AmneziaWG start is
//! refused with the gap's message.
use std::path::Path;

use vpnte_tunnel::runtime::RealEngines;

/// `engines` with mihomo from `resources`, after the gate was read from `data_dir`.
pub(super) fn with_lab_engine(
    engines: RealEngines,
    data_dir: &Path,
    resources: &Path,
) -> RealEngines {
    // The outcome is logged and kept by the gate itself; the engine choice reads it from there.
    let _gate = vpnte_engine::lab::activate(data_dir);
    engines.with_mihomo(
        resources.join("mihomo.exe"),
        data_dir.join("lab").join("runs"),
    )
}
