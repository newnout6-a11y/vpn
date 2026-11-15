//! Generations as the lifecycle needs them: strictly increasing per start (and per in-place
//! switch), although the numbers come from more than one counter — the service's restarts with
//! the service, and the split runtime has two hosts. Each source keeps its own order; on a change
//! of source the offset moves past everything handed out, so the next number is larger still.
use vpnte_tunnel::api::TunnelEvent;

#[derive(Debug, Default)]
pub(super) struct Gens {
    offset: u64,
    max: u64,
    switch_offset: u64,
    switch_max: u64,
}

impl Gens {
    /// Another source from now on (a new service connection, the other host).
    pub fn relink(&mut self) {
        self.offset = self.max;
        self.switch_offset = self.switch_max;
    }

    /// A start generation of the current source.
    pub fn native(&mut self, generation: u64) -> u64 {
        let out = generation + self.offset;
        self.max = self.max.max(out);
        out
    }

    fn switch(&mut self, generation: u64) -> u64 {
        let out = generation + self.switch_offset;
        self.switch_max = self.switch_max.max(out);
        out
    }

    /// The event with its generations mapped.
    pub fn event(&mut self, event: TunnelEvent) -> TunnelEvent {
        use TunnelEvent as E;
        match event {
            E::StartBegan { generation } => E::StartBegan {
                generation: self.native(generation),
            },
            E::StartFinished { generation, ok } => E::StartFinished {
                generation: self.native(generation),
                ok,
            },
            E::StopFinished {
                generation,
                preserved,
                receipt,
            } => E::StopFinished {
                generation: self.native(generation),
                preserved,
                receipt,
            },
            E::FailedOver {
                generation,
                profile_id,
                cause,
            } => E::FailedOver {
                generation: self.native(generation),
                profile_id,
                cause,
            },
            E::SwitchBegan { generation } => E::SwitchBegan {
                generation: self.switch(generation),
            },
            E::SwitchFinished {
                generation,
                verified,
            } => E::SwitchFinished {
                generation: self.switch(generation),
                verified,
            },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_keep_increasing_across_sources() {
        let mut g = Gens::default();
        assert_eq!(g.native(3), 3);
        assert_eq!(g.native(4), 4);
        g.relink();
        // The service restarted: its counter is back at 1.
        assert_eq!(g.native(1), 5);
        assert_eq!(g.native(1), 5, "the same run maps to the same number");
        g.relink();
        // Back to the other host, whose own counter went on from 4.
        assert_eq!(g.native(5), 10);
        let switched = g.event(TunnelEvent::SwitchBegan { generation: 2 });
        assert!(matches!(
            switched,
            TunnelEvent::SwitchBegan { generation: 2 }
        ));
        g.relink();
        let switched = g.event(TunnelEvent::SwitchBegan { generation: 1 });
        assert!(matches!(
            switched,
            TunnelEvent::SwitchBegan { generation: 3 }
        ));
    }
}
