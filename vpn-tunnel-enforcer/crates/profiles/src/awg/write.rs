//! The parameters of an [`Awg`] in file order, for the `.conf` and mihomo YAML exporters.
use super::field::AwgField;
use crate::model::{Awg, AwgRange};

/// One parameter value as the formats write it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AwgValue<'a> {
    Number(u32),
    Range(AwgRange),
    /// A tag chain or the header protection key, verbatim.
    Text(&'a str),
    Switch(bool),
}

/// Every parameter `awg` sets, in [`AwgField`] order. `PersistentKeepalive` is not among them:
/// it belongs to the peers.
pub(crate) fn pairs(awg: &Awg) -> Vec<(AwgField, AwgValue<'_>)> {
    use AwgValue::{Number, Range, Switch, Text};
    let junk = [
        (AwgField::Jc, awg.jc),
        (AwgField::Jmin, awg.jmin),
        (AwgField::Jmax, awg.jmax),
    ];
    let numbers = junk.into_iter().chain(AwgField::S.into_iter().zip(awg.s));
    let mut out: Vec<_> = numbers.filter_map(|(f, v)| Some((f, Number(v?)))).collect();
    out.extend(ranges(&AwgField::H, &awg.h));
    out.extend(texts(&AwgField::I, &awg.i));
    out.extend(texts(&AwgField::J, &awg.j));
    out.extend(awg.itime.map(|v| (AwgField::Itime, Number(v))));
    let key = awg.header_protection_key.as_deref();
    out.extend(key.map(|k| (AwgField::HeaderProtectionKey, Text(k))));
    let padding = awg.content_padding;
    out.extend(padding.map(|p| (AwgField::ContentPaddingAddition, Range(p))));
    out.extend(ranges(&AwgField::TIMERS, &awg.timers));
    out.extend(
        awg.random_trailers
            .map(|on| (AwgField::RandomTrailers, Switch(on))),
    );
    out.extend(
        awg.disable_cookies
            .map(|on| (AwgField::DisableCookies, Switch(on))),
    );
    out
}

fn ranges<'a>(
    fields: &'a [AwgField],
    values: &'a [Option<AwgRange>],
) -> impl Iterator<Item = (AwgField, AwgValue<'a>)> + 'a {
    let set = fields.iter().zip(values);
    set.filter_map(|(&f, v)| v.map(|v| (f, AwgValue::Range(v))))
}

fn texts<'a>(
    fields: &'a [AwgField],
    values: &'a [Option<String>],
) -> impl Iterator<Item = (AwgField, AwgValue<'a>)> + 'a {
    let set = fields.iter().zip(values);
    set.filter_map(|(&f, v)| v.as_deref().map(|v| (f, AwgValue::Text(v))))
}
