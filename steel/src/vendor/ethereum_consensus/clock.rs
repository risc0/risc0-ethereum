//! A consensus clock
use crate::ethereum_consensus::{
    configs, phase0 as presets,
    primitives::{Epoch, Slot},
};
use std::{
    ops::Deref,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAINNET_GENESIS_TIME: u64 = 1606824023;
pub const SEPOLIA_GENESIS_TIME: u64 = 1655733600;
pub const GOERLI_GENESIS_TIME: u64 = 1616508000;
pub const HOLESKY_GENESIS_TIME: u64 = 1695902400;

pub fn duration_since_unix_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

pub fn duration_until(unix_timestamp_secs: u64) -> Duration {
    let unix_now = duration_since_unix_epoch();
    let timestamp = Duration::from_secs(unix_timestamp_secs);
    timestamp.saturating_sub(unix_now)
}

fn slot_to_nanos(slot: Slot, seconds_per_slot: u128, genesis_time: u128) -> u128 {
    u128::from(slot) * seconds_per_slot + genesis_time
}

#[inline]
fn u128_to_u64(t: u128) -> u64 {
    u64::try_from(t).expect("close enough to `UNIX_EPOCH` to fit in type")
}

/// Converts `timestamp` with **second** precision to a `Slot`.
/// Returns `None` if `timestamp` is before the `genesis_time`.
pub fn convert_timestamp_to_slot(
    timestamp: u64,
    genesis_time: u64,
    seconds_per_slot: u64,
) -> Option<Slot> {
    let delta = timestamp.checked_sub(genesis_time)?;
    Some(delta / seconds_per_slot)
}

/// Converts `timestamp` with **nanosecond** precision to a `Slot`.
/// Returns `None` if `timestamp` is before the `genesis_time`.
pub fn convert_timestamp_nanos_to_slot(
    timestamp: u128,
    genesis_time: u128,
    seconds_per_slot: u128,
) -> Option<Slot> {
    let delta = timestamp.checked_sub(genesis_time)?;
    Some(u128_to_u64(delta / seconds_per_slot))
}

/// Convert the `slot` to the number of seconds since the `UNIX_EPOCH`.
pub fn convert_slot_to_timestamp(slot: Slot, seconds_per_slot: u128, genesis_time: u128) -> u64 {
    let slot_in_seconds = slot * Duration::from_nanos(u128_to_u64(seconds_per_slot)).as_secs();
    slot_in_seconds + Duration::from_nanos(u128_to_u64(genesis_time)).as_secs()
}

pub fn get_current_unix_time_in_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after `UNIX_EPOCH`")
        .as_nanos()
}

pub trait TimeProvider {
    // Provide the current time to **nanosecond** precision.
    fn get_current_time(&self) -> u128;
}

#[derive(Clone)]
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    fn get_current_time(&self) -> u128 {
        get_current_unix_time_in_nanos()
    }
}

#[derive(Clone)]
pub struct Clock<T: TimeProvider + Send + Sync>(Arc<Inner<T>>);

impl<T: TimeProvider + Send + Sync> Deref for Clock<T> {
    type Target = Inner<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Inner<T: TimeProvider> {
    genesis_time: u128,
    seconds_per_slot: u128,
    slots_per_epoch: Slot,
    time_provider: T,
}

pub fn from_system_time(
    genesis_time: u64,
    seconds_per_slot: u64,
    slots_per_epoch: Slot,
) -> Clock<SystemTimeProvider> {
    let time_provider = SystemTimeProvider;
    Clock::new(
        genesis_time,
        seconds_per_slot,
        slots_per_epoch,
        time_provider,
    )
}

pub fn for_mainnet() -> Clock<SystemTimeProvider> {
    let genesis_time = MAINNET_GENESIS_TIME;
    let seconds_per_slot = configs::mainnet::SECONDS_PER_SLOT;
    let slots_per_epoch = presets::mainnet::SLOTS_PER_EPOCH;
    from_system_time(genesis_time, seconds_per_slot, slots_per_epoch)
}

pub fn for_sepolia() -> Clock<SystemTimeProvider> {
    let genesis_time = SEPOLIA_GENESIS_TIME;
    let seconds_per_slot = configs::sepolia::SECONDS_PER_SLOT;
    let slots_per_epoch = presets::mainnet::SLOTS_PER_EPOCH;
    from_system_time(genesis_time, seconds_per_slot, slots_per_epoch)
}

pub fn for_goerli() -> Clock<SystemTimeProvider> {
    let genesis_time = GOERLI_GENESIS_TIME;
    let seconds_per_slot = configs::goerli::SECONDS_PER_SLOT;
    let slots_per_epoch = presets::mainnet::SLOTS_PER_EPOCH;
    from_system_time(genesis_time, seconds_per_slot, slots_per_epoch)
}

pub fn for_holesky() -> Clock<SystemTimeProvider> {
    let genesis_time = HOLESKY_GENESIS_TIME;
    let seconds_per_slot = configs::holesky::SECONDS_PER_SLOT;
    let slots_per_epoch = presets::mainnet::SLOTS_PER_EPOCH;
    from_system_time(genesis_time, seconds_per_slot, slots_per_epoch)
}

impl<T: TimeProvider + Send + Sync> Clock<T> {
    pub fn new(
        genesis_time: u64,
        seconds_per_slot: u64,
        slots_per_epoch: Slot,
        time_provider: T,
    ) -> Self {
        let genesis_time = Duration::from_secs(genesis_time).as_nanos();
        let seconds_per_slot = Duration::from_secs(seconds_per_slot).as_nanos();
        let inner = Inner {
            genesis_time,
            seconds_per_slot,
            slots_per_epoch,
            time_provider,
        };
        Self(Arc::new(inner))
    }

    fn get_current_time(&self) -> u128 {
        self.time_provider.get_current_time()
    }

    pub fn before_genesis(&self) -> bool {
        self.before_genesis_at(self.get_current_time())
    }

    #[inline]
    fn before_genesis_at(&self, current_time: u128) -> bool {
        current_time < self.genesis_time
    }

    // Return the current slot, or `None` if before genesis.
    pub fn current_slot(&self) -> Option<Slot> {
        self.slot_at_time(self.get_current_time())
    }

    #[inline]
    pub fn slot_at_time(&self, current_time: u128) -> Option<Slot> {
        convert_timestamp_nanos_to_slot(current_time, self.genesis_time, self.seconds_per_slot)
    }

    #[inline]
    pub fn timestamp_at_slot(&self, slot: Slot) -> u64 {
        convert_slot_to_timestamp(slot, self.seconds_per_slot, self.genesis_time)
    }

    // Return the current epoch, or `None` if before genesis.
    pub fn current_epoch(&self) -> Option<Epoch> {
        let current_slot = self.current_slot()?;
        Some(self.epoch_for(current_slot))
    }

    #[inline]
    pub fn epoch_for(&self, slot: Slot) -> Epoch {
        slot / self.slots_per_epoch
    }

    /// Return a `Duration` until the provided `slot` relative to the current time as determined
    /// by the clock. If `slot` is in the past, return a `Duration` of 0.
    pub fn duration_until_slot(&self, slot: Slot) -> Duration {
        let current_time = self.get_current_time();
        let target_slot_in_nanos = slot_to_nanos(slot, self.seconds_per_slot, self.genesis_time);
        target_slot_in_nanos
            .checked_sub(current_time)
            .map(|t| Duration::from_nanos(u128_to_u64(t)))
            .unwrap_or_default()
    }

    /// Return a `Duration` until the next `slot` relative to the
    /// current time as determined by the clock.
    pub fn duration_until_next_slot(&self) -> Duration {
        let current_time = self.get_current_time();
        if self.before_genesis_at(current_time) {
            Duration::from_nanos(u128_to_u64(self.genesis_time - current_time))
        } else {
            let current_slot = self.slot_at_time(current_time).expect("is after genesis");
            let next_slot = current_slot + 1;
            let target_slot_in_nanos =
                slot_to_nanos(next_slot, self.seconds_per_slot, self.genesis_time);
            // safety: `target_slot_in_seconds` >= `current_time` always
            Duration::from_nanos(u128_to_u64(target_slot_in_nanos - current_time))
        }
    }
}

pub type SystemClock = Clock<SystemTimeProvider>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Ticker {
        tick: Mutex<u128>,
        seconds_per_slot: u128,
    }

    impl Ticker {
        fn tick(&self) {
            let mut tick = self.tick.lock().unwrap();
            *tick += Duration::from_secs(1).as_nanos();
        }

        // tick until we are one before the smallest resolution until the next slot
        fn tick_until_next_slot(&self) {
            let mut tick = self.tick.lock().unwrap();
            let current_slot = *tick / self.seconds_per_slot;
            let next_slot = current_slot + 1;
            let next_tick = next_slot * self.seconds_per_slot;
            *tick = next_tick - 1;
        }
    }

    impl TimeProvider for Arc<Ticker> {
        fn get_current_time(&self) -> u128 {
            *self.tick.lock().unwrap()
        }
    }

    fn new_ticker(seconds_per_slot: u64) -> Arc<Ticker> {
        let seconds_per_slot = Duration::from_secs(seconds_per_slot).as_nanos();
        Arc::new(Ticker {
            tick: Mutex::new(0),
            seconds_per_slot,
        })
    }

    #[test]
    fn test_custom_time_provider() {
        let seconds_per_slot: u64 = 12;
        let time_provider = new_ticker(seconds_per_slot);
        let clock = Clock::new(0, seconds_per_slot, 32, time_provider.clone());
        assert_eq!(clock.duration_until_next_slot().as_secs(), 12);
        assert_eq!(clock.current_slot().unwrap(), 0);
        time_provider.tick();
        assert_eq!(clock.duration_until_next_slot().as_secs(), 11);
        assert_eq!(clock.current_slot().unwrap(), 0);
        for _ in 0..seconds_per_slot {
            time_provider.tick();
        }
        assert_eq!(clock.duration_until_next_slot().as_secs(), 11);
        let current_slot = clock.current_slot().unwrap();
        assert_eq!(current_slot, 1);
        let duration_until_previous_slot = clock.duration_until_slot(current_slot - 1);
        assert_eq!(duration_until_previous_slot, Duration::default());
        let duration_until_now = clock.duration_until_slot(current_slot);
        assert_eq!(duration_until_now, Duration::default());
        let next_slot = current_slot + 1;
        let duration_until_next_slot = clock.duration_until_slot(next_slot);
        assert_eq!(duration_until_next_slot, Duration::from_secs(11));
        assert_eq!(duration_until_next_slot, clock.duration_until_next_slot());
    }

    #[test]
    fn test_before_genesis() {
        let seconds_per_slot: u64 = 12;
        let time_provider = new_ticker(seconds_per_slot);
        let clock = Clock::new(10, seconds_per_slot, 32, time_provider.clone());
        assert_eq!(clock.duration_until_next_slot().as_secs(), 10);
        time_provider.tick();
        assert_eq!(clock.duration_until_next_slot().as_secs(), 9);

        assert!(clock.current_slot().is_none());
    }
}
