use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeSet {
    ranges: BTreeMap<u64, u64>,
}

impl RangeSet {
    /// Creates an empty range set.
    pub const fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }

        if let Some(mut last) = self.ranges.last_entry() {
            let last_start = *last.key();
            if start >= last_start && start <= *last.get() {
                *last.get_mut() = (*last.get()).max(end);
                return;
            }
        }

        let mut merged_start = start;
        let mut merged_end = end;
        let previous = self
            .ranges
            .range(..=start)
            .next_back()
            .map(|(&existing_start, &existing_end)| (existing_start, existing_end));
        if let Some((existing_start, existing_end)) =
            previous.filter(|(_, existing_end)| *existing_end >= start)
        {
            merged_start = existing_start;
            merged_end = merged_end.max(existing_end);
            self.ranges.remove(&existing_start);
        }

        loop {
            let next = self
                .ranges
                .range(merged_start..=merged_end)
                .next()
                .map(|(&existing_start, &existing_end)| (existing_start, existing_end));
            let Some((existing_start, existing_end)) = next else {
                break;
            };
            merged_end = merged_end.max(existing_end);
            self.ranges.remove(&existing_start);
        }
        self.ranges.insert(merged_start, merged_end);
    }

    pub fn contains(&self, value: u64) -> bool {
        self.ranges
            .range(..=value)
            .next_back()
            .is_some_and(|(_, end)| value < *end)
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (u64, u64)> + ExactSizeIterator + '_ {
        self.ranges.iter().map(|(&start, &end)| (start, end))
    }

    pub fn max(&self) -> Option<u64> {
        self.ranges
            .iter()
            .next_back()
            .and_then(|(_, end)| end.checked_sub(1))
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Removes and returns the range with the lowest start offset.
    pub fn pop_first(&mut self) -> Option<(u64, u64)> {
        self.ranges.pop_first()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the smallest value absent from the half-open interval.
    pub fn smallest_missing(&self, start: u64, end: u64) -> Option<u64> {
        if start >= end {
            return None;
        }
        let mut cursor = start;
        for (&range_start, &range_end) in self.ranges.range(..end) {
            if range_end <= cursor {
                continue;
            }
            if range_start > cursor {
                return Some(cursor);
            }
            cursor = cursor.max(range_end);
            if cursor >= end {
                return None;
            }
        }
        (cursor < end).then_some(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn merges_touching_ranges() {
        let mut set = RangeSet::default();
        set.insert(5, 10);
        set.insert(1, 5);
        set.insert(8, 12);
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![(1, 12)]);
        assert_eq!(set.max(), Some(11));
        assert!(set.contains(11));
        assert!(!set.contains(12));
    }

    #[test]
    fn finds_smallest_missing_value_in_interval() {
        let mut set = RangeSet::default();
        set.insert(2, 5);
        set.insert(7, 9);

        assert_eq!(set.smallest_missing(0, 10), Some(0));
        assert_eq!(set.smallest_missing(2, 10), Some(5));
        assert_eq!(set.smallest_missing(6, 10), Some(6));
        assert_eq!(set.smallest_missing(7, 9), None);
        assert_eq!(set.smallest_missing(10, 10), None);
    }

    proptest! {
        #[test]
        fn inserted_values_are_contained(start in 0u64..10_000, len in 1u64..1_000) {
            let mut set = RangeSet::default();
            let end = start + len;
            set.insert(start, end);
            prop_assert!(set.contains(start));
            prop_assert!(set.contains(end - 1));
            prop_assert!(!set.contains(end));
        }
    }
}
