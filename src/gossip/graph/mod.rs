// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod ancestors;
mod event_index;
mod event_ref;

#[cfg(any(all(test, feature = "mock"), feature = "testing"))]
pub(crate) use self::ancestors::Ancestors;
pub(crate) use self::{event_index::EventIndex, event_ref::IndexedEventRef};

use super::{event::Event, event_hash::EventHash};
use crate::id::PublicId;
#[cfg(feature = "malice-detection")]
use fnv::FnvHashSet;
use std::collections::btree_map::{BTreeMap, Entry};
#[cfg(any(all(test, feature = "mock"), feature = "testing"))]
use std::collections::BTreeSet;

/// The gossip graph.
#[derive(Eq, PartialEq, Debug)]
pub(crate) struct Graph<P: PublicId> {
    events: Vec<Event<P>>,
    indices: BTreeMap<EventHash, EventIndex>,
    /// Indices of `Requesting` events with no associated descendant `Request`, and `Request`s with
    /// no associated descendant `Response`.
    #[cfg(feature = "malice-detection")]
    awaiting_associated_events: FnvHashSet<EventIndex>,
}

impl<P: PublicId> Default for Graph<P> {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            indices: BTreeMap::new(),
            #[cfg(feature = "malice-detection")]
            awaiting_associated_events: FnvHashSet::default(),
        }
    }
}

impl<P: PublicId> Graph<P> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get index of an event with the given hash.
    pub fn get_index(&self, hash: &EventHash) -> Option<EventIndex> {
        self.indices.get(hash).cloned()
    }

    /// Checks whether this graph contains an event with the given hash.
    pub fn contains(&self, hash: &EventHash) -> bool {
        self.indices.contains_key(hash)
    }

    /// Insert new event into the graph.
    ///
    /// Returns `IndexedEventRef` to the newly inserted event.
    /// If the event was already present in the graph, does not overwrite it, just returns an
    /// `IndexedEventRef` to it.
    ///
    /// If the event is a `Requesting` or `Request`, it is also added to
    /// `awaiting_associated_events`.
    ///
    /// If the event is a `Request` or `Response`, the other_parent is removed from
    /// `awaiting_associated_events`.
    pub fn insert(&mut self, event: Event<P>) -> IndexedEventRef<P> {
        let index = match self.indices.entry(*event.hash()) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let index = EventIndex(self.events.len());

                #[cfg(any(test, feature = "testing"))]
                assert_ne!(index, EventIndex::PHONY);

                self.events.push(event);
                let _ = entry.insert(index);

                #[cfg(feature = "malice-detection")]
                self.update_awaiting(index);

                index
            }
        };

        IndexedEventRef {
            index,
            event: &self.events[index.0],
        }
    }

    /// Gets `Event` with the given `index`, if it exists.
    pub fn get(&self, index: EventIndex) -> Option<IndexedEventRef<P>> {
        self.events
            .get(index.0)
            .map(|event| IndexedEventRef { index, event })
    }

    /// Gets `Event` by the given `hash`, if it exists.
    #[cfg(any(feature = "malice-detection", feature = "dump-graphs"))]
    pub fn get_by_hash<'a>(&'a self, hash: &EventHash) -> Option<IndexedEventRef<'a, P>> {
        self.get_index(hash).and_then(|index| self.get(index))
    }

    /// Number of events in this graph.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Iterator over all events in this graph. Yields `IndexedEventRef`s.
    pub fn iter(&self) -> Iter<P> {
        self.iter_from(0)
    }

    /// Iterator over events in this graph starting at the given topological index.
    pub fn iter_from(&self, start_index: usize) -> Iter<P> {
        Iter {
            events: &self.events,
            index: start_index,
        }
    }

    /// Iterator over event indices starting at the given topological index.
    pub fn indices_from(&self, start_index: usize) -> impl Iterator<Item = EventIndex> {
        (start_index..self.events.len()).map(EventIndex)
    }

    /// Returns self-parent of the given event, if any.
    #[cfg(feature = "malice-detection")]
    pub fn self_parent<E: AsRef<Event<P>>>(&self, event: E) -> Option<IndexedEventRef<P>> {
        event
            .as_ref()
            .self_parent()
            .and_then(|index| self.get(index))
    }

    /// Returns other-parent of the given event, if any.
    #[cfg(feature = "malice-detection")]
    pub fn other_parent<E: AsRef<Event<P>>>(&self, event: E) -> Option<IndexedEventRef<P>> {
        event
            .as_ref()
            .other_parent()
            .and_then(|index| self.get(index))
    }

    /// Returns the first self-parent of the given event, that is a sync_event.
    pub fn self_sync_parent<E: AsRef<Event<P>>>(&self, event: E) -> Option<IndexedEventRef<P>> {
        let mut event = event.as_ref();
        while let Some(parent) = event.self_parent().and_then(|index| self.get(index)) {
            if parent.is_sync_event() {
                return Some(parent);
            }
            event = parent.inner();
        }
        None
    }

    /// Returns `event` if it's a sync event, or else `self_sync_parent()` of it otherwise.
    #[cfg(feature = "malice-detection")]
    pub fn self_sync_ancestor<'a>(
        &'a self,
        event: IndexedEventRef<'a, P>,
    ) -> Option<IndexedEventRef<'a, P>> {
        if event.is_sync_event() {
            Some(event)
        } else {
            self.self_sync_parent(event)
        }
    }

    /// Iterator over all ancestors of the given event (including itself) in reverse topological
    /// order.
    #[cfg(any(all(test, feature = "mock"), feature = "testing"))]
    pub fn ancestors<'a>(&'a self, event: IndexedEventRef<'a, P>) -> Ancestors<'a, P> {
        let mut queue = BTreeSet::new();
        let _ = queue.insert(event);

        Ancestors {
            graph: self,
            queue,
            visited: vec![false; event.topological_index() + 1],
        }
    }
}

#[cfg(feature = "malice-detection")]
impl<P: PublicId> Graph<P> {
    /// Returns true if the event specified by `index` should eventually but still doesn't have an
    /// associated `Request` or `Response` added to the graph.
    pub fn is_awaiting_associated_event(&self, event: IndexedEventRef<P>) -> bool {
        self.awaiting_associated_events.contains(&event.index)
    }

    /// Returns `Some(true)` if the event is a `Request` or `Response` and is valid (follows the
    /// `Requesting -> Request -> Response` pattern).  Returns `Some(false)` if the event is a
    /// `Request` or `Response` and is invalid.  Otherwise returns `None`.
    pub fn is_valid_sync_event(&self, event: &Event<P>) -> Option<bool> {
        if event.is_request() {
            Some(
                self.other_parent(event)
                    .map(|requesting_event| {
                        Some(event.creator()) == requesting_event.requesting_recipient()
                            && self.is_awaiting_associated_event(requesting_event)
                    })
                    .unwrap_or(false),
            )
        } else if event.is_response() {
            Some(
                self.other_parent(event)
                    .and_then(|other_parent| self.self_sync_ancestor(other_parent))
                    .and_then(|request_event| {
                        self.other_parent(request_event)
                            .map(|requesting_event| (request_event, requesting_event))
                    })
                    .map(|(request_event, requesting_event)| {
                        request_event.is_request()
                            && requesting_event.creator() == event.creator()
                            && self.is_awaiting_associated_event(request_event)
                    })
                    .unwrap_or(false),
            )
        } else {
            None
        }
    }

    fn awaiting_and_awaited_indices(
        &self,
        index: EventIndex,
    ) -> (Option<EventIndex>, Option<EventIndex>) {
        let event = &self.events[index.0];
        if event.is_requesting() {
            (Some(index), None)
        } else if event.is_request() {
            (
                Some(index),
                self.other_parent(event)
                    .map(|other_parent| other_parent.index),
            )
        } else if event.is_response() {
            (
                None,
                self.other_parent(event)
                    .and_then(|other_parent| self.self_sync_ancestor(other_parent))
                    .map(|self_sync_ancestor| self_sync_ancestor.index),
            )
        } else {
            (None, None)
        }
    }

    fn update_awaiting(&mut self, index: EventIndex) {
        let (awaiting, awaited) = self.awaiting_and_awaited_indices(index);
        let _ = awaiting.map(|awaiting| self.awaiting_associated_events.insert(awaiting));
        let _ = awaited.map(|awaited| self.awaiting_associated_events.remove(&awaited));
    }
}

#[cfg(any(all(test, feature = "mock"), feature = "testing"))]
impl<P: PublicId> Graph<P> {
    /// Remove the topologically last event.
    #[cfg(test)]
    pub fn remove_last(&mut self) -> Option<(EventIndex, Event<P>)> {
        let index = EventIndex(self.events.len() - 1);
        #[cfg(feature = "malice-detection")]
        {
            let (awaiting, awaited) = self.awaiting_and_awaited_indices(index);
            let _ = awaiting.map(|awaiting| self.awaiting_associated_events.remove(&awaiting));
            let _ = awaited.map(|awaited| self.awaiting_associated_events.insert(awaited));
        }
        let event = self.events.pop()?;
        let _ = self.indices.remove(event.hash());
        Some((index, event))
    }
}

#[cfg(all(test, feature = "mock"))]
impl<P: PublicId> Graph<P> {
    /// Finds the first event which has the `short_name` provided.
    pub fn find_by_short_name<'a>(&'a self, short_name: &str) -> Option<IndexedEventRef<'a, P>> {
        let short_name = short_name.to_uppercase();

        if let Some(sep) = short_name.find(',') {
            let just_short_name = &short_name[0..sep];
            let fork_index: usize = unwrap!(short_name[(sep + 1)..].parse());

            self.iter().find(|event| {
                event.short_name().to_string() == just_short_name
                    && event
                        .fork_set()
                        .map(|set| set.contains(fork_index))
                        .unwrap_or(fork_index == 0)
            })
        } else {
            self.iter()
                .find(move |event| event.short_name().to_string() == short_name)
        }
    }
}

impl<P: PublicId> IntoIterator for Graph<P> {
    type IntoIter = IntoIter<P>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        let mut events = self.events;
        events.reverse();

        IntoIter { events, index: 0 }
    }
}

pub(crate) struct IntoIter<P: PublicId> {
    events: Vec<Event<P>>,
    index: usize,
}

impl<P: PublicId> Iterator for IntoIter<P> {
    type Item = (EventIndex, Event<P>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(event) = self.events.pop() {
            let item = (EventIndex(self.index), event);
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }
}

impl<'a, P: PublicId> IntoIterator for &'a Graph<P> {
    type IntoIter = Iter<'a, P>;
    type Item = <Self::IntoIter as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        Iter {
            events: &self.events,
            index: 0,
        }
    }
}

pub(crate) struct Iter<'a, P: PublicId + 'a> {
    events: &'a [Event<P>],
    index: usize,
}

impl<'a, P: PublicId> Iterator for Iter<'a, P> {
    type Item = IndexedEventRef<'a, P>;

    fn next(&mut self) -> Option<Self::Item> {
        let event = self.events.get(self.index)?;
        let item = IndexedEventRef {
            index: EventIndex(self.index),
            event,
        };
        self.index += 1;
        Some(item)
    }
}

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) mod snapshot {
    use super::*;
    use std::collections::BTreeSet;

    /// Snapshot of the graph. Two snapshots compare as equal if the graphs had the same events
    /// modulo their insertion order.
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct GraphSnapshot(pub BTreeSet<EventHash>);

    impl GraphSnapshot {
        pub fn new<P: PublicId>(graph: &Graph<P>) -> Self {
            Self::new_with_ignore(graph, 0)
        }

        /// Generate a snapshot without the last `ignore_last_events` events
        pub fn new_with_ignore<P: PublicId>(graph: &Graph<P>, ignore_last_events: usize) -> Self {
            GraphSnapshot(
                graph
                    .iter()
                    .map(|event| *event.hash())
                    .take(graph.len() - ignore_last_events)
                    .collect(),
            )
        }
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use crate::dev_utils::parse_test_dot_file;
    use std::cmp::Reverse;

    #[test]
    fn ancestors_iterator() {
        // Generated with RNG seed: [174994228, 1445633118, 3041276290, 90293447].
        let contents = parse_test_dot_file("carol.dot");
        let graph = contents.graph;

        let event = unwrap!(graph.find_by_short_name("C_8"));

        let expected = vec![
            "C_8", "C_7", "D_14", "B_26", "B_25", "B_24", "A_18", "B_23", "B_22", "D_13", "B_21",
            "D_12", "D_11", "B_20", "B_19", "A_17", "B_18", "A_16", "A_15", "D_10", "B_17", "B_16",
            "A_14", "B_15", "B_14", "D_9", "D_8", "A_13", "A_12", "A_11", "A_10", "D_7", "D_6",
            "B_13", "A_9", "A_8", "D_5", "B_12", "B_11", "B_10", "C_6", "B_9", "B_8", "D_4", "D_3",
            "A_7", "C_5", "C_4", "A_6", "A_5", "A_4", "D_2", "D_1", "D_0", "B_7", "B_6", "B_5",
            "B_4", "A_3", "B_3", "C_3", "C_2", "B_2", "B_1", "B_0", "A_2", "A_1", "A_0", "C_1",
            "C_0",
        ];

        let mut actual_names = Vec::new();
        let mut actual_indices = Vec::new();

        for event in graph.ancestors(event) {
            actual_names.push(event.short_name().to_string());
            actual_indices.push(event.event_index());
        }

        assert_eq!(actual_names, expected);

        // Assert the events are yielded in reverse topological order.
        let mut sorted_indices = actual_indices.clone();
        sorted_indices.sort_by_key(|&b| Reverse(b));

        assert_eq!(actual_indices, sorted_indices);
    }
}
