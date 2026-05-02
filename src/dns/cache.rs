use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct DnsCache {
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
    max_entries: usize,
}

#[derive(Hash, Eq, PartialEq)]
struct CacheKey {
    qname: String,
    qtype: RecordType,
}

struct CacheEntry {
    message: Message,
    inserted_at: Instant,
    ttl: Duration,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.max_entries > 0
    }

    pub fn lookup(&self, qname: &str, qtype: RecordType) -> Option<Message> {
        let key = CacheKey {
            qname: qname.to_lowercase(),
            qtype,
        };
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get(&key) {
            let elapsed = entry.inserted_at.elapsed();
            if elapsed < entry.ttl {
                let mut msg = entry.message.clone();
                // RFC 1035 §3.2.1 / RFC 2181 §8: a record's TTL is "time
                // remaining", not "original lifetime". Without decrementing,
                // downstream resolvers re-cache the original TTL and total
                // staleness compounds past the authoritative expiry.
                // Sub-second elapsed truncates to 0, so within the first
                // second after insert we may hand back the original TTL —
                // accepted as a 1s rounding error rather than tracking
                // millisecond TTLs that resolvers can't represent anyway.
                decrement_record_ttls(&mut msg, elapsed.as_secs() as u32);
                return Some(msg);
            }
            entries.remove(&key);
        }
        None
    }

    pub fn insert(&self, qname: &str, qtype: RecordType, message: Message, ttl: Duration) {
        if !self.is_enabled() {
            return;
        }
        let key = CacheKey {
            qname: qname.to_lowercase(),
            qtype,
        };
        let mut entries = self.entries.lock().unwrap();

        // If at capacity and this is a new key, sweep expired entries
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            entries.retain(|_, entry| entry.inserted_at.elapsed() < entry.ttl);
        }

        // If still at capacity after sweep, skip insertion
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            return;
        }

        entries.insert(
            key,
            CacheEntry {
                message,
                inserted_at: Instant::now(),
                ttl,
            },
        );
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

fn decrement_record_ttls(msg: &mut Message, elapsed_secs: u32) {
    for record in msg.answers_mut() {
        record.set_ttl(record.ttl().saturating_sub(elapsed_secs));
    }
    for record in msg.name_servers_mut() {
        record.set_ttl(record.ttl().saturating_sub(elapsed_secs));
    }
    for record in msg.additionals_mut() {
        record.set_ttl(record.ttl().saturating_sub(elapsed_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, ResponseCode};
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn make_response(name: &str, ip: Ipv4Addr, ttl: u32) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let mut record = Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(hickory_proto::rr::rdata::A(ip)),
        );
        record.set_record_type(RecordType::A);
        msg.add_answer(record);
        msg
    }

    #[test]
    fn test_disabled_cache() {
        let cache = DnsCache::new(0);
        assert!(!cache.is_enabled());
        cache.insert(
            "example.com",
            RecordType::A,
            Message::new(),
            Duration::from_secs(60),
        );
        assert!(cache.lookup("example.com", RecordType::A).is_none());
    }

    #[test]
    fn test_insert_and_lookup() {
        let cache = DnsCache::new(100);
        let msg = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300);

        cache.insert(
            "example.com.",
            RecordType::A,
            msg.clone(),
            Duration::from_secs(60),
        );

        let cached = cache.lookup("example.com.", RecordType::A);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().answers().len(), 1);
    }

    #[test]
    fn test_case_insensitive() {
        let cache = DnsCache::new(100);
        let msg = make_response("Example.COM.", Ipv4Addr::new(1, 2, 3, 4), 300);

        cache.insert("Example.COM.", RecordType::A, msg, Duration::from_secs(60));
        assert!(cache.lookup("example.com.", RecordType::A).is_some());
    }

    #[test]
    fn test_expired_entry_removed() {
        let cache = DnsCache::new(100);
        let msg = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300);

        cache.insert("example.com.", RecordType::A, msg, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));

        assert!(cache.lookup("example.com.", RecordType::A).is_none());
    }

    #[test]
    fn test_different_qtypes() {
        let cache = DnsCache::new(100);
        let msg = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300);

        cache.insert("example.com.", RecordType::A, msg, Duration::from_secs(60));
        assert!(cache.lookup("example.com.", RecordType::A).is_some());
        assert!(cache.lookup("example.com.", RecordType::AAAA).is_none());
    }

    #[test]
    fn test_clear() {
        let cache = DnsCache::new(100);
        let msg = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300);

        cache.insert("example.com.", RecordType::A, msg, Duration::from_secs(60));
        cache.clear();
        assert!(cache.lookup("example.com.", RecordType::A).is_none());
    }

    #[test]
    fn test_capacity_sweep() {
        let cache = DnsCache::new(2);
        let msg1 = make_response("a.com.", Ipv4Addr::new(1, 1, 1, 1), 300);
        let msg2 = make_response("b.com.", Ipv4Addr::new(2, 2, 2, 2), 300);
        let msg3 = make_response("c.com.", Ipv4Addr::new(3, 3, 3, 3), 300);

        // Insert with very short TTL so they expire
        cache.insert("a.com.", RecordType::A, msg1, Duration::from_millis(1));
        cache.insert("b.com.", RecordType::A, msg2, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));

        // This should trigger sweep of expired entries and succeed
        cache.insert("c.com.", RecordType::A, msg3, Duration::from_secs(60));
        assert!(cache.lookup("c.com.", RecordType::A).is_some());
    }

    #[test]
    fn lookup_decrements_record_ttl_by_elapsed() {
        // Regression: previously the cached message was returned verbatim,
        // so downstream resolvers re-cached the original TTL and total
        // staleness compounded past the authoritative expiry.
        let cache = DnsCache::new(100);
        let msg = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300);

        cache.insert("example.com.", RecordType::A, msg, Duration::from_secs(300));

        std::thread::sleep(Duration::from_millis(1100));

        let cached = cache.lookup("example.com.", RecordType::A).unwrap();
        let returned_ttl = cached.answers()[0].ttl();
        // The point is that decrement happened (TTL strictly less than the
        // original 300). We don't pin a tight window because heavily loaded
        // CI runners can sleep noticeably longer than requested.
        assert!(
            returned_ttl < 300,
            "expected TTL < 300 after decrement, got {returned_ttl}"
        );
        assert!(
            returned_ttl >= 290,
            "expected TTL >= 290 (at most 10s of scheduler slack), got {returned_ttl}"
        );
    }

    #[test]
    fn lookup_saturates_at_zero_for_old_records() {
        // If for some reason a record's encoded TTL is shorter than the
        // cache TTL, decrement must not underflow.
        let cache = DnsCache::new(100);
        let msg = make_response("example.com.", Ipv4Addr::new(1, 2, 3, 4), 0);

        cache.insert("example.com.", RecordType::A, msg, Duration::from_secs(60));

        std::thread::sleep(Duration::from_millis(1100));

        let cached = cache.lookup("example.com.", RecordType::A).unwrap();
        assert_eq!(cached.answers()[0].ttl(), 0);
    }
}
