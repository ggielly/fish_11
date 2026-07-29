//! FCEP-2 fragmentation and reassembly

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;

use crate::envelope::{DEFAULT_IRC_BUDGET, FCEP2_PREFIX, Fcep2Type, IrcLineBudget};
use crate::error::{Fcep2Error, Result};

/// Maximum number of fragments per logical object (spec §10.3).
pub const MAX_FRAGMENTS: u16 = 256;

/// Maximum total reassembled object size (1 MiB per spec §10.3).
pub const MAX_REASSEMBLY_SIZE: usize = 1024 * 1024;

/// Maximum concurrent reassemblies per remote source (spec §10.3).
pub const MAX_CONCURRENT_ASSEMBLIES: usize = 32;

/// Reassembly timeout (120 seconds per spec §10.3).
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum fragment raw payload before base64url encoding.
///
/// 320 raw octets => ~427 base64url chars => line = ~469 chars including overhead.
/// With `PRIVMSG/NOTICE target :` (up to ~40 chars) + CRLF (2), the wire line
/// must stay under 512. We use 240 raw octets as a safe upper bound that fits
/// even with 80-char targets, while still being efficient.
///
/// The transport layer SHOULD use `serialize_for_irc(command, destination)`
/// for precise budget calculation when the target is known.
pub const MAX_FRAGMENT_PAYLOAD: usize = 240;

/// A single fragment.
#[derive(Debug, Clone)]
pub struct Fragment {
    /// 128-bit random object identifier.
    pub object_id: [u8; 16],
    /// Zero-based index.
    pub index: u16,
    /// Total number of fragments.
    pub count: u16,
    /// Kind of the reassembled object.
    pub kind: Fcep2Type,
    /// Base64url-encoded fragment data.
    pub data: Vec<u8>,
}

impl Fragment {
    /// Parse a fragment from the tokens after "+FCEP2 F ".
    pub fn parse(tokens: &[&str]) -> Result<Self> {
        if tokens.len() < 5 {
            return Err(Fcep2Error::InvalidFragment(format!(
                "Expected 5 tokens (oid index count kind data), got {}",
                tokens.len()
            )));
        }

        // object-id: 22 chars base64url = 16 bytes
        let oid_bytes = URL_SAFE_NO_PAD
            .decode(tokens[0])
            .map_err(|e| Fcep2Error::InvalidFragment(format!("Invalid object-id: {}", e)))?;
        if oid_bytes.len() != 16 {
            return Err(Fcep2Error::InvalidFragment(format!(
                "object-id must be 16 bytes, got {}",
                oid_bytes.len()
            )));
        }
        let mut object_id = [0u8; 16];
        object_id.copy_from_slice(&oid_bytes);

        // index
        let index: u16 = tokens[1]
            .parse()
            .map_err(|e| Fcep2Error::InvalidFragment(format!("Invalid index: {}", e)))?;

        // count
        let count: u16 = tokens[2]
            .parse()
            .map_err(|e| Fcep2Error::InvalidFragment(format!("Invalid count: {}", e)))?;
        if count == 0 || count > MAX_FRAGMENTS {
            return Err(Fcep2Error::InvalidFragment(format!(
                "Count must be 1-{}, got {}",
                MAX_FRAGMENTS, count
            )));
        }
        if index >= count {
            return Err(Fcep2Error::InvalidFragment(format!("Index {} >= count {}", index, count)));
        }

        // kind
        let kind_byte = tokens[3]
            .as_bytes()
            .first()
            .ok_or_else(|| Fcep2Error::InvalidFragment("Empty kind".to_string()))?;
        let kind = Fcep2Type::from_byte(*kind_byte)?;
        if kind == Fcep2Type::Fragment {
            return Err(Fcep2Error::InvalidFragment(
                "Kind F is reserved for fragment headers".to_string(),
            ));
        }

        // fragment data (remaining tokens joined, in case of edge cases)
        let data_str = if tokens.len() > 4 { tokens[4..].join("") } else { tokens[4].to_string() };
        let data = URL_SAFE_NO_PAD
            .decode(&data_str)
            .map_err(|e| Fcep2Error::InvalidFragment(format!("Invalid fragment data: {}", e)))?;

        Ok(Self { object_id, index, count, kind, data })
    }

    /// Serialize this fragment to an IRC line using the default conservative budget.
    pub fn serialize(&self) -> Result<String> {
        self.serialize_with_budget(&DEFAULT_IRC_BUDGET)
    }

    /// Serialize this fragment for a specific IRC command and destination,
    /// computing the precise line budget.
    pub fn serialize_for_irc(&self, command: &str, destination: &str) -> Result<String> {
        let budget = IrcLineBudget::new(command, destination);
        self.serialize_with_budget(&budget)
    }

    /// Serialize with a given IRC line budget.
    fn serialize_with_budget(&self, budget: &IrcLineBudget) -> Result<String> {
        let oid_b64 = URL_SAFE_NO_PAD.encode(self.object_id);
        let data_b64 = URL_SAFE_NO_PAD.encode(&self.data);
        let kind_char = self.kind.to_char() as char;

        let line = format!(
            "{}F {} {} {} {} {}",
            FCEP2_PREFIX, oid_b64, self.index, self.count, kind_char, data_b64
        );

        // Check IRC line budget dynamically
        let max_line = budget.available_for_line();
        if line.len() > max_line {
            return Err(Fcep2Error::LineOverflow);
        }

        Ok(line)
    }
}

/// State of an in-progress fragment assembly.
#[derive(Debug)]
pub struct FragmentAssembly {
    /// Source identifier (IRC nick or device fingerprint).
    pub source_id: String,
    /// Object identifier.
    pub object_id: [u8; 16],
    /// Kind of the reassembled object.
    pub kind: Fcep2Type,
    /// Total expected fragment count.
    pub count: u16,
    /// Received fragments (indexed by fragment index).
    pub received: Vec<Option<Vec<u8>>>,
    /// When assembly started.
    pub created_at: Instant,
}

impl FragmentAssembly {
    /// Create a new assembly from the first fragment.
    pub fn new(source_id: String, fragment: &Fragment) -> Self {
        let mut received = Vec::with_capacity(fragment.count as usize);
        received.resize_with(fragment.count as usize, || None);
        received[fragment.index as usize] = Some(fragment.data.clone());

        Self {
            source_id,
            object_id: fragment.object_id,
            kind: fragment.kind,
            count: fragment.count,
            received,
            created_at: Instant::now(),
        }
    }

    /// Add a fragment to this assembly.
    ///
    /// Returns `Some(data)` if the assembly is now complete.
    /// Validates per-fragment size limits to prevent DoS before concatenation.
    pub fn add_fragment(&mut self, fragment: &Fragment) -> Result<Option<Vec<u8>>> {
        // Validate consistency
        if fragment.object_id != self.object_id {
            return Err(Fcep2Error::InvalidFragment("Object ID mismatch".to_string()));
        }
        if fragment.count != self.count {
            return Err(Fcep2Error::InvalidFragment(format!(
                "Count mismatch: expected {}, got {}",
                self.count, fragment.count
            )));
        }
        if fragment.kind != self.kind {
            return Err(Fcep2Error::InvalidFragment(format!(
                "Kind mismatch: expected {:?}, got {:?}",
                self.kind, fragment.kind
            )));
        }
        if fragment.index >= self.count {
            return Err(Fcep2Error::InvalidFragment(format!(
                "Index {} >= count {}",
                fragment.index, self.count
            )));
        }

        // §10.3 / DoS: reject individual fragments that exceed the total max size.
        // Even a single fragment must fit within the reassembly budget.
        if fragment.data.len() > MAX_REASSEMBLY_SIZE {
            return Err(Fcep2Error::InvalidFragment(format!(
                "Fragment data too large: {} bytes (max {})",
                fragment.data.len(),
                MAX_REASSEMBLY_SIZE
            )));
        }

        // §10.3 / DoS: check cumulative received bytes BEFORE storing this fragment,
        // to prevent an attacker from filling memory with fragments that will be
        // rejected only at concatenation time.
        let new_total =
            self.received.iter().filter_map(|s| s.as_ref().map(|d| d.len())).sum::<usize>()
                + fragment.data.len();
        if new_total > MAX_REASSEMBLY_SIZE {
            return Err(Fcep2Error::FragmentAssembly(format!(
                "Cumulative fragment data would exceed {} byte limit",
                MAX_REASSEMBLY_SIZE
            )));
        }

        // Store the fragment (ignore duplicates)
        if self.received[fragment.index as usize].is_none() {
            self.received[fragment.index as usize] = Some(fragment.data.clone());
        }

        // Check if complete
        if self.received.iter().all(|s| s.is_some()) {
            let data: Vec<u8> =
                self.received.iter().flat_map(|s| s.as_ref().unwrap().iter()).copied().collect();

            // Validate total size (safety net : should be redundant with per-fragment check)
            if data.len() > MAX_REASSEMBLY_SIZE {
                return Err(Fcep2Error::InvalidFragment(format!(
                    "Reassembled object too large: {} bytes (max {})",
                    data.len(),
                    MAX_REASSEMBLY_SIZE
                )));
            }

            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Check if this assembly has timed out.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > REASSEMBLY_TIMEOUT
    }

    /// Count of received fragments.
    pub fn received_count(&self) -> usize {
        self.received.iter().filter(|s| s.is_some()).count()
    }
}

/// Fragment assembler: manages concurrent reassemblies.
pub struct FragmentAssembler {
    /// Active assemblies keyed by (source_id, object_id).
    assemblies: HashMap<(String, [u8; 16]), FragmentAssembly>,
}

impl FragmentAssembler {
    pub fn new() -> Self {
        Self { assemblies: HashMap::new() }
    }

    /// Process an incoming fragment. Returns the reassembled data if complete.
    ///
    /// The assembly entry is removed immediately upon successful reassembly
    /// (§10.3: prevent memory leak, free concurrency slot, avoid ambiguity
    /// on retransmission of the same object_id).
    pub fn process_fragment(
        &mut self,
        source_id: &str,
        fragment: Fragment,
    ) -> Result<Option<Vec<u8>>> {
        let key = (source_id.to_string(), fragment.object_id);

        // Check if assembly exists
        if let Some(assembly) = self.assemblies.get_mut(&key) {
            let complete = assembly.add_fragment(&fragment)?;
            if complete.is_some() {
                self.assemblies.remove(&key);
            }
            return Ok(complete);
        }

        // New assembly : validate fragment first
        if fragment.count == 0 {
            return Err(Fcep2Error::InvalidFragment("Count must be >= 1".to_string()));
        }
        if fragment.index >= fragment.count {
            return Err(Fcep2Error::InvalidFragment(format!(
                "Index {} >= count {}",
                fragment.index, fragment.count
            )));
        }

        // New assembly : check limits
        let source_count = self.assemblies.keys().filter(|(sid, _)| sid == source_id).count();
        if source_count >= MAX_CONCURRENT_ASSEMBLIES {
            // Evict oldest expired assembly
            self.evict_expired();
            let source_count = self.assemblies.keys().filter(|(sid, _)| sid == source_id).count();
            if source_count >= MAX_CONCURRENT_ASSEMBLIES {
                return Err(Fcep2Error::RateLimit(format!(
                    "Too many concurrent assemblies from {}",
                    source_id
                )));
            }
        }

        // Single fragment = complete
        if fragment.count == 1 {
            return Ok(Some(fragment.data.clone()));
        }

        let assembly = FragmentAssembly::new(source_id.to_string(), &fragment);
        self.assemblies.insert(key, assembly);
        Ok(None)
    }

    /// Evict expired assemblies.
    fn evict_expired(&mut self) {
        self.assemblies.retain(|_, a| !a.is_expired());
    }

    /// Clean up expired assemblies (call periodically).
    pub fn cleanup(&mut self) {
        self.evict_expired();
    }

    /// Number of active assemblies.
    pub fn active_count(&self) -> usize {
        self.assemblies.len()
    }
}

/// Fragment a complete payload into transport-sized pieces.
///
/// Returns a list of Fragment structs ready to be serialized.
pub fn fragment_payload(
    object_id: [u8; 16],
    kind: Fcep2Type,
    data: &[u8],
) -> Result<Vec<Fragment>> {
    if data.is_empty() {
        return Err(Fcep2Error::InvalidFragment("Empty payload".to_string()));
    }

    if data.len() > MAX_REASSEMBLY_SIZE {
        return Err(Fcep2Error::InvalidFragment(format!(
            "Payload too large: {} bytes",
            data.len()
        )));
    }

    let chunk_size = MAX_FRAGMENT_PAYLOAD;
    let count = (data.len() + chunk_size - 1) / chunk_size;

    if count > MAX_FRAGMENTS as usize {
        return Err(Fcep2Error::InvalidFragment(format!(
            "Payload requires {} fragments (max {})",
            count, MAX_FRAGMENTS
        )));
    }

    let mut fragments = Vec::with_capacity(count);
    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        fragments.push(Fragment {
            object_id,
            index: i as u16,
            count: count as u16,
            kind,
            data: chunk.to_vec(),
        });
    }

    Ok(fragments)
}

/// Generate a random 128-bit object identifier for fragmentation.
pub fn generate_object_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

impl Default for FragmentAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_roundtrip() {
        let data = vec![0x42u8; 500];
        let oid = generate_object_id();
        let fragments = fragment_payload(oid, Fcep2Type::Application, &data).unwrap();

        // With MAX_FRAGMENT_PAYLOAD = 240, 500 bytes -> 3 fragments
        assert!(fragments.len() >= 3);

        let mut assembler = FragmentAssembler::new();
        let mut last_result = None;
        for frag in &fragments {
            last_result = assembler.process_fragment("test", frag.clone()).unwrap();
        }
        // Last fragment should complete the assembly
        assert!(last_result.is_some());
        assert_eq!(last_result.unwrap(), data);
    }

    #[test]
    fn test_single_fragment() {
        let data = vec![0x01, 0x02, 0x03];
        let oid = generate_object_id();
        let fragments = fragment_payload(oid, Fcep2Type::Welcome, &data).unwrap();

        assert_eq!(fragments.len(), 1);

        let mut assembler = FragmentAssembler::new();
        let result = assembler.process_fragment("test", fragments[0].clone()).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_duplicate_fragment_ignored() {
        let data = vec![0x42u8; 500];
        let oid = generate_object_id();
        let fragments = fragment_payload(oid, Fcep2Type::Application, &data).unwrap();

        let mut assembler = FragmentAssembler::new();
        // Send first fragment twice
        assembler.process_fragment("test", fragments[0].clone()).unwrap();
        let result = assembler.process_fragment("test", fragments[0].clone()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_count_validation() {
        let oid = generate_object_id();
        let frag = Fragment {
            object_id: oid,
            index: 0,
            count: 0, // invalid
            kind: Fcep2Type::Application,
            data: vec![1],
        };
        let result = FragmentAssembler::new().process_fragment("test", frag);
        assert!(result.is_err());
    }

    #[test]
    fn test_index_validation() {
        let oid = generate_object_id();
        let frag = Fragment {
            object_id: oid,
            index: 5,
            count: 3, // index >= count
            kind: Fcep2Type::Application,
            data: vec![1],
        };
        let result = FragmentAssembler::new().process_fragment("test", frag);
        assert!(result.is_err());
    }
}
