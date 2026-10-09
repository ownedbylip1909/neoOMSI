//! Protected In-Memory Virtual File System (VFS) and `.neoasset` encrypted containers.
//!
//! Provides zero-disk-leak mod asset protection, in-memory on-demand decryption,
//! session-bound key management with automatic memory zeroization, and forensic watermarking
//! for leak attribution.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Container magic identifier: "NEOASSET"
pub const MAGIC: &[u8; 8] = b"NEOASSET";
pub const CURRENT_VERSION: u32 = 1;

const FLAG_HAS_WATERMARK: u32 = 1 << 0;
const FLAG_COMPRESSED_INDEX: u32 = 1 << 1;

/// Maximum size for a single file entry in memory (2 GB).
const MAX_ENTRY_SIZE: u64 = 1 << 31;

// -------------------------------------------------------------------------------------
// Cryptographic Primitives & Key Management

/// A 32-byte key container that automatically zeroes its memory when dropped.
#[derive(Clone)]
pub struct ZeroizingKey(pub [u8; 32]);

impl ZeroizingKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ZeroizingKey {
    fn drop(&mut self) {
        for byte in self.0.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Constant-time comparison of two byte slices to prevent timing side channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC-SHA256 implementation (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut k = [0u8; BLOCK_SIZE];

    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_hash);
    out
}

/// HKDF Extract & Expand (RFC 5869) using SHA-256.
pub fn hkdf_derive_keys(
    master_key: &[u8],
    salt: &[u8],
    info: &[u8],
) -> (ZeroizingKey, ZeroizingKey, [u8; 16]) {
    let prk = hmac_sha256(salt, master_key);

    // Expand T(1) = HMAC(PRK, info || 0x01)
    let mut t1_input = Vec::with_capacity(info.len() + 1);
    t1_input.extend_from_slice(info);
    t1_input.push(1);
    let t1 = hmac_sha256(&prk, &t1_input);

    // Expand T(2) = HMAC(PRK, T(1) || info || 0x02)
    let mut t2_input = Vec::with_capacity(32 + info.len() + 1);
    t2_input.extend_from_slice(&t1);
    t2_input.extend_from_slice(info);
    t2_input.push(2);
    let t2 = hmac_sha256(&prk, &t2_input);

    // Expand T(3) = HMAC(PRK, T(2) || info || 0x03)
    let mut t3_input = Vec::with_capacity(32 + info.len() + 1);
    t3_input.extend_from_slice(&t2);
    t3_input.extend_from_slice(info);
    t3_input.push(3);
    let t3 = hmac_sha256(&prk, &t3_input);

    let enc_key = ZeroizingKey::new(t1);
    let mac_key = ZeroizingKey::new(t2);
    let mut nonce_prefix = [0u8; 16];
    nonce_prefix.copy_from_slice(&t3[..16]);

    (enc_key, mac_key, nonce_prefix)
}

/// CTR-mode keystream XOR encryption/decryption using SHA-256 block generation.
/// Keystream block i = SHA-256(Key || Nonce || BlockCounter).
pub fn crypt_stream(key: &[u8; 32], nonce: &[u8; 16], counter_start: u64, data: &mut [u8]) {
    let mut block_idx = counter_start;
    let mut chunk_iter = data.chunks_mut(32);

    while let Some(chunk) = chunk_iter.next() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(&block_idx.to_le_bytes());
        let block = hasher.finalize();

        for (d, k) in chunk.iter_mut().zip(block.iter()) {
            *d ^= k;
        }
        block_idx = block_idx.wrapping_add(1);
    }
}

// -------------------------------------------------------------------------------------
// Forensic Watermark

/// Forensic Watermark embedded into protected containers to trace leaks to specific accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watermark {
    /// Account / Steam ID of the licensee.
    pub account_id: String,
    /// Licensee display name or identifier.
    pub owner_name: String,
    /// Session or issuance ID.
    pub session_id: u64,
    /// Issuance timestamp (Unix seconds).
    pub created_at: u64,
    /// Feature or permission flags.
    pub flags: u32,
    /// Cryptographic signature / authentication token.
    pub signature: Vec<u8>,
}

impl Watermark {
    pub fn new(account_id: impl Into<String>, owner_name: impl Into<String>, session_id: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            account_id: account_id.into(),
            owner_name: owner_name.into(),
            session_id,
            created_at: now,
            flags: 0,
            signature: Vec::new(),
        }
    }

    /// Encode watermark into binary format:
    /// [acc_len: u16][account_id][owner_len: u16][owner_name][session_id: u64][created_at: u64][flags: u32][sig_len: u16][sig]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let acc_bytes = self.account_id.as_bytes();
        buf.extend_from_slice(&(acc_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(acc_bytes);

        let owner_bytes = self.owner_name.as_bytes();
        buf.extend_from_slice(&(owner_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(owner_bytes);

        buf.extend_from_slice(&self.session_id.to_le_bytes());
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());

        buf.extend_from_slice(&(self.signature.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Decode watermark from binary payload.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let mut cursor = 0;
        let read_u16 = |cur: &mut usize| -> io::Result<u16> {
            if *cur + 2 > bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "watermark truncated"));
            }
            let val = u16::from_le_bytes([bytes[*cur], bytes[*cur + 1]]);
            *cur += 2;
            Ok(val)
        };
        let read_u32 = |cur: &mut usize| -> io::Result<u32> {
            if *cur + 4 > bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "watermark truncated"));
            }
            let val = u32::from_le_bytes([
                bytes[*cur],
                bytes[*cur + 1],
                bytes[*cur + 2],
                bytes[*cur + 3],
            ]);
            *cur += 4;
            Ok(val)
        };
        let read_u64 = |cur: &mut usize| -> io::Result<u64> {
            if *cur + 8 > bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "watermark truncated"));
            }
            let val = u64::from_le_bytes([
                bytes[*cur],
                bytes[*cur + 1],
                bytes[*cur + 2],
                bytes[*cur + 3],
                bytes[*cur + 4],
                bytes[*cur + 5],
                bytes[*cur + 6],
                bytes[*cur + 7],
            ]);
            *cur += 8;
            Ok(val)
        };

        let acc_len = read_u16(&mut cursor)? as usize;
        if cursor + acc_len > bytes.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "watermark acc truncated"));
        }
        let account_id = String::from_utf8_lossy(&bytes[cursor..cursor + acc_len]).into_owned();
        cursor += acc_len;

        let owner_len = read_u16(&mut cursor)? as usize;
        if cursor + owner_len > bytes.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "watermark owner truncated"));
        }
        let owner_name = String::from_utf8_lossy(&bytes[cursor..cursor + owner_len]).into_owned();
        cursor += owner_len;

        let session_id = read_u64(&mut cursor)?;
        let created_at = read_u64(&mut cursor)?;
        let flags = read_u32(&mut cursor)?;

        let sig_len = read_u16(&mut cursor)? as usize;
        if cursor + sig_len > bytes.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "watermark sig truncated"));
        }
        let signature = bytes[cursor..cursor + sig_len].to_vec();

        Ok(Self {
            account_id,
            owner_name,
            session_id,
            created_at,
            flags,
            signature,
        })
    }

    /// Sign the watermark with an authentication secret key.
    pub fn sign(&mut self, secret: &[u8]) {
        self.signature.clear();
        let payload = self.encode();
        let tag = hmac_sha256(secret, &payload);
        self.signature = tag.to_vec();
    }

    /// Verify signature authenticity against the master server secret.
    pub fn verify(&self, secret: &[u8]) -> bool {
        let mut copy = self.clone();
        copy.signature.clear();
        let payload = copy.encode();
        let expected = hmac_sha256(secret, &payload);
        constant_time_eq(&self.signature, &expected)
    }
}

// -------------------------------------------------------------------------------------
// Protected Archive Structures

/// One file entry inside a protected `.neoasset` archive.
#[derive(Debug, Clone)]
pub struct ProtectedEntry {
    /// Original relative path inside OMSI content roots.
    pub rel_path: String,
    /// Uncompressed plain text size.
    pub uncompressed_size: u64,
    /// Compressed/encrypted stored size.
    pub encrypted_size: u64,
    /// Byte offset in the container file/buffer.
    pub offset: u64,
    /// Expected SHA-256 digest of decrypted, uncompressed data.
    pub sha256: [u8; 32],
    /// Compression method (0 = none, 8 = Deflate).
    pub compression: u8,
    /// Nonce tweak for entry encryption.
    pub nonce_tweak: [u8; 8],
    /// HMAC authentication tag for entry payload.
    pub entry_mac: [u8; 32],
}

enum ArchiveSource {
    File {
        file: File,
        #[cfg(not(unix))]
        lock: Mutex<()>,
    },
    Memory(Arc<Vec<u8>>),
}

/// A mounted protected archive containing encrypted OMSI assets.
pub struct ProtectedArchive {
    path: PathBuf,
    prefix: String,
    watermark: Option<Watermark>,
    entries: HashMap<String, ProtectedEntry>,
    dirs: HashMap<String, Vec<(String, bool)>>,
    source: ArchiveSource,
    enc_key: ZeroizingKey,
    mac_key: ZeroizingKey,
    nonce_prefix: [u8; 16],
}

impl ProtectedArchive {
    /// Open a `.neoasset` container from disk using the session decryption key.
    pub fn open(path: &Path, session_key: &[u8]) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = File::open(path)?;
        let mut header = [0u8; 64];
        reader.read_exact(&mut header)?;

        if &header[..8] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: not a valid .neoasset container", path.display()),
            ));
        }

        let version = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        if version != CURRENT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: unsupported container version {version}", path.display()),
            ));
        }

        let flags = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        let salt = &header[16..32];
        let master_nonce = &header[32..48];

        let wm_len = u32::from_le_bytes([header[48], header[49], header[50], header[51]]) as usize;
        let watermark = if flags & FLAG_HAS_WATERMARK != 0 && wm_len > 0 {
            let mut wm_bytes = vec![0u8; wm_len];
            reader.read_exact(&mut wm_bytes)?;
            Watermark::decode(&wm_bytes).ok()
        } else {
            None
        };

        let mut index_meta = [0u8; 48]; // [idx_offset: u64][idx_len: u32][pad: 4][idx_mac: 32]
        reader.read_exact(&mut index_meta)?;
        let idx_offset = u64::from_le_bytes([
            index_meta[0], index_meta[1], index_meta[2], index_meta[3],
            index_meta[4], index_meta[5], index_meta[6], index_meta[7],
        ]);
        let idx_len = u32::from_le_bytes([
            index_meta[8], index_meta[9], index_meta[10], index_meta[11],
        ]) as usize;
        let idx_mac = &index_meta[16..48];

        let (enc_key, mac_key, nonce_prefix) =
            hkdf_derive_keys(session_key, salt, b"neoOMSI-Protected-VFS-v1");

        // Read and authenticate encrypted directory table
        reader.seek(SeekFrom::Start(idx_offset))?;
        let mut enc_idx = vec![0u8; idx_len];
        reader.read_exact(&mut enc_idx)?;

        let computed_idx_mac = hmac_sha256(mac_key.as_slice(), &enc_idx);
        if !constant_time_eq(&computed_idx_mac, idx_mac) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{}: invalid session key or corrupted container header", path.display()),
            ));
        }

        let mut raw_idx = enc_idx;
        let mut idx_nonce = [0u8; 16];
        idx_nonce[..8].copy_from_slice(&master_nonce[..8]);
        idx_nonce[8..].copy_from_slice(b"DIRINDEX");
        crypt_stream(&enc_key.0, &idx_nonce, 0, &mut raw_idx);

        let entries_list = Self::parse_entries_index(&raw_idx)?;
        let (prefix, entries, dirs) = Self::index_entries(entries_list);

        Ok(Self {
            path: path.to_path_buf(),
            prefix,
            watermark,
            entries,
            dirs,
            source: ArchiveSource::File {
                file,
                #[cfg(not(unix))]
                lock: Mutex::new(()),
            },
            enc_key,
            mac_key,
            nonce_prefix,
        })
    }

    /// Open a `.neoasset` container directly from an in-memory byte buffer.
    pub fn from_bytes(name: &str, data: Arc<Vec<u8>>, session_key: &[u8]) -> io::Result<Self> {
        let bytes = data.as_slice();
        if bytes.len() < 112 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "container buffer too short",
            ));
        }

        if &bytes[..8] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a valid .neoasset container",
            ));
        }

        let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != CURRENT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported container version {version}"),
            ));
        }

        let flags = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let salt = &bytes[16..32];
        let master_nonce = &bytes[32..48];

        let wm_len = u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]) as usize;
        let mut cur = 52;
        let watermark = if flags & FLAG_HAS_WATERMARK != 0 && wm_len > 0 {
            if cur + wm_len > bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated watermark"));
            }
            let wm = Watermark::decode(&bytes[cur..cur + wm_len]).ok();
            cur += wm_len;
            wm
        } else {
            None
        };

        if cur + 48 > bytes.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated index meta"));
        }
        let idx_offset = u64::from_le_bytes([
            bytes[cur], bytes[cur + 1], bytes[cur + 2], bytes[cur + 3],
            bytes[cur + 4], bytes[cur + 5], bytes[cur + 6], bytes[cur + 7],
        ]) as usize;
        let idx_len = u32::from_le_bytes([
            bytes[cur + 8], bytes[cur + 9], bytes[cur + 10], bytes[cur + 11],
        ]) as usize;
        let idx_mac = &bytes[cur + 16..cur + 48];

        let (enc_key, mac_key, nonce_prefix) =
            hkdf_derive_keys(session_key, salt, b"neoOMSI-Protected-VFS-v1");

        if idx_offset + idx_len > bytes.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated directory index"));
        }

        let enc_idx = &bytes[idx_offset..idx_offset + idx_len];
        let computed_idx_mac = hmac_sha256(mac_key.as_slice(), enc_idx);
        if !constant_time_eq(&computed_idx_mac, idx_mac) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid session key or corrupted container index",
            ));
        }

        let mut raw_idx = enc_idx.to_vec();
        let mut idx_nonce = [0u8; 16];
        idx_nonce[..8].copy_from_slice(&master_nonce[..8]);
        idx_nonce[8..].copy_from_slice(b"DIRINDEX");
        crypt_stream(&enc_key.0, &idx_nonce, 0, &mut raw_idx);

        let entries_list = Self::parse_entries_index(&raw_idx)?;
        let (prefix, entries, dirs) = Self::index_entries(entries_list);

        Ok(Self {
            path: PathBuf::from(name),
            prefix,
            watermark,
            entries,
            dirs,
            source: ArchiveSource::Memory(data),
            enc_key,
            mac_key,
            nonce_prefix,
        })
    }

    /// Extract watermark metadata from a `.neoasset` file without requiring the full decryption key.
    pub fn extract_watermark(path: &Path) -> io::Result<Option<Watermark>> {
        let mut f = File::open(path)?;
        let mut header = [0u8; 52];
        f.read_exact(&mut header)?;

        if &header[..8] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: not a valid .neoasset container", path.display()),
            ));
        }

        let flags = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        let wm_len = u32::from_le_bytes([header[48], header[49], header[50], header[51]]) as usize;

        if flags & FLAG_HAS_WATERMARK != 0 && wm_len > 0 {
            let mut wm_bytes = vec![0u8; wm_len];
            f.read_exact(&mut wm_bytes)?;
            Ok(Watermark::decode(&wm_bytes).ok())
        } else {
            Ok(None)
        }
    }

    fn parse_entries_index(data: &[u8]) -> io::Result<Vec<ProtectedEntry>> {
        let mut cur = 0;
        let read_u16 = |c: &mut usize| -> io::Result<u16> {
            if *c + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "idx eof"));
            }
            let v = u16::from_le_bytes([data[*c], data[*c + 1]]);
            *c += 2;
            Ok(v)
        };
        let read_u32 = |c: &mut usize| -> io::Result<u32> {
            if *c + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "idx eof"));
            }
            let v = u32::from_le_bytes([data[*c], data[*c + 1], data[*c + 2], data[*c + 3]]);
            *c += 4;
            Ok(v)
        };
        let read_u64 = |c: &mut usize| -> io::Result<u64> {
            if *c + 8 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "idx eof"));
            }
            let v = u64::from_le_bytes([
                data[*c], data[*c + 1], data[*c + 2], data[*c + 3],
                data[*c + 4], data[*c + 5], data[*c + 6], data[*c + 7],
            ]);
            *c += 8;
            Ok(v)
        };

        let count = read_u32(&mut cur)? as usize;
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            let path_len = read_u16(&mut cur)? as usize;
            if cur + path_len > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "idx path eof"));
            }
            let rel_path = String::from_utf8_lossy(&data[cur..cur + path_len]).into_owned();
            cur += path_len;

            let uncompressed_size = read_u64(&mut cur)?;
            let encrypted_size = read_u64(&mut cur)?;
            let offset = read_u64(&mut cur)?;

            if cur + 32 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "idx sha256 eof"));
            }
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&data[cur..cur + 32]);
            cur += 32;

            if cur + 1 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "idx comp eof"));
            }
            let compression = data[cur];
            cur += 1;

            if cur + 8 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "idx nonce eof"));
            }
            let mut nonce_tweak = [0u8; 8];
            nonce_tweak.copy_from_slice(&data[cur..cur + 8]);
            cur += 8;

            if cur + 32 > data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "idx mac eof"));
            }
            let mut entry_mac = [0u8; 32];
            entry_mac.copy_from_slice(&data[cur..cur + 32]);
            cur += 32;

            entries.push(ProtectedEntry {
                rel_path,
                uncompressed_size,
                encrypted_size,
                offset,
                sha256,
                compression,
                nonce_tweak,
                entry_mac,
            });
        }

        Ok(entries)
    }

    fn index_entries(
        entries_list: Vec<ProtectedEntry>,
    ) -> (
        String,
        HashMap<String, ProtectedEntry>,
        HashMap<String, Vec<(String, bool)>>,
    ) {
        let prefix = Self::detect_content_prefix(entries_list.iter().map(|e| e.rel_path.as_str()));
        let prefix_lower = prefix.to_lowercase();
        let mut entries = HashMap::new();
        let mut dirs: HashMap<String, Vec<(String, bool)>> = HashMap::new();
        let mut seen_dirs: HashSet<String> = HashSet::new();

        for entry in entries_list {
            let norm_path = entry.rel_path.replace('\\', "/");
            let lower = norm_path.to_lowercase();
            let rel_lower = if let Some(stripped) = lower.strip_prefix(&prefix_lower) {
                normalize_vfs_path(stripped)
            } else {
                normalize_vfs_path(&lower)
            };

            if rel_lower.is_empty() {
                continue;
            }

            let parts: Vec<&str> = rel_lower.split('/').collect();
            for k in 0..parts.len().saturating_sub(1) {
                let parent = parts[..k].join("/");
                let child_name = parts[k].to_string();
                let dir_key = parts[..=k].join("/");
                if seen_dirs.insert(dir_key) {
                    dirs.entry(parent)
                        .or_default()
                        .push((child_name, true));
                }
            }

            let parent = if parts.len() > 1 {
                parts[..parts.len() - 1].join("/")
            } else {
                String::new()
            };
            let file_name = parts.last().unwrap().to_string();
            dirs.entry(parent).or_default().push((file_name, false));

            entries.insert(rel_lower, entry);
        }

        (prefix, entries, dirs)
    }

    fn detect_content_prefix<'a>(names: impl Iterator<Item = &'a str>) -> String {
        const SHARED: [&str; 3] = ["Texture", "Sound", "Scripts"];
        let is_content = |c: &str| {
            crate::CONTENT_FOLDERS
                .iter()
                .any(|f| f.eq_ignore_ascii_case(c))
        };
        let mut children: HashMap<String, (String, Vec<String>)> = HashMap::new();
        for n in names {
            let parts: Vec<&str> = n.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
            let folders = parts.len().saturating_sub(1);
            for k in 0..folders.min(6) {
                if k > 0 && is_content(parts[k - 1]) {
                    break;
                }
                let dir: String = parts[..k].iter().map(|c| format!("{c}/")).collect();
                let e = children
                    .entry(dir.to_lowercase())
                    .or_insert_with(|| (dir.clone(), Vec::new()));
                let child = parts[k].to_lowercase();
                if !e.1.contains(&child) {
                    e.1.push(child);
                }
            }
        }
        children
            .into_iter()
            .filter_map(|(key, (dir, kids))| {
                let present: Vec<&str> = crate::CONTENT_FOLDERS
                    .iter()
                    .copied()
                    .filter(|f| kids.iter().any(|k| k.eq_ignore_ascii_case(f)))
                    .collect();
                if present.is_empty() {
                    return None;
                }
                let shared = present
                    .iter()
                    .filter(|f| SHARED.iter().any(|s| s.eq_ignore_ascii_case(f)))
                    .count();
                let depth = key.matches('/').count();
                Some((
                    (
                        present.len() - shared,
                        shared,
                        std::cmp::Reverse(depth),
                        std::cmp::Reverse(key),
                    ),
                    dir,
                ))
            })
            .max_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, dir)| dir)
            .unwrap_or_default()
    }

    fn read_bytes_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        match &self.source {
            ArchiveSource::Memory(arc) => {
                let off = offset as usize;
                if off + len > arc.len() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read out of bounds"));
                }
                Ok(arc[off..off + len].to_vec())
            }
            ArchiveSource::File {
                #[cfg(unix)]
                file,
                #[cfg(not(unix))]
                file,
                #[cfg(not(unix))]
                lock,
            } => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileExt;
                    let mut buf = vec![0u8; len];
                    file.read_exact_at(&mut buf, offset)?;
                    Ok(buf)
                }
                #[cfg(not(unix))]
                {
                    let _g = lock.lock().unwrap();
                    let mut f = file;
                    f.seek(SeekFrom::Start(offset))?;
                    let mut buf = vec![0u8; len];
                    f.read_exact(&mut buf)?;
                    Ok(buf)
                }
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    pub fn total_size(&self) -> u64 {
        self.entries.values().map(|e| e.uncompressed_size).sum()
    }

    pub fn watermark(&self) -> Option<&Watermark> {
        self.watermark.as_ref()
    }

    /// Read and decrypt an entry purely in memory. No decrypted file is ever written to disk.
    pub fn read(&self, rel: &str) -> io::Result<Vec<u8>> {
        let key = normalize_vfs_path(rel);
        let entry = self.entries.get(&key).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: no entry {rel}", self.path.display()),
            )
        })?;

        if entry.uncompressed_size > MAX_ENTRY_SIZE || entry.encrypted_size > MAX_ENTRY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: entry too large ({} bytes)", self.path.display(), entry.uncompressed_size),
            ));
        }

        let mut enc_data = self.read_bytes_at(entry.offset, entry.encrypted_size as usize)?;

        // 1. Verify Entry HMAC Tag
        let computed_mac = hmac_sha256(self.mac_key.as_slice(), &enc_data);
        if !constant_time_eq(&computed_mac, &entry.entry_mac) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: integrity tag mismatch for {rel}", self.path.display()),
            ));
        }

        // 2. Decrypt In-Memory
        let mut entry_nonce = [0u8; 16];
        entry_nonce[..8].copy_from_slice(&self.nonce_prefix[..8]);
        entry_nonce[8..].copy_from_slice(&entry.nonce_tweak);
        crypt_stream(&self.enc_key.0, &entry_nonce, 0, &mut enc_data);

        // 3. Decompress if Deflated
        let plain = match entry.compression {
            0 => enc_data,
            8 => {
                let mut out = Vec::with_capacity(entry.uncompressed_size as usize);
                flate2::read::DeflateDecoder::new(&enc_data[..])
                    .take(entry.uncompressed_size + 1)
                    .read_to_end(&mut out)?;
                out
            }
            c => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported compression method {c}"),
                ));
            }
        };

        if plain.len() as u64 != entry.uncompressed_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: size mismatch ({} vs expected {})", self.path.display(), plain.len(), entry.uncompressed_size),
            ));
        }

        // 4. Verify SHA-256 Checksum
        let computed_sha = Sha256::digest(&plain);
        if computed_sha.as_slice() != entry.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: SHA-256 checksum mismatch for {rel}", self.path.display()),
            ));
        }

        Ok(plain)
    }

    pub fn is_file(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn is_dir(&self, key: &str) -> bool {
        self.dirs.contains_key(key)
    }

    pub fn list_dir(&self, key: &str) -> Option<Vec<(OsString, bool)>> {
        self.dirs
            .get(key)
            .map(|l| l.iter().map(|(n, d)| (OsString::from(n), *d)).collect())
    }
}

// -------------------------------------------------------------------------------------
// Protected Archive Builder (Packaging & Encryption)

/// Builder to package mod directories into encrypted `.neoasset` containers.
pub struct ProtectedArchiveBuilder {
    watermark: Option<Watermark>,
    files: Vec<(String, Vec<u8>)>,
}

impl ProtectedArchiveBuilder {
    pub fn new() -> Self {
        Self {
            watermark: None,
            files: Vec::new(),
        }
    }

    pub fn set_watermark(&mut self, wm: Watermark) -> &mut Self {
        self.watermark = Some(wm);
        self
    }

    pub fn add_file(&mut self, rel_path: impl Into<String>, data: Vec<u8>) -> &mut Self {
        self.files.push((rel_path.into(), data));
        self
    }

    /// Recursively add all files from a directory on disk.
    pub fn add_dir_recursive(&mut self, base_dir: &Path) -> io::Result<usize> {
        let mut count = 0;
        fn walk(dir: &Path, base: &Path, list: &mut Vec<(String, Vec<u8>)>) -> io::Result<usize> {
            let mut c = 0;
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    c += walk(&path, base, list)?;
                } else if path.is_file() {
                    let rel = path
                        .strip_prefix(base)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                        .to_string_lossy()
                        .replace('\\', "/");
                    let data = std::fs::read(&path)?;
                    list.push((rel, data));
                    c += 1;
                }
            }
            Ok(c)
        }
        count += walk(base_dir, base_dir, &mut self.files)?;
        Ok(count)
    }

    /// Build and encrypt into an in-memory byte buffer.
    pub fn build_to_bytes(&self, session_key: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let salt = {
            let mut s = [0u8; 16];
            let mut hasher = Sha256::new();
            hasher.update(session_key);
            hasher.update(b"SALT");
            hasher.update(&std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos().to_le_bytes());
            s.copy_from_slice(&hasher.finalize()[..16]);
            s
        };
        let master_nonce = {
            let mut n = [0u8; 16];
            let mut hasher = Sha256::new();
            hasher.update(&salt);
            hasher.update(b"NONCE");
            n.copy_from_slice(&hasher.finalize()[..16]);
            n
        };

        let (enc_key, mac_key, nonce_prefix) =
            hkdf_derive_keys(session_key, &salt, b"neoOMSI-Protected-VFS-v1");

        let mut flags = 0u32;
        let wm_bytes = if let Some(ref wm) = self.watermark {
            flags |= FLAG_HAS_WATERMARK;
            wm.encode()
        } else {
            Vec::new()
        };

        // Write Header stub
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CURRENT_VERSION.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&master_nonce);
        out.extend_from_slice(&(wm_bytes.len() as u32).to_le_bytes());
        if !wm_bytes.is_empty() {
            out.extend_from_slice(&wm_bytes);
        }

        // Placeholder for directory table metadata: [idx_offset: u64][idx_len: u32][pad: 4][idx_mac: 32]
        let meta_pos = out.len();
        out.extend_from_slice(&[0u8; 48]);

        // Encrypt and write file bodies
        let mut entries = Vec::with_capacity(self.files.len());
        for (i, (rel_path, plain_data)) in self.files.iter().enumerate() {
            let uncompressed_size = plain_data.len() as u64;
            let sha256_digest: [u8; 32] = {
                let d = Sha256::digest(plain_data);
                let mut s = [0u8; 32];
                s.copy_from_slice(&d);
                s
            };

            // Deflate compression
            let mut compressed = Vec::new();
            let mut encoder = flate2::write::DeflateEncoder::new(&mut compressed, flate2::Compression::default());
            encoder.write_all(plain_data)?;
            encoder.finish()?;

            let (compression, mut payload) = if compressed.len() < plain_data.len() {
                (8u8, compressed)
            } else {
                (0u8, plain_data.clone())
            };

            let nonce_tweak: [u8; 8] = (i as u64).to_le_bytes();
            let mut entry_nonce = [0u8; 16];
            entry_nonce[..8].copy_from_slice(&nonce_prefix[..8]);
            entry_nonce[8..].copy_from_slice(&nonce_tweak);

            crypt_stream(&enc_key.0, &entry_nonce, 0, &mut payload);

            let entry_mac = hmac_sha256(mac_key.as_slice(), &payload);
            let offset = out.len() as u64;
            let encrypted_size = payload.len() as u64;

            out.extend_from_slice(&payload);

            entries.push(ProtectedEntry {
                rel_path: rel_path.clone(),
                uncompressed_size,
                encrypted_size,
                offset,
                sha256: sha256_digest,
                compression,
                nonce_tweak,
                entry_mac,
            });
        }

        // Serialize and Encrypt Directory Index Table
        let idx_offset = out.len() as u64;
        let mut raw_idx = Vec::new();
        raw_idx.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for e in &entries {
            let p_bytes = e.rel_path.as_bytes();
            raw_idx.extend_from_slice(&(p_bytes.len() as u16).to_le_bytes());
            raw_idx.extend_from_slice(p_bytes);
            raw_idx.extend_from_slice(&e.uncompressed_size.to_le_bytes());
            raw_idx.extend_from_slice(&e.encrypted_size.to_le_bytes());
            raw_idx.extend_from_slice(&e.offset.to_le_bytes());
            raw_idx.extend_from_slice(&e.sha256);
            raw_idx.push(e.compression);
            raw_idx.extend_from_slice(&e.nonce_tweak);
            raw_idx.extend_from_slice(&e.entry_mac);
        }

        let mut idx_nonce = [0u8; 16];
        idx_nonce[..8].copy_from_slice(&master_nonce[..8]);
        idx_nonce[8..].copy_from_slice(b"DIRINDEX");
        crypt_stream(&enc_key.0, &idx_nonce, 0, &mut raw_idx);

        let idx_mac = hmac_sha256(mac_key.as_slice(), &raw_idx);
        let idx_len = raw_idx.len() as u32;
        out.extend_from_slice(&raw_idx);

        // Fill index metadata in header
        let mut meta = [0u8; 48];
        meta[..8].copy_from_slice(&idx_offset.to_le_bytes());
        meta[8..12].copy_from_slice(&idx_len.to_le_bytes());
        meta[16..48].copy_from_slice(&idx_mac);

        out[meta_pos..meta_pos + 48].copy_from_slice(&meta);

        Ok(out)
    }

    /// Build container and save to file.
    pub fn build_to_file(&self, out_path: &Path, session_key: &[u8]) -> io::Result<()> {
        let bytes = self.build_to_bytes(session_key)?;
        std::fs::write(out_path, bytes)?;
        Ok(())
    }
}

fn normalize_vfs_path(rel: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in rel.split(['/', '\\']) {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c.to_string()),
        }
    }
    parts.join("/").to_lowercase()
}

// -------------------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watermark_encode_decode() {
        let mut wm = Watermark::new("STEAM_0:1:12345678", "MaxMustermann", 0x1337);
        wm.sign(b"master-server-secret");
        assert!(wm.verify(b"master-server-secret"));
        assert!(!wm.verify(b"wrong-secret"));

        let bytes = wm.encode();
        let decoded = Watermark::decode(&bytes).unwrap();
        assert_eq!(wm.account_id, decoded.account_id);
        assert_eq!(wm.owner_name, decoded.owner_name);
        assert_eq!(wm.session_id, decoded.session_id);
        assert!(decoded.verify(b"master-server-secret"));
    }

    #[test]
    fn test_protected_archive_roundtrip() {
        let key = b"my-ephemeral-session-key-32bytes";
        let mut builder = ProtectedArchiveBuilder::new();
        builder.set_watermark(Watermark::new("STEAM_1234", "Driver1", 42));
        builder.add_file("maps/Berlin/global.cfg", b"[map]\nname=Berlin\n".to_vec());
        builder.add_file("Vehicles/MAN_NL202/model/bus.o3d", vec![0x12, 0x34, 0x56, 0x78; 1000]);

        let bytes = builder.build_to_bytes(key).unwrap();
        let archive = ProtectedArchive::from_bytes("test.neoasset", Arc::new(bytes), key).unwrap();

        assert_eq!(archive.file_count(), 2);
        assert!(archive.watermark().is_some());
        assert_eq!(archive.watermark().unwrap().account_id, "STEAM_1234");

        let cfg = archive.read("maps/Berlin/global.cfg").unwrap();
        assert_eq!(cfg, b"[map]\nname=Berlin\n");

        let mesh = archive.read("Vehicles/MAN_NL202/model/bus.o3d").unwrap();
        assert_eq!(mesh.len(), 4000);
        assert_eq!(mesh[..4], [0x12, 0x34, 0x56, 0x78]);

        // Wrong key must fail
        let wrong_key = b"wrong-session-key-00000000000000";
        let wrong = ProtectedArchive::from_bytes("test.neoasset", Arc::new(builder.build_to_bytes(key).unwrap()), wrong_key);
        assert!(wrong.is_err());
    }
}
