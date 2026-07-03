# ---------------------------------------------------------------------------
# Protocol constants
# All values are as specified in the PBT design notes.
# ---------------------------------------------------------------------------

# Storage-type subtree IDs
HEADER_SUBTREE: int = 0
CODE_SUBTREE: int = 1
METADATA_SUBTREE: int = 254
STORAGE_SUBTREE: int = 255

# Leaf key indices within the header stem
BASIC_DATA_LEAF_KEY: int = 0
CODE_HASH_LEAF_KEY: int = 1

# Offset within the header stem where storage slots begin
HEADER_STORAGE_OFFSET: int = 20

# Offset within the header stem where code chunks begin
CODE_OFFSET: int = 4

# Number of code chunks that are co-located in the header stem
CODE_CHUNKS_IN_HEADER: int = 16

# Number of storage slots that are co-located in the header stem
STORAGE_CHUNKS_IN_HEADER: int = 4

# Width of a single stem (number of leaf slots per stem)
STEM_SUBTREE_WIDTH: int = 256

# Reserved metadata leaf indices in the header stem.
METADATA_EXPIRY_EPOCH_SUBINDEX: int = 240
METADATA_HOT_COLD_SUBINDEX: int = 241
METADATA_ARCHIVAL_TIER_SUBINDEX: int = 242
METADATA_FLAGS_SUBINDEX: int = 243

# First subindex for overflow storage stems (256^31, i.e. 256**31)
MAIN_STORAGE_OFFSET: int = STEM_SUBTREE_WIDTH ** 31

# Sentinel value for an empty leaf slot (32 zero bytes)
EMPTY_VALUE: bytes = b"\x00" * 32

# ---------------------------------------------------------------------------
# Invariant assertions (checked once at import time)
# ---------------------------------------------------------------------------
assert STEM_SUBTREE_WIDTH > HEADER_STORAGE_OFFSET > CODE_OFFSET > CODE_HASH_LEAF_KEY, (
    "Required ordering: "
    "STEM_SUBTREE_WIDTH > HEADER_STORAGE_OFFSET > CODE_OFFSET > CODE_HASH_LEAF_KEY"
)
assert MAIN_STORAGE_OFFSET == STEM_SUBTREE_WIDTH ** 31, (
    "MAIN_STORAGE_OFFSET must be a power of STEM_SUBTREE_WIDTH"
)
assert len({HEADER_SUBTREE, CODE_SUBTREE, METADATA_SUBTREE, STORAGE_SUBTREE}) == 4, (
    "Subtree identifiers must be unique"
)
