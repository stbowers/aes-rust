use std::convert::TryInto;

// AES data types
type Word = [u8; 4]; // A word is 4 bytes (32 bits)
type Block = [Word; 4]; // A block is 4 words (16 bytes)

// The plaintext to encrypt
// static PLAINTEXT: u128 = 0x0123456789abcdeffedcba9876543210;
static PLAINTEXT: u128 = 0x00112233445566778899aabbccddeeff;

// The key to use
//static KEY: u128       = 0x0f1571c947d9e8590cb7add6af7f6798;
static KEY: u128       = 0x000102030405060708090a0b0c0d0e0f;

// Round constant used in the key expantion algorithm
static RCON: [Word; 10] = [
    word_from_u32(0x00000001),
    word_from_u32(0x00000002),
    word_from_u32(0x00000004),
    word_from_u32(0x00000008),
    word_from_u32(0x00000010),
    word_from_u32(0x00000020),
    word_from_u32(0x00000040),
    word_from_u32(0x00000080),
    word_from_u32(0x0000001B),
    word_from_u32(0x00000036),
];

// Substitution box (S-Box)
static SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

const fn word_from_u32(value: u32) -> Word {
    return [
        ((value >> 0  ) & 0xff) as u8,
        ((value >> 8  ) & 0xff) as u8,
        ((value >> 16 ) & 0xff) as u8,
        ((value >> 24 ) & 0xff) as u8,
    ];
}

fn u128_to_byte_array(value: u128) -> [u8; 16] {
    return [
        ((value >> 0  ) & 0xff) as u8,
        ((value >> 8  ) & 0xff) as u8,
        ((value >> 16 ) & 0xff) as u8,
        ((value >> 24 ) & 0xff) as u8,
        ((value >> 32 ) & 0xff) as u8,
        ((value >> 40 ) & 0xff) as u8,
        ((value >> 48 ) & 0xff) as u8,
        ((value >> 56 ) & 0xff) as u8,
        ((value >> 64 ) & 0xff) as u8,
        ((value >> 72 ) & 0xff) as u8,
        ((value >> 80 ) & 0xff) as u8,
        ((value >> 88 ) & 0xff) as u8,
        ((value >> 96 ) & 0xff) as u8,
        ((value >> 104) & 0xff) as u8,
        ((value >> 112) & 0xff) as u8,
        ((value >> 120) & 0xff) as u8,
    ];
}

fn block_from_byte_array(array: &[u8; 16]) -> Block {
    return [
        [array[0], array[4], array[8] , array[12]],
        [array[1], array[5], array[9] , array[13]],
        [array[2], array[6], array[10], array[14]],
        [array[3], array[7], array[11], array[15]],
    ];
}

fn block_from_u128(value: u128) -> Block {
    return block_from_byte_array(&u128_to_byte_array(value));
}

fn u32_from_word(word: &Word) -> u32 {
    return ( 0
           | (word[0] as u32) << 0
           | (word[1] as u32) << 8
           | (word[2] as u32) << 16
           | (word[3] as u32) << 24
    );
}

fn u128_from_block(block: &Block) -> u128 {
    return ( 0
           | (block[0][0] as u128) << 0
           | (block[1][0] as u128) << 8
           | (block[2][0] as u128) << 16
           | (block[3][0] as u128) << 24
           | (block[0][1] as u128) << 32
           | (block[1][1] as u128) << 40
           | (block[2][1] as u128) << 48
           | (block[3][1] as u128) << 56
           | (block[0][2] as u128) << 64
           | (block[1][2] as u128) << 72
           | (block[2][2] as u128) << 80
           | (block[3][2] as u128) << 88
           | (block[0][3] as u128) << 96
           | (block[1][3] as u128) << 104
           | (block[2][3] as u128) << 112
           | (block[3][3] as u128) << 120
    );
}

fn block_from_word_columns(words: &[Word; 4]) -> Block {
    return [
        [words[0][0], words[1][0], words[2][0], words[3][0]],
        [words[0][1], words[1][1], words[2][1], words[3][1]],
        [words[0][2], words[1][2], words[2][2], words[3][2]],
        [words[0][3], words[1][3], words[2][3], words[3][3]],
    ];
}

fn block_from_word_rows(words: &[Word; 4]) -> Block {
    return [
        [words[0][0], words[0][1], words[0][2], words[0][3]],
        [words[1][0], words[1][1], words[1][2], words[1][3]],
        [words[2][0], words[2][1], words[2][2], words[2][3]],
        [words[3][0], words[3][1], words[3][2], words[3][3]],
    ];
}

// Perform the s-box substitution
fn sub_byte(value: u8) -> u8 {
    return SBOX[value as usize];
}

// Perform the s-box substitution on each byte in the word
fn sub_word(word: &Word) -> Word {
    return [
        sub_byte(word[0]),
        sub_byte(word[1]),
        sub_byte(word[2]),
        sub_byte(word[3]),
    ];
}

// Perform s-box substitution on every byte in the block
fn sub_block(block: &Block) -> Block {
    return [
        sub_word(&block[0]),
        sub_word(&block[1]),
        sub_word(&block[2]),
        sub_word(&block[3]),
    ];
}

fn rot_word(word: &Word) -> Word {
    return [
        word[1],
        word[2],
        word[3],
        word[0],
    ];
}

// Rotates the word n times (left shift where the leftmost byte goes to the right)
fn shift_word(word: &Word, n: usize) -> Word {
    return [
        word[(n + 0) % 4],
        word[(n + 1) % 4],
        word[(n + 2) % 4],
        word[(n + 3) % 4],
    ];
}

fn xor_word(a: &Word, b: &Word) -> Word {
    return [
        a[0] ^ b[0],
        a[1] ^ b[1],
        a[2] ^ b[2],
        a[3] ^ b[3],
    ];
}

fn xor_block(a: &Block, b: &Block) -> Block {
    return [
        xor_word(&a[0], &b[0]),
        xor_word(&a[1], &b[1]),
        xor_word(&a[2], &b[2]),
        xor_word(&a[3], &b[3]),
    ];
}

fn multiply_byte(x: u8, y: u8) -> u8 {
    let mut a = x;
    let mut b = y;
    let mut result = 0;

    for i in 0..8 {
        if (0b00000001 & b) > 0 {
            result = result ^ a;
        }
        b = b >> 1;
        let msb = 0b10000000 & a;
        a = a << 1;
        if msb > 0 {
            a = a ^ 0b00011011;
        }
    }

    return result;
}

// Takes a 16 byte input key and expands it in to 44 words (176 bytes), organized into an array of 11 16-byte words (the round keys)
fn expand_key(key: Block) -> [Word; 44] {
    println!("=== Key Expantion ===");

    // Initialize the word array
    let mut words: [Word; 44] = [[0; 4]; 44];

    // Copy the key into the first 4 words
    words[0] = [key[3][3], key[2][3], key[1][3], key[0][3]];
    words[1] = [key[3][2], key[2][2], key[1][2], key[0][2]];
    words[2] = [key[3][1], key[2][1], key[1][1], key[0][1]];
    words[3] = [key[3][0], key[2][0], key[1][0], key[0][0]];

    println!("w0 = {:02x?}", words[0]);
    println!("w1 = {:02x?}", words[1]);
    println!("w2 = {:02x?}", words[2]);
    println!("w3 = {:02x?}", words[3]);

    // Calculate each subsequent word
    for i in 1..11 {
        let tmp = words[(4*i)-1];
        let rot = rot_word(&tmp);
        let sub = sub_word(&rot);
        let rcon = RCON[i - 1];
        let xor = xor_word(&sub, &rcon);

        println!("RotWord (w{}) = {:02x?} = x{}", (4*i) - 1, rot, i);
        println!("SubWord (x{}) = {:02x?} = y{}", i, sub, i);
        println!("Rcon ({}) = {:02x?}", i, rcon);
        println!("y{} ^ rcon ({}) = {:02x?} = z{}", i, i, xor, i);
        
        words[(4*i) + 0] = xor_word(&words[(4*i) - 4], &xor);
        words[(4*i) + 1] = xor_word(&words[(4*i) - 3], &words[(4*i) + 0]);
        words[(4*i) + 2] = xor_word(&words[(4*i) - 2], &words[(4*i) + 1]);
        words[(4*i) + 3] = xor_word(&words[(4*i) - 1], &words[(4*i) + 2]);
        println!("w{} = w{} ^ z{} = {:02x?}", (4*i) + 0, (4*i) - 4, i        ,  words[(4*i) + 0]);
        println!("w{} = w{} ^ w{} = {:02x?}", (4*i) + 1, (4*i) - 3, (4*i) + 0,  words[(4*i) + 1]);
        println!("w{} = w{} ^ w{} = {:02x?}", (4*i) + 2, (4*i) - 2, (4*i) + 1,  words[(4*i) + 2]);
        println!("w{} = w{} ^ w{} = {:02x?}", (4*i) + 3, (4*i) - 1, (4*i) + 2,  words[(4*i) + 3]);
    }

    return words;
}

fn add_round_key(input: &Block, round_key: &Block) -> Block {
    return xor_block(input, round_key);
}

// Shifts each "row" of the block by it's index, i.e.
// row 0 => shift left by 0
// row 1 => shift left by 1
// row 2 => shift left by 2
// row 3 => shift left by 3
fn shift_rows(block: &Block) -> Block {
    return [
        shift_word(&block[0], 0),
        shift_word(&block[1], 1),
        shift_word(&block[2], 2),
        shift_word(&block[3], 3),
    ];
}

/// Performs the MixColumns transformation to the block.
/// This is done by multiplying each column of the block by the MixColumns matrix (MIX_COLUMNS)
fn mix_columns(block: &Block) -> Block {
    let mut new_block = [[0; 4]; 4];

    for col in 0..4 {
        // Create the column
        let column = [
            block[0][col],
            block[1][col],
            block[2][col],
            block[3][col],
        ];

        // Multiply by matrix (inlined, using equations from ch 6.3)
        let new_column = [
            (multiply_byte(column[0], 2)) ^ (multiply_byte(column[1], 3)) ^ (multiply_byte(column[2], 1)) ^ (multiply_byte(column[3], 1)),
            (multiply_byte(column[0], 1)) ^ (multiply_byte(column[1], 2)) ^ (multiply_byte(column[2], 3)) ^ (multiply_byte(column[3], 1)),
            (multiply_byte(column[0], 1)) ^ (multiply_byte(column[1], 1)) ^ (multiply_byte(column[2], 2)) ^ (multiply_byte(column[3], 3)),
            (multiply_byte(column[0], 3)) ^ (multiply_byte(column[1], 1)) ^ (multiply_byte(column[2], 1)) ^ (multiply_byte(column[3], 2)),
        ];

        // Insert into block
        new_block[0][col] = new_column[0];
        new_block[1][col] = new_column[1];
        new_block[2][col] = new_column[2];
        new_block[3][col] = new_column[3];
    }

    return new_block;
}

fn print_block(block: &Block) {
    println!("0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}", block[0][0], block[0][1], block[0][2], block[0][3]);
    println!("0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}", block[1][0], block[1][1], block[1][2], block[1][3]);
    println!("0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}", block[2][0], block[2][1], block[2][2], block[2][3]);
    println!("0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}", block[3][0], block[3][1], block[3][2], block[3][3]);
}

fn main() {
    println!("===== AES Ecryption =====");
    println!("Plaintext:  0x{:032x}", PLAINTEXT);
    println!("Key:        0x{:032x}", KEY);

    let mut state = block_from_u128(PLAINTEXT);

    //let round_keys: [Word; 44] = expand_key(block_from_u128(0xEAD27321B58DBAD2312BF5607F8D292F));
    //let round_keys: [Word; 44] = expand_key(block_from_u128(0x2f60d22129f5ba738d2b8dd27f31b5ea));
    let round_keys: [Word; 44] = expand_key(block_from_u128(KEY));
    let mut round_key = block_from_word_columns(&round_keys[0..4].try_into().unwrap());

    // Initial transformation
    println!("R{} (key = 0x{:032x})", 0, u128_from_block(&round_key));
    state = add_round_key(&state, &round_key);
    println!("=> 0x{:032x}", u128_from_block(&state));

    // Round transformations
    for round in 1..11 {
        let mut round_key = block_from_word_columns(&round_keys[(4*round)..(4*round)+4].try_into().unwrap());
        println!("R{} (key = 0x{:032x})", round, u128_from_block(&round_key));

        // Substitute bytes
        state = sub_block(&state);

        // Shift rows
        state = shift_rows(&state);

        // Mix columns
        state = mix_columns(&state);

        // Add round key
        state = add_round_key(&state, &round_keys[(4*round)..(4*round)+4].try_into().unwrap());

        println!("=> 0x{:032x}", u128_from_block(&state));
    }

    println!("Ciphertext: 0x{:032x}", u128_from_block(&state));

    // test mix columns
    let test_in = block_from_u128(0xc5ad2df0b098335c965d4583856504ea);
    let test_sub = sub_block(&test_in);
    let test_shift = shift_rows(&test_sub);
    let test_mix = mix_columns(&test_shift);
    println!("In:");
    print_block(&test_in);
    println!("Sub:");
    print_block(&test_sub);
    println!("Shift:");
    print_block(&test_shift);
    println!("Mix:");
    print_block(&test_mix);
}
