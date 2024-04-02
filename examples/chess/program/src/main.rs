#![no_main]
wp1_zkvm::entrypoint!(main);

use chess::{Board, ChessMove};
use std::str::FromStr;

pub fn main() {
    // Read the board position in Forsyth-Edwards Notation (FEN), and a move in Standard Algebraic Notation (SAN)
    let fen = wp1_zkvm::io::read::<String>();
    let san = wp1_zkvm::io::read::<String>();

    // Generate the chessboard from the FEN input
    let b = Board::from_str(&fen).expect("valid FEN board");

    // Try to parse the SAN as a legal chess move
    let is_valid_move = ChessMove::from_san(&b, &san).is_ok();

    // Write whether or not the move is legal
    wp1_zkvm::io::commit(&is_valid_move);
}
