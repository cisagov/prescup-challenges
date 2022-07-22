/*
President's Cup Cybersecurity Competition 2019 Challenges

Copyright 2020 Carnegie Mellon University.

NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
TRADEMARK, OR COPYRIGHT INFRINGEMENT.

Released under a MIT (SEI)-style license, please see license.txt or
contact permission@sei.cmu.edu for full terms.

[DISTRIBUTION STATEMENT A] This material has been approved for public
release and unlimited distribution.  Please see Copyright notice for
non-US Government use and distribution.

DM20-0347
*/

pub const RESET_OPCODE: u8 = 1 << 0;
pub const INDEX_OPCODE: u8 = 1 << 1;
pub const TRAVEL_OPCODE: u8 = 1 << 2;
pub const BUY_OPCODE: u8 = 1 << 3;
pub const SELL_OPCODE: u8 = 1 << 4;
pub const LIST_GOODS_OPCODE: u8 = 1 << 5;
pub const QUERY_STATE_OPCODE: u8 = 1 << 6;

// DATA CONVENTION IS LITTLE ENDIAN

pub fn serialize_transaction(item_id: u8, quantity: u64, buffer: &mut Vec<u8>) {
    buffer.push(item_id);
    buffer.extend(quantity.to_le_bytes().iter());
}
