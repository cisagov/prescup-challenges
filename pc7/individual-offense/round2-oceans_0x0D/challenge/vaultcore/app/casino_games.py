from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("vault.games")

RANKS = "23456789TJQKA"
SUITS = "CDHS"  # Clubs, Diamonds, Hearts, Spades


# -------------------------
# Helpers: cards/deck
# -------------------------

def new_deck(rng: random.Random) -> List[str]:
    deck = [r + s for r in RANKS for s in SUITS]
    rng.shuffle(deck)
    return deck

def card_rank(c: str) -> int:
    return RANKS.index(c[0]) + 2  # 2..14

def pretty_hand(hand: List[str]) -> str:
    return " ".join(hand)


# -------------------------
# Poker (5-card) evaluation
# -------------------------

POKER_HAND_NAMES = {
    9: "Royal Flush",
    8: "Straight Flush",
    7: "Four of a Kind",
    6: "Full House",
    5: "Flush",
    4: "Straight",
    3: "Three of a Kind",
    2: "Two Pair",
    1: "One Pair",
    0: "High Card",
}

def _is_straight(ranks: List[int]) -> Tuple[bool, int]:
    """Return (is_straight, high_card). Handles wheel A-2-3-4-5."""
    uniq = sorted(set(ranks))
    if len(uniq) != 5:
        return (False, 0)
    # wheel: A,2,3,4,5
    if uniq == [2, 3, 4, 5, 14]:
        return (True, 5)
    if max(uniq) - min(uniq) == 4:
        return (True, max(uniq))
    return (False, 0)

def evaluate_5card(hand: List[str]) -> Tuple[int, Tuple[int, ...], str]:
    """
    Returns:
      (category, tiebreak_tuple, name)
    category: 0..9 (higher is better)
    tiebreak_tuple: lexicographic compare for winner resolution
    """
    ranks = [card_rank(c) for c in hand]
    suits = [c[1] for c in hand]
    ranks_sorted = sorted(ranks, reverse=True)

    # counts of ranks
    counts: Dict[int, int] = {}
    for r in ranks:
        counts[r] = counts.get(r, 0) + 1
    # sort by (count desc, rank desc)
    groups = sorted(((cnt, r) for r, cnt in counts.items()), reverse=True)

    is_flush = (len(set(suits)) == 1)
    is_str, straight_high = _is_straight(ranks)

    # Straight flush / Royal flush
    if is_flush and is_str:
        if straight_high == 14:  # A-high straight
            return (9, (14,), POKER_HAND_NAMES[9])
        return (8, (straight_high,), POKER_HAND_NAMES[8])

    # Four of a kind
    if groups[0][0] == 4:
        four_rank = groups[0][1]
        kicker = max(r for r in ranks if r != four_rank)
        return (7, (four_rank, kicker), POKER_HAND_NAMES[7])

    # Full house
    if groups[0][0] == 3 and groups[1][0] == 2:
        trips = groups[0][1]
        pair = groups[1][1]
        return (6, (trips, pair), POKER_HAND_NAMES[6])

    # Flush
    if is_flush:
        return (5, tuple(ranks_sorted), POKER_HAND_NAMES[5])

    # Straight
    if is_str:
        return (4, (straight_high,), POKER_HAND_NAMES[4])

    # Three of a kind
    if groups[0][0] == 3:
        trips = groups[0][1]
        kickers = sorted((r for r in ranks if r != trips), reverse=True)
        return (3, (trips, *kickers), POKER_HAND_NAMES[3])

    # Two pair
    if groups[0][0] == 2 and groups[1][0] == 2:
        high_pair = max(groups[0][1], groups[1][1])
        low_pair = min(groups[0][1], groups[1][1])
        kicker = max(r for r in ranks if r not in (high_pair, low_pair))
        return (2, (high_pair, low_pair, kicker), POKER_HAND_NAMES[2])

    # One pair
    if groups[0][0] == 2:
        pair = groups[0][1]
        kickers = sorted((r for r in ranks if r != pair), reverse=True)
        return (1, (pair, *kickers), POKER_HAND_NAMES[1])

    # High card
    return (0, tuple(ranks_sorted), POKER_HAND_NAMES[0])

def deal_poker_table(rng: random.Random, table_id: int) -> dict:
    """
    5 players, unique 5-card hands from a single deck.
    Returns a JSON-ready dict with winner + hand type.
    """
    deck = new_deck(rng)
    players = []
    evaluations = []

    for i in range(5):
        hand = [deck.pop() for _ in range(5)]
        cat, tb, name = evaluate_5card(hand)
        player = {
            "seat": i + 1,
            "name": f"Player_{i+1}",
            "hand": hand,
            "hand_pretty": pretty_hand(hand),
            "hand_type": name,
        }
        players.append(player)
        evaluations.append((cat, tb, i))

    # Determine winner (highest category then tiebreak)
    evaluations.sort(reverse=True)
    best_cat, best_tb, winner_idx = evaluations[0]
    winner = players[winner_idx]

    return {
        "game": "poker",
        "table_id": table_id,
        "ts": int(time.time() * 1000),
        "players": players,
        "winner": {
            "seat": winner["seat"],
            "name": winner["name"],
            "hand_type": winner["hand_type"],
        },
    }


# -------------------------
# Blackjack
# -------------------------

def _bj_value(cards: List[str]) -> int:
    """Standard blackjack: A is 11 or 1; face cards 10."""
    vals = []
    for c in cards:
        r = c[0]
        if r in "TJQK":
            vals.append(10)
        elif r == "A":
            vals.append(11)
        else:
            vals.append(int(r))
    total = sum(vals)
    # adjust aces
    aces = sum(1 for c in cards if c[0] == "A")
    while total > 21 and aces > 0:
        total -= 10
        aces -= 1
    return total

def deal_blackjack_round(rng: random.Random, round_id: int) -> dict:
    deck = new_deck(rng)

    # Random bet sizes (CTF vibe: plausible chips)
    bet = rng.choice([10, 25, 50, 75, 100, 150, 200, 250])

    player = [deck.pop(), deck.pop()]
    dealer = [deck.pop(), deck.pop()]

    # Player strategy (simple): hit until 17+
    while _bj_value(player) < 17:
        player.append(deck.pop())
        if _bj_value(player) > 21:
            break

    # Dealer rule: hit until 17+
    while _bj_value(dealer) < 17:
        dealer.append(deck.pop())
        if _bj_value(dealer) > 21:
            break

    p_val = _bj_value(player)
    d_val = _bj_value(dealer)

    if p_val > 21:
        outcome = "lose"
    elif d_val > 21:
        outcome = "win"
    elif p_val > d_val:
        outcome = "win"
    elif p_val < d_val:
        outcome = "lose"
    else:
        outcome = "push"

    # payout: win = +bet, lose = -bet, push = 0
    net = bet if outcome == "win" else (-bet if outcome == "lose" else 0)

    return {
        "game": "blackjack",
        "round_id": round_id,
        "ts": int(time.time() * 1000),
        "bet": bet,
        "player": {"hand": player, "value": p_val},
        "dealer": {"hand": dealer, "value": d_val},
        "outcome": outcome,
        "net": net,
    }


# -------------------------
# Slots
# -------------------------

SLOT_GAMES = ["Dragon Linx", "Casino Royale", "Buffalo Soldier"]

# Simple symbol sets per theme (kept lightweight but believable)
SLOT_SYMBOLS = {
    "Dragon Linx": ["DRG", "FLM", "ORB", "COIN", "WILD"],
    "Casino Royale": ["7", "BAR", "CHERRY", "DIAMOND", "WILD"],
    "Buffalo Soldier": ["BUF", "EAGLE", "SUN", "TOTEM", "WILD"],
}

def slot_spin(rng: random.Random, game: str, state_id: int) -> dict:
    bet = rng.choice([0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0])
    reels = [rng.choice(SLOT_SYMBOLS[game]) for _ in range(3)]

    # Simple win rule:
    # - 3 of a kind => big win
    # - 2 of a kind or any WILD => small win
    # - else => loss
    win = False
    payout_mult = 0.0

    if reels[0] == reels[1] == reels[2]:
        win = True
        payout_mult = 20.0 if reels[0] != "WILD" else 40.0
    elif len(set(reels)) == 2 or "WILD" in reels:
        win = True
        payout_mult = 2.0
    else:
        win = False
        payout_mult = 0.0

    payout = round(bet * payout_mult, 2)
    net = round(payout - bet, 2)

    return {
        "game": "slots",
        "machine_state_id": state_id,
        "ts": int(time.time() * 1000),
        "slot_theme": game,
        "bet": bet,
        "reels": reels,
        "win": win,
        "payout": payout,
        "net": net,
    }


# -------------------------
# Async emitter (MQTT integration)
# -------------------------

class CasinoGamesEmitter:
    """
    Production-oriented game telemetry emitter.
    Publish cadence:
      - poker: every ~15s
      - blackjack: every ~5s
      - slots: every ~1.2s (rotating themes with state_id)
    """

    def __init__(self, mqtt, seed: bytes, enable: bool = True):
        self.mqtt = mqtt  # expects publish_json(suffix, obj, retain=?, qos=?)
        self.enable = enable

        # deterministic-ish RNG per instance: good for debugging + fairness
        seed_int = int.from_bytes(seed[:8], "big", signed=False) ^ int(time.time())
        self.rng = random.Random(seed_int)

        self._task: Optional[asyncio.Task] = None
        self._poker_id = 1000
        self._bj_id = 5000
        self._slot_state = 900000

    async def start(self) -> None:
        if not self.enable or self._task:
            return
        self._task = asyncio.create_task(self._run_supervised(), name="casino_games")

    async def _run_supervised(self) -> None:
        while True:
            try:
                await asyncio.gather(
                    self._poker_loop(),
                    self._blackjack_loop(),
                    self._slots_loop(),
                )
            except Exception:
                log.exception("casino_games_emitter_crashed_restart")
                await asyncio.sleep(2)

    async def _poker_loop(self) -> None:
        while True:
            self._poker_id += 1
            payload = deal_poker_table(self.rng, self._poker_id)
            await self.mqtt.publish_json("telemetry/poker/table", payload, retain=False)
            await asyncio.sleep(15.0)

    async def _blackjack_loop(self) -> None:
        while True:
            self._bj_id += 1
            payload = deal_blackjack_round(self.rng, self._bj_id)
            await self.mqtt.publish_json("telemetry/blackjack/round", payload, retain=False)
            await asyncio.sleep(5.0)

    async def _slots_loop(self) -> None:
        game_idx = 0
        while True:
            self._slot_state += 1
            game = SLOT_GAMES[game_idx % len(SLOT_GAMES)]
            game_idx += 1
            payload = slot_spin(self.rng, game, self._slot_state)
            await self.mqtt.publish_json("telemetry/slots/spin", payload, retain=False)
            await asyncio.sleep(1.2)

