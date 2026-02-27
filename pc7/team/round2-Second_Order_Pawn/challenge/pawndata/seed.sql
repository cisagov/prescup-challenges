INSERT INTO pawn (id, name, description, price, image, category, item_condition, listed_on) VALUES
(1, 'Vintage Watch', 'A classic 1960s timepiece with a leather strap.', 120, 'vintage_watch.jpg', 'Accessories', 'Good', DATE(TIMESTAMPADD(SECOND, -FLOOR(86400 + RAND(1)*6*86400), NOW()))),
(2, 'Electric Guitar', 'Gloss black Strat-style guitar, barely used.', 250, 'electric_guitar.png', 'Instruments', 'Very Good', DATE(TIMESTAMPADD(SECOND, -FLOOR(86400 + RAND(2)*6*86400), NOW()))),
(3, 'Mountain Bike', '21-speed aluminum frame with front suspension.', 180, 'mountain_bike.jpg', 'Sporting Goods', 'Fair', DATE(TIMESTAMPADD(SECOND, -FLOOR(86400 + RAND(3)*6*86400), NOW()))),
(4, 'Gold Ring', '14k gold ring with small diamond centerpiece.', 400, 'gold_ring.jpg', 'Jewelry', 'Excellent', DATE(TIMESTAMPADD(SECOND, -FLOOR(86400 + RAND(4)*6*86400), NOW()))),
(5, 'DSLR Camera', 'Canon EOS Rebel T7 with 18-55mm lens.', 300, 'dslr_camera.jpg', 'Electronics', 'Very Good', DATE(TIMESTAMPADD(SECOND, -FLOOR(86400 + RAND(5)*6*86400), NOW())));

INSERT INTO users (id, role, username, password, last_login) VALUES
(1, 'admin', 'admin', 'scrypt:32768:8:1$kB0u4tcEVtfoXhpn$431114a400b22c8b57870695a5918b3e341763e440c637a31f643d27536856ed96117f94524fb731159373cbdace49c84a57ae1004070b15b7e290e408665577', TIMESTAMPADD(SECOND, -FLOOR(RAND(1)*86400), NOW())), -- 12If7tqNM@2WP#Hw
(2, 'user', 'jstevens', 'scrypt:32768:8:1$05g2Is5aMyQbghsu$deb81bf97e99bfed1fe91616c2034eaba90749e0b16bca3b901ac92daaf463be6421ea915d9556da453dde22c86497427b4af40cd334066894c6ba3e1f085232', TIMESTAMPADD(SECOND, -FLOOR(RAND(2)*86400), NOW())), -- q87%8NCT*xstHzXO
(3, 'user', 'quantumdrop', 'scrypt:32768:8:1$9x2LHRfdacXcTGOH$c63b402c12292894d0a3f2e4de996c663b7d029abf6c28c2740ccf44e11eb216a0a41bc3634c970138294a410880e47de92303438c2b2d75a6d27d1a640ee21c', TIMESTAMPADD(SECOND, -FLOOR(RAND(3)*86400), NOW())), -- I3CFqw5H%v$Apjy1
(4, 'user', 'IL0v3D0gs', 'scrypt:32768:8:1$2LUNx21xeL8M9r7c$880f214689a168089f73c4cce696269d0dab752e083a6ab1f0b22f6d9bd6df49cc8253372826ac9339ac375f25f155903f17ec4288ff5c44d777751e53a8c9dd', TIMESTAMPADD(SECOND, -FLOOR(RAND(4)*86400), NOW())), -- k4$luS0HKK7&3j4h
(5, 'user', 'AuctionKid', 'scrypt:32768:8:1$dbYyDJB3Aa7PZuJ3$d75b4e651e5ee22b12e1b4142231f93bc1971f449911e083636d2bd62684a6fb36b34fe59f3e80c7b748df723fc8a130ddfb970b766f1acea60043bdd803d46f', TIMESTAMPADD(SECOND, -FLOOR(RAND(5)*86400), NOW())), -- y83WuBaUk%Y3$OzP
(6, 'user', 'NotAFed', 'scrypt:32768:8:1$ez2AHPPQuBsOLbNq$680dce93a28c4b125a36c0eb71ccceee439a2dd6c9597d792431bdf8abbccd5b2f44fb778d177f4613bdff58c8a9fad4561a83487d3693b30cfcbe7f9b11d46a', TIMESTAMPADD(SECOND, -FLOOR(RAND(6)*86400), NOW())) -- v7#Bn0YC7oKtsiz&
;

INSERT INTO auctions (id, warehouse_id, user_id, public, open, starting_bid, end_date, winner, cover_image) VALUES
(1, 1, 2, 1, 0, 5000.00, TIMESTAMPADD(SECOND, FLOOR(1*86400 + RAND(1)*6*86400), NOW()), 6, 2),   -- Antique Betsy Ross Flag
(2, 2, 2, 1, 1, 1200.00, TIMESTAMPADD(SECOND, FLOOR(1*86400 + RAND(2)*6*86400), NOW()), NULL, 4),   -- Antique Flintlock Musket
(3, 3, 3, 1, 0, 60.00, TIMESTAMPADD(SECOND, FLOOR(1*86400 + RAND(3)*6*86400), NOW()), 5, 5),     -- The Hacker Files
(4, 4, 3, 1, 1, 75.00, TIMESTAMPADD(SECOND, FLOOR(1*86400 + RAND(4)*6*86400), NOW()), NULL, 6),     -- Captain Crunch Whistle
(5, 5, 3, 1, 1, 90.00, TIMESTAMPADD(SECOND, FLOOR(1*86400 + RAND(5)*6*86400), NOW()), NULL, 7),     -- DEF CON 27 Badge
(6, 6, 4, 1, 1, 35.00, TIMESTAMPADD(SECOND, FLOOR(1*86400 + RAND(6)*6*86400), NOW()), NULL, 8),     -- Corgi with Crown Collar
(7, 7, 5, 1, 1, 50.00, TIMESTAMPADD(SECOND, FLOOR(1*86400 + RAND(7)*6*86400), NOW()), NULL, 10),     -- Giant Stuffed Dragon
(8, 8, 5, 1, 1, 20.00, TIMESTAMPADD(SECOND, FLOOR(1*86400 + RAND(8)*6*86400), NOW()), NULL, 11)     -- D&D Borderlands
;

INSERT INTO bids (id, auction_id, user_id, bid, timestamp) VALUES
-- Auction 1: Flag (ends 2026-02-16 10:00:00)
(1, 1, 3, 5200.00, TIMESTAMPADD(SECOND, -FLOOR(4*86400 + RAND(1)*86400), NOW())),
(2, 1, 5, 5400.00, TIMESTAMPADD(SECOND, -FLOOR(3*86400 + RAND(2)*86400), NOW())),
(13, 1, 2, 5500.00, TIMESTAMPADD(SECOND, -FLOOR(2*86400 + RAND(13)*86400), NOW())),
(14, 1, 6, 5700.00, TIMESTAMPADD(SECOND, -FLOOR(1*86400 + RAND(14)*86400), NOW())),

-- Auction 2: Musket (ends 2026-02-20 16:00:00)
(3, 2, 4, 1250.00, TIMESTAMPADD(SECOND, -FLOOR(4*86400 + RAND(3)*86400), NOW())),
(4, 2, 5, 1350.00, TIMESTAMPADD(SECOND, -FLOOR(2*86400 + RAND(4)*86400), NOW())),
(15, 2, 2, 1400.00, TIMESTAMPADD(SECOND, -FLOOR(1*86400 + RAND(15)*86400), NOW())),

-- Auction 3: Hacker Files (ends 2026-02-15 15:00:00)
(5, 3, 2, 65.00, TIMESTAMPADD(SECOND, -FLOOR(4*86400 + RAND(5)*86400), NOW())),
(6, 3, 4, 75.00, TIMESTAMPADD(SECOND, -FLOOR(3*86400 + RAND(6)*86400), NOW())),
(16, 3, 5, 80.00, TIMESTAMPADD(SECOND, -FLOOR(2*86400 + RAND(16)*86400), NOW())),

-- Auction 4: Captain Crunch Whistle (ends 2026-02-19 11:30:00)
(7, 4, 5, 85.00, TIMESTAMPADD(SECOND, -FLOOR(1*86400 + RAND(7)*86400), NOW())),

-- Auction 5: DEF CON 27 Badge (ends 2026-02-21 14:45:00)
(8, 5, 2, 100.00, TIMESTAMPADD(SECOND, -FLOOR(3*86400 + RAND(8)*86400), NOW())),
(9, 5, 4, 115.00, TIMESTAMPADD(SECOND, -FLOOR(2*86400 + RAND(9)*86400), NOW())),
(17, 5, 3, 125.00, TIMESTAMPADD(SECOND, -FLOOR(1*86400 + RAND(17)*86400), NOW())),

-- Auction 6: Corgi Statue (ends 2026-02-23 18:00:00)
(10, 6, 3, 40.00, TIMESTAMPADD(SECOND, -FLOOR(2*86400 + RAND(10)*86400), NOW())),

-- Auction 7: Stuffed Dragon (ends 2026-02-24 09:00:00)
(11, 7, 4, 55.00, TIMESTAMPADD(SECOND, -FLOOR(4*86400 + RAND(11)*86400), NOW())),
(18, 7, 2, 60.00, TIMESTAMPADD(SECOND, -FLOOR(3*86400 + RAND(18)*86400), NOW())),
(19, 7, 3, 65.00, TIMESTAMPADD(SECOND, -FLOOR(1*86400 + RAND(19)*86400), NOW())),

-- Auction 8: D&D Module (ends 2026-02-17 13:00:00)
(12, 8, 2, 25.00, TIMESTAMPADD(SECOND, -FLOOR(4*86400 + RAND(12)*86400), NOW())),
(20, 8, 5, 28.00, TIMESTAMPADD(SECOND, -FLOOR(1*86400 + RAND(20)*86400), NOW()));
