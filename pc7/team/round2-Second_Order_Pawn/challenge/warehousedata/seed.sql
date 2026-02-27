INSERT INTO secondOrderWarehouse.items (id, name, description, dropped_off, drop_off_date, user_id) VALUES
(1, 'Antique Betsy Ross Flag', 'An authentic 13-star flag, flown on family farm around 1780. Includes document of authenticity.', 1, TIMESTAMPADD(SECOND, -FLOOR(5*86400 + RAND(1)*2*86400), NOW()), 2),
(2, 'Antique Flintlock Musket', 'French Charleville 1763 musket, used by ancestor in Revolutionary war. Includes document of authenticity, paper cartridges, and detached bayonet.', 1, TIMESTAMPADD(SECOND, -FLOOR(5*86400 + RAND(2)*2*86400), NOW()), 2),
(3, 'The Hacker Files', 'All twelve issues of The Hacker Series, a mini-series written by Lewis Shiner, illustrated by Tom Sutton, and published by DC Comics from August 1992 to July 1993. Cover to Hacker Files No. 2 shown.', 1, TIMESTAMPADD(SECOND, -FLOOR(5*86400 + RAND(3)*2*86400), NOW()), 3),
(4, 'Captain Crunch Whistle', 'Used by Phone Phreaks in the 70s to play certain control tones into the analog phone system.', 1, TIMESTAMPADD(SECOND, -FLOOR(5*86400 + RAND(4)*2*86400), NOW()), 3),
(5, 'DEF CON 27 (2019) badge', 'Electronic badge from DEF CON 27. White general attendance badge featuring a modular design, interactive puzzles, and embedded challenges. Includes original lanyard.', 1, TIMESTAMPADD(SECOND, -FLOOR(5*86400 + RAND(5)*2*86400), NOW()), 3),
(6, 'Corgi with Crown Collar', 'To whom it may concern, I won this lovely corgi statue from the Queen Elizabeth collection from the local knitting competition for "loveliest sweater". While I adore it very much, my grandson will be going to college soon, and I would like to help him along. If you think this will make a great fit in your home, please consider helping my grandson! Sincerely, Ethel', 1, DATE(TIMESTAMPADD(SECOND, -FLOOR(5*86400 + RAND(6)*2*86400), NOW())), 4),
(7, 'Collectible Giant Stuffed Dragon', 'A giant dragon stuffed animal, lightly used. Part of a collectible set.', 1, TIMESTAMPADD(SECOND, -FLOOR(5*86400 + RAND(7)*2*86400), NOW()), 5),
(8, 'D&D The Keep on the Borderlands', 'A heavily used, but intact, copy of "The Keep on the Borderlands" from 1980 for the first edition of Dungeons and Dragons.', 1, TIMESTAMPADD(SECOND, -FLOOR(5*86400 + RAND(8)*2*86400), NOW()), 5)
;

INSERT INTO secondOrderWarehouse.documents (id, item_id, filename, description, metadata) VALUES
(1, 1, 'Betsy_Ross_Flag_Certificate.pdf', 'Authenticity document for Betsy Ross Flag.', NULL),
(2, 1, 'flag.jpg', 'Image of Betsy Ross Flag',
    'X-CoverImage-Make,Canon,X-CoverImage-Model,EOS 5D,X-CoverImage-DateTimeOriginal,2023:07:04 15:30:00,X-CoverImage-Software,Photoshop 24.1'),
(3, 2, 'Charleville_Musket_Certificate.pdf', 'Authenticity document for Musket.', NULL),
(4, 2, 'musket.jpg', 'Image of Musket',
    'X-CoverImage-Make,Nikon,X-CoverImage-Model,D3500,X-CoverImage-DateTimeOriginal,2022:11:10 08:12:00,X-CoverImage-Software,Lightroom 12.1'),
(5, 3, 'HackerFiles.jpg', 'Hacker Files No. 2 Cover',
    'X-CoverImage-Make,Sony,X-CoverImage-Model,Alpha 7 III,X-CoverImage-DateTimeOriginal,2021:09:18 12:00:00'),
(6, 4, 'whistle.jpg', 'Captain Crunch whistle',
    'X-CoverImage-Make,Apple,X-CoverImage-Model,iPhone 12,X-CoverImage-DateTimeOriginal,2023:04:02 16:45:00'),
(7, 5, 'badge.png', 'DEF CON 27 badge',
    'X-CoverImage-Make,Google,X-CoverImage-Model,Pixel 4a,X-CoverImage-DateTimeOriginal,2019:08:09 10:45:00'),
(8, 6, 'corgi.jpg', 'Corgi statue',
    'X-CoverImage-Make,Canon,X-CoverImage-Model,PowerShot G7 X,X-CoverImage-ImageDescription,Ceramic corgi statue'),
(9, 6, 'MeAndMaxPark2015.png', 'My Grandson and I',
    'X-CoverImage-Make,Apple,X-CoverImage-Model,iPhone 5,X-CoverImage-DateTimeOriginal,2015:05:21 14:05:00'),
(10, 7, 'dragon.webp', 'Image of the Stuffed Dragon',
    'X-CoverImage-Make,Samsung,X-CoverImage-Model,Galaxy S10,X-CoverImage-ImageDescription,Plush red dragon toy'),
(11, 8, 'KeepFrontCover.webp', 'Front cover of book',
    'X-CoverImage-Make,Epson,X-CoverImage-Model,Perfection V600,X-CoverImage-DateTimeOriginal,2020:02:01 09:00:00'),
(12, 8, 'KeepBackCover.webp', 'Back of book',
    'X-CoverImage-Make,Epson,X-CoverImage-Model,Perfection V600'),
(13, 8, 'KeepMap.webp', 'Inside of cover, with map',
    'X-CoverImage-Make,Epson,X-CoverImage-Model,Perfection V600,X-CoverImage-ImageDescription,Illustrated map')
;



