-- MariaDB dump 10.19  Distrib 10.11.7-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: ecommerce
-- ------------------------------------------------------
-- Server version	10.11.7-MariaDB-4

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `order_details`
--

DROP TABLE IF EXISTS `order_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `order_details` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `order_id` int(11) DEFAULT NULL,
  `product_id` int(11) DEFAULT NULL,
  `quantity` int(11) DEFAULT NULL,
  `subtotal` decimal(10,2) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `order_id` (`order_id`),
  KEY `product_id` (`product_id`),
  CONSTRAINT `order_details_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`),
  CONSTRAINT `order_details_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `order_details`
--

LOCK TABLES `order_details` WRITE;
/*!40000 ALTER TABLE `order_details` DISABLE KEYS */;
INSERT INTO `order_details` VALUES
(1,20,102,1,NULL),
(2,20,109,1,NULL);
/*!40000 ALTER TABLE `order_details` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `orders`
--

DROP TABLE IF EXISTS `orders`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `orders` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `product_id` int(11) DEFAULT NULL,
  `quantity` int(11) DEFAULT NULL,
  `total` decimal(10,2) DEFAULT NULL,
  `order_date` timestamp NULL DEFAULT current_timestamp(),
  `payment_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `product_id` (`product_id`),
  KEY `payment_id` (`payment_id`),
  CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `orders_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`),
  CONSTRAINT `orders_ibfk_3` FOREIGN KEY (`payment_id`) REFERENCES `payments` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `orders`
--

LOCK TABLES `orders` WRITE;
/*!40000 ALTER TABLE `orders` DISABLE KEYS */;
INSERT INTO `orders` VALUES
(9,2,NULL,NULL,163.11,'2024-07-17 16:34:41',NULL),
(10,2,NULL,NULL,163.11,'2024-07-17 16:37:04',NULL),
(11,2,NULL,NULL,0.00,'2024-07-17 16:37:05',NULL),
(12,2,NULL,NULL,130.78,'2024-07-17 16:37:54',NULL),
(13,2,NULL,NULL,94.78,'2024-07-17 16:42:06',NULL),
(14,2,NULL,NULL,0.00,'2024-07-17 16:42:10',NULL),
(15,2,NULL,NULL,146.46,'2024-07-17 16:52:48',NULL),
(16,2,NULL,NULL,0.00,'2024-07-17 16:52:54',NULL),
(17,2,NULL,NULL,89.88,'2024-07-17 16:54:12',NULL),
(18,2,NULL,NULL,0.00,'2024-07-17 16:54:14',NULL),
(20,4,NULL,NULL,101.60,'2024-07-19 16:07:13',NULL);
/*!40000 ALTER TABLE `orders` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `payments`
--

DROP TABLE IF EXISTS `payments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `payments` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `card_number` varbinary(255) NOT NULL,
  `cardholder_name` varchar(100) NOT NULL,
  `expiry_month` int(11) NOT NULL,
  `expiry_year` int(11) NOT NULL,
  `cvv` varbinary(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `order_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `order_id` (`order_id`),
  CONSTRAINT `payments_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `payments_ibfk_2` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `payments`
--

LOCK TABLES `payments` WRITE;
/*!40000 ALTER TABLE `payments` DISABLE KEYS */;
/*!40000 ALTER TABLE `payments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `products`
--

DROP TABLE IF EXISTS `products`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `products` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `price` decimal(10,2) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `is_visible` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=260 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `products`
--

LOCK TABLES `products` WRITE;
/*!40000 ALTER TABLE `products` DISABLE KEYS */;
INSERT INTO `products` VALUES
(101,'toward he field','Technology ground dark big. Bed entire research thank particular want nothing.',73.23,'images/products/00191-2634414147.png',1),
(102,'none special win','Decade political within little. Feeling fall future carry need. Opportunity rule unit girl exactly in environment. Partner office according pull police dinner heavy.',89.88,'images/products/00112-1891437376.png',1),
(103,'require or two','Do soldier message image see. Soldier although building discuss forget minute hard. Mind woman enough despite.',72.24,'images/products/00277-2087160998.png',1),
(104,'listen reflect Mrs','General upon probably morning. Painting middle positive house talk.',58.54,'images/products/00241-309230552.png',1),
(105,'education TV board','Since cause bar stop traditional. Term site parent play return capital reveal.',9.54,'images/products/00195-3425492520.png',1),
(106,'above significant will','Like own college sort cut strategy time. Back remember still degree majority.',13.37,'images/products/00238-2007530438.png',1),
(107,'onto thousand list','Moment evening and finally simply. Side lead strong similar avoid.',59.87,'images/products/00313-3621154532.png',1),
(108,'game beautiful woman','Style meet no event development often. Teacher blue theory people. Cause decade tonight hope reflect detail.',50.08,'images/products/00237-2007530437.png',1),
(109,'listen subject analysis','Onto energy property.',11.72,'images/products/00196-3425492521.png',1),
(110,'fine affect network','Game growth structure new. Stop one particular old letter agree firm.',94.40,'images/products/00273-19062398.png',1),
(111,'still sport carry','Power blood opportunity trouble mention strategy term measure. Must end religious factor first trial successful.',77.66,'images/products/00130-2762652907.png',1),
(112,'animal sing two','Price job give understand. During growth on whom medical.',45.11,'images/products/00339-1497179028.png',1),
(113,'attention girl general','Purpose nothing event blood rest stage. Cup paper loss article again bring. Action point away collection arrive customer soon.',23.13,'images/products/00314-2700599749.png',1),
(114,'north believe take','Safe economy training car white begin wind. As sort letter outside.',99.82,'images/products/00171-854848260.png',1),
(115,'song seven where','Good popular trip data behavior argue night less. Off hour natural although.',70.48,'images/products/00272-19062397.png',1),
(116,'indeed artist own','Modern off arm. Usually water live easy let capital.',97.20,'images/products/00336-2547854932.png',1),
(117,'girl him action','Same area south get dark Mr. Present it new member garden age.',58.39,'images/products/00177-270898264.png',1),
(118,'painting something nature','Pick step answer food. Will no trade keep home blood. Treatment but wait without.',32.34,'images/products/00164-4185346297.png',1),
(119,'half say company','See significant according risk wonder. Herself piece medical strategy detail write.',27.61,'images/products/00197-3425492522.png',1),
(120,'station size artist','Power lay or. Claim even author area. Us east both direction citizen lead.',23.31,'images/products/00337-2547854933.png',1),
(121,'suddenly figure still','Cost yard art me occur. Owner father song throughout of usually.',14.22,'images/products/00203-3136802431.png',1),
(122,'start participant administration','Side American stock amount matter short. Word police actually material hundred center. Eight word collection green discover require history.',40.58,'images/products/00119-2124098807.png',1),
(123,'father carry Mrs','Read fill dream kind. Trip third any enough later. Cell general important thus bill work each.',98.66,'images/products/00291-2136001793.png',1),
(124,'remember Mrs buy','Perform tree begin age outside. House tax carry recognize.',27.71,'images/products/00290-2136001792.png',1),
(125,'summer be most','Town wonder table. Provide until play mission though.',91.22,'images/products/00025-365506416.png',1),
(126,'over power security','Must process cold energy often form. During method senior at main action.',32.29,'images/products/00118-2124098806.png',1),
(127,'total trial now','Author outside clearly health rest stuff PM. Keep thing require happen care new. No else attack public pick partner fish.',99.80,'images/products/00199-3136802427.png',1),
(128,'themselves treatment notice','Theory us let throughout. Message just six design year. Happy word yes still.',96.45,'images/products/00120-2124098808.png',1),
(129,'describe field part','School involve remember particular magazine necessary still. Reality something purpose.',36.22,'images/products/00353-68627793.png',1),
(130,'paper dark win','Could rock baby. Recently not will make rather. Natural town trouble through support.',19.06,'images/products/00287-2433630668.png',1),
(131,'note art test','Include stuff speak during.',49.11,'images/products/00269-19062394.png',1),
(132,'this others huge','Executive large present sell bring paper else example. Again piece lay major.',51.15,'images/products/00174-270898261.png',1),
(133,'subject total husband','Radio per support modern method human agent. Young Mrs line always.',49.27,'images/products/00335-2547854931.png',1),
(134,'list study respond','Population take along produce. Business simply possible or. Have take analysis arrive.',47.63,'images/products/00172-854848261.png',1),
(135,'me fight newspaper','Pm voice however doctor necessary bank discover. Professional campaign simple civil own offer whose sell. Near meet create environment. Author building meet her face friend.',97.59,'images/products/00178-270898265.png',1),
(136,'market meet cultural','Protect role everybody. Entire relationship all perhaps.',98.59,'images/products/00230-4115365096.png',1),
(137,'response decide form','Ahead rich consider spring everything hair national really. Forget vote card house big a up. Meet maintain office.',71.24,'images/products/00280-1509179004.png',1),
(138,'PM cultural smile','Me west exactly thus owner total.',85.07,'images/products/00243-309230554.png',1),
(139,'heavy people two','Culture fire just either. Task up rich Congress.',82.81,'images/products/00350-68627790.png',1),
(140,'public industry world','Sell must officer statement. Trial catch me.',18.65,'images/products/00192-2634414148.png',1),
(141,'seat Republican knowledge','Machine story represent throw truth game some rest. Late some everything with chance wrong. Tv some president.',30.91,'images/products/00179-1617750089.png',1),
(142,'doctor although year','Deep bar full charge bill government. Crime put media could knowledge early. Speech who candidate miss garden create discuss plan.',4.13,'images/products/00116-2124098804.png',1),
(143,'artist never much','Certainly at style girl reflect group bank fall. Certain Republican traditional information chair second. Quality hotel how do let southern American.',20.60,'images/products/00333-1584005842.png',1),
(144,'direction beautiful serve','Whom could attention two direction. Imagine source thus employee painting level. Modern strong be involve important.',75.89,'images/products/00181-1617750091.png',1),
(145,'share laugh east','Try Mr main commercial happen sell health. Speech high nature almost matter product. Its successful every section minute.',26.00,'images/products/00264-2817242260.png',1),
(146,'according east news','Surface laugh person partner. Then left according between too head approach mission. Onto way only accept relate human.',91.25,'images/products/00158-2762652935.png',1),
(147,'matter hand condition','High factor own few according piece partner. Rise red history catch the. Support free response kid throughout room.',53.45,'images/products/00292-2136001794.png',1),
(148,'American you theory','Bank little her short hear smile present. Detail agree education able million current move.',68.40,'images/products/00318-2700599753.png',1),
(149,'reveal miss itself','Finish resource throw little generation hope.',1.15,'images/products/00311-3621154530.png',1),
(150,'such explain forward','Approach notice do. Draw kitchen century support.',20.43,'images/products/00343-1497179032.png',1),
(151,'hour staff weight','Beat fast water chair reality. Pretty drop process decide girl by. Poor or audience must.',16.82,'images/products/00117-2124098805.png',1),
(152,'attorney main rate','Six statement course never. Daughter state matter media because almost friend. Who kitchen rate friend lay Congress agreement.',17.32,'images/products/00183-1617750093.png',1),
(153,'remember nice already','Decide always authority game bill peace leave. Wish threat must husband region long partner. Once discuss board still end. Four since letter hotel.',95.69,'images/products/00235-2007530435.png',1),
(154,'agreement worker make','Include per keep left hot son number. Then whole sing tell financial area easy. Own mission appear area stock short between. Lead fast by although season whatever.',48.02,'images/products/00268-2817242264.png',1),
(155,'have store opportunity','Degree away reflect until finish art laugh whom. Almost audience before industry position shake natural.',32.42,'images/products/00340-1497179029.png',1),
(156,'yard work public','His community fine number agree never. Deep almost factor stock magazine agent town. Travel let prove understand read.',89.70,'images/products/00262-971114324.png',1),
(157,'answer for let','Home truth beyond perform executive can. Senior fish have box.',54.35,'images/products/00267-2817242263.png',1),
(158,'eat model chance','Show president message memory certain sort. Family program voice financial member. Perform responsibility however water remain.',54.24,'images/products/00352-68627792.png',1),
(159,'identify friend today','But whose win change east. Still agree everyone race thank my shake amount. Name fast final million develop wait management.',26.71,'images/products/00166-4185346299.png',1),
(160,'military themselves consumer','Teacher yeah adult huge mention near career. Attack avoid face tree peace hot itself.',4.90,'images/products/00289-2136001791.png',1),
(161,'modern author training','Girl type upon question security. Modern professional trial weight skin. Including cultural spring charge question long green.',88.11,'images/products/00170-854848259.png',1),
(162,'affect put entire','Total field establish cup training. Worry development always above everything mention.',15.00,'images/products/00147-2762652924.png',1),
(163,'strong exactly civil','Determine close fall show reveal keep into. Time expert focus be piece floor condition. Experience these art cost market.',16.17,'images/products/00180-1617750090.png',1),
(164,'yard hundred newspaper','Board lot spend television tell others. Example remember expect public remain create citizen. Our tax street region.',42.08,'images/products/00149-2762652926.png',1),
(165,'professional spend glass','Century which chair process. Low certain listen turn.',29.06,'images/products/00236-2007530436.png',1),
(166,'cover interesting form','Although generation while. Brother tree between investment give drop.',77.18,'images/products/00142-2762652919.png',1),
(167,'sell various second','Owner public three state.',27.82,'images/products/00146-2762652923.png',1),
(168,'old data factor','Image her present author include administration. Bed herself maybe here. Center wish sport wait American if peace.',95.22,'images/products/00309-3621154528.png',1),
(169,'against main expect','Seem agency mind since order stop treatment.',33.09,'images/products/00242-309230553.png',1),
(170,'plant usually imagine','Detail garden church together which certainly pattern. Painting however camera drug tax girl live program. Face they decide me head drop form wall.',75.21,'images/products/00260-971114322.png',1),
(171,'hold source interest','Recognize continue force pick. Simply fast cause likely chair magazine field bring. Read stop word former.',61.19,'images/products/00173-854848262.png',1),
(172,'join during admit','Series resource light kitchen meeting pretty young state. East describe source she.',94.46,'images/products/00234-2007530434.png',1),
(173,'late energy everyone','Find well system technology arm activity memory. Speak reveal ball their politics.',15.81,'images/products/00349-68627789.png',1),
(174,'fill around away','Lose right forward specific central purpose tough citizen. Morning best red collection ago officer.',65.89,'images/products/00351-68627791.png',1),
(175,'carry project sometimes','Total design green authority.',26.84,'images/products/00293-2136001795.png',1),
(176,'family arm green','Also over sign give truth. Practice truth best when everything fight. Step draw though east write listen.',18.83,'images/products/00240-309230551.png',1),
(177,'reflect area theory','Instead road sister authority never develop position science. Shake show provide. Would many name.',58.82,'images/products/00157-2762652934.png',1),
(178,'eye police common','Save no nearly matter. Morning population training very. Star chance they treat.',30.03,'images/products/00145-2762652922.png',1),
(179,'former simply middle','Whole brother watch protect image make south. Among spend thousand imagine than treat security employee. Drive mean maintain decide quite lose win.',42.83,'images/products/00106-1891437370.png',1),
(180,'country value long','Lawyer find sister true method follow figure. Affect son whether character ask sit perhaps.',34.35,'images/products/00341-1497179030.png',1),
(181,'memory play may','Civil edge quality network apply another. Media know over. May me once.',39.93,'images/products/00286-2433630667.png',1),
(182,'trade interest development','Thought must single down share case large. Matter exist early account church.',17.95,'images/products/00168-4185346301.png',1),
(183,'drive middle police','Gun history do itself drop anyone. Indicate live try military whether property white. All reason imagine determine stuff financial space.',47.77,'images/products/00281-1509179005.png',1),
(184,'produce water nature','Will life general community cup if fine. My what task police view most their. Bit every decade figure respond.',57.44,'images/products/00193-2634414149.png',1),
(185,'federal yes appear','Foreign yard fall million. Huge budget before car whole.',71.63,'images/products/00201-3136802429.png',1),
(186,'door would magazine','Mean my candidate street south. Prove long capital station tell change. Leg somebody wife deep challenge writer.',15.88,'images/products/00231-4115365097.png',1),
(187,'local manage around','Bit similar process nice heart. Theory a happy a alone. Themselves performance office fly.',77.73,'images/products/00279-1509179003.png',1),
(188,'nation site then','Throw name fight girl keep forget debate discuss. Sit available the necessary ask his live. Contain card knowledge weight still. Such study raise carry attention throughout place she.',71.48,'images/products/00236-2007530436.png',1),
(259,'Chainsaw','A powerful chainsaw suitable for various cutting tasks and capable of holding off the forces of evil.',199.99,'images/products/chainsaw.jpg',0);
/*!40000 ALTER TABLE `products` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `salt` varchar(32) NOT NULL,
  `is_admin` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES
(1,'admin','e7d60450e3066b29b1dacc643962b11d','admin@merch.codes','ab8833ad3227138c',1),
(2,'test','570b0df40afbcd523889b051fbb3fe42','test@merch.codes','56145baf1c47164b',0),
(4,'bcampbell','7bd4db7c909eb2a4d9e17cadcec4a106','bcampbell@merch.codes','6309c6ec3f747aa5',0);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-07-30 10:29:25
