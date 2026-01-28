
-- Copyright 2025 Carnegie Mellon University.
-- Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
-- root or contact permission@sei.cmu.edu for full terms.

-- MySQL dump 10.13  Distrib 8.0.41, for Linux (x86_64)
--
-- Host: localhost    Database: ecommerce
-- ------------------------------------------------------
-- Server version	8.0.41-0ubuntu0.20.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
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
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `order_details` (
  `id` int NOT NULL AUTO_INCREMENT,
  `order_id` int DEFAULT NULL,
  `product_id` int DEFAULT NULL,
  `quantity` int DEFAULT NULL,
  `subtotal` decimal(10,2) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `order_id` (`order_id`),
  KEY `product_id` (`product_id`),
  CONSTRAINT `order_details_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`),
  CONSTRAINT `order_details_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `order_details`
--

LOCK TABLES `order_details` WRITE;
/*!40000 ALTER TABLE `order_details` DISABLE KEYS */;
/*!40000 ALTER TABLE `order_details` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `orders`
--

DROP TABLE IF EXISTS `orders`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `orders` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `product_id` int DEFAULT NULL,
  `quantity` int DEFAULT NULL,
  `total` decimal(10,2) DEFAULT NULL,
  `order_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `payment_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `product_id` (`product_id`),
  KEY `payment_id` (`payment_id`),
  CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `orders_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`),
  CONSTRAINT `orders_ibfk_3` FOREIGN KEY (`payment_id`) REFERENCES `payments` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `orders`
--

LOCK TABLES `orders` WRITE;
/*!40000 ALTER TABLE `orders` DISABLE KEYS */;
/*!40000 ALTER TABLE `orders` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `payments`
--

DROP TABLE IF EXISTS `payments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `payments` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `card_number` varbinary(255) NOT NULL,
  `cardholder_name` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `expiry_month` int NOT NULL,
  `expiry_year` int NOT NULL,
  `cvv` varbinary(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `order_id` int DEFAULT NULL,
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
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `products` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `description` text COLLATE utf8mb4_general_ci,
  `price` decimal(10,2) NOT NULL,
  `image` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `is_visible` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `products`
--

LOCK TABLES `products` WRITE;
/*!40000 ALTER TABLE `products` DISABLE KEYS */;
INSERT INTO `products` VALUES (1,'Jump Boots','Springy shoes that make you leap higher!',12.99,'images/1.png',1),(2,'Star Candy','Shiny candy that tastes like victory!',3.49,'images/2.png',1),(3,'Glide Cape','So light, it flutters with every breeze.',19.99,'images/3.png',1),(4,'Lucky Bell','Ring it and good luck follows!',7.99,'images/4.png',1),(5,'Bouncy Juice','Drink and feel the bounce!',4.99,'images/5.png',1),(6,'Cloud Pillow','Nap like you\'re floating in the sky.',15.00,'images/6.png',1),(7,'Magic Feather','A feather full of wonder.',9.99,'images/7.png',1),(8,'Puzzle Piece','Feels like part of something bigger...',2.00,'images/8.png',1),(9,'Fire Pop','A spicy-sweet treat!',2.99,'images/9.png',1),(10,'Rainbow Shell','Makes colorful sounds when shaken!',14.50,'images/10.png',1),(11,'Pocket Cloud','Keep a tiny cloud with you.',6.75,'images/11.png',1),(12,'Yummi Fruit','Smells delicious! (Don\'t actually eat it.)',3.00,'images/12.png',1),(13,'Wind Whistle','Calls friendly breezes.',5.25,'images/13.png',1),(14,'Goofy Goggles','See the world upside-down!',11.00,'images/14.png',1),(15,'Dream Lantern','Light that makes you feel cozy inside.',18.00,'images/15.png',1);
/*!40000 ALTER TABLE `products` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) COLLATE utf8mb4_general_ci NOT NULL,
  `password` varchar(255) COLLATE utf8mb4_general_ci NOT NULL,
  `email` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `salt` varchar(32) COLLATE utf8mb4_general_ci NOT NULL,
  `is_admin` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=22 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin','e7d60450e3066b29b1dacc643962b11d','admin@merch.codes','ab8833ad3227138c',1),(2,'test','570b0df40afbcd523889b051fbb3fe42','test@merch.codes','56145baf1c47164b',0),(3,'test2','032f5fadf3b81e6516365cff8263a784','test2@test.test','dd31d0890aa96158',0),(4,'bcampbell','7bd4db7c909eb2a4d9e17cadcec4a106','bcampbell@skills.hub','6309c6ec3f747aa5',0),(6,'cthreatscape','d48d89d52b843c6ec0e7d14378cd863b','cthreatscape@mushmarket.com','73bb6bc90e84b943',0),(7,'snullbyte','6ced1719cae7eff7e6c114640165c587','snullbyte@mushmarket.com','642eafb5ee7096d3',0),(8,'bsudo','0a1f3982c82615d85b0e8e919e72a1bf','bsudo@mushmarket.com','3b065598c679e69c',0),(9,'wforcenet','f8134271895773b372524e52b40908ea','wforcenet@mushmarket.com','b942ee1f6dc647a7',0),(10,'fnoptrick','0a1f3982c82615d85b0e8e919e72a1bf','fnoptrick@mushmarket.com','3b065598c679e69c',0),(11,'dheapou','2e6d9e82519627140f8352ca3a74fc05','dheapou@mushmarket.com','72ff3e8d74d406ca',0),(12,'gshellshock','62e1e98734dfe8a83588d9dc7d692d26','gshellshock@mushmarket.com','6979c2a0a3110d04',0),(13,'mvoidcast','0a1f3982c82615d85b0e8e919e72a1bf','mvoidcast@mushmarket.com','3b065598c679e69c',0),(14,'eaguirre','ec60bd2e24c77fbc56d0a909a0c3052b','richardberg@example.net','c4d67ee636614152',0),(15,'chadchen','ea50d112699dd8a3a8a9539b04c6f9b0','scottryan@example.com','a48c561583c8eafb',0),(16,'ehoffman','14f1c900f3631ad619c3ff6bb2cd63a4','gmyers@example.com','b6c7951ca4c4d766',0),(17,'amanda98','d728d5572704bc47a1aeea3b22b2c58e','weissemily@example.com','98bbce6ba8d2643a',0),(18,'christopherrichards','c03f9d1b7e6468d9c34b7b79b397cf35','alvaradomatthew@example.com','498c76a731264b89',0),(19,'urose','8e59346db97920edfb356b6b8f8c15e1','ebrewer@example.net','80eebea22546289e',0),(20,'tammy80','48322207da3cef6610084ed2d22f1ab9','michael30@example.net','53e0c67b18956846',0),(21,'regtest','35dfd40957f89f3dac9e48da7e38a44f','regtest@test.test','4cd44edac5419f98',0);
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

-- Dump completed on 2025-05-20  8:41:27
