CREATE TABLE `chat_history` (
	`id` int AUTO_INCREMENT NOT NULL,
	`organizationId` int NOT NULL,
	`userId` int NOT NULL,
	`sessionId` varchar(64),
	`userMessage` text,
	`aiResponse` text,
	`context` json,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `chat_history_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `incident_recommendations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`threatDetectionId` int NOT NULL,
	`organizationId` int NOT NULL,
	`shortTermActions` json,
	`longTermActions` json,
	`estimatedEffort` json,
	`priority` enum('critical','high','medium','low') DEFAULT 'high',
	`aiGeneratedText` text,
	`recStatus` enum('pending','in_progress','completed') DEFAULT 'pending',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `incident_recommendations_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `incident_reports` (
	`id` int AUTO_INCREMENT NOT NULL,
	`organizationId` int NOT NULL,
	`threatDetectionId` int,
	`reportType` enum('executive','technical','combined') DEFAULT 'combined',
	`title` varchar(255),
	`executiveSummary` text,
	`technicalAnalysis` text,
	`recommendations` text,
	`pdfUrl` varchar(500),
	`generatedBy` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `incident_reports_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `organizations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`name` varchar(255) NOT NULL,
	`ownerId` int NOT NULL,
	`industry` varchar(100),
	`maxLogsPerMonth` int DEFAULT 100000,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `organizations_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `security_logs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`organizationId` int NOT NULL,
	`sourceType` varchar(50),
	`rawLog` longtext,
	`normalizedLog` json,
	`timestamp` timestamp,
	`sourceIp` varchar(45),
	`destinationIp` varchar(45),
	`userId` varchar(255),
	`eventType` varchar(100),
	`severity` enum('low','medium','high','critical') DEFAULT 'low',
	`logHash` varchar(64),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `security_logs_id` PRIMARY KEY(`id`),
	CONSTRAINT `security_logs_logHash_unique` UNIQUE(`logHash`)
);
--> statement-breakpoint
CREATE TABLE `threat_detections` (
	`id` int AUTO_INCREMENT NOT NULL,
	`organizationId` int NOT NULL,
	`logId` int,
	`threatType` enum('phishing','brute_force','malware','lateral_movement','data_exfiltration','privilege_escalation','unknown') DEFAULT 'unknown',
	`riskScore` decimal(5,2),
	`confidence` decimal(5,2),
	`mitreAttackIds` json,
	`description` text,
	`indicators` json,
	`affectedAssets` json,
	`aiAnalysis` text,
	`status` enum('new','investigating','confirmed','false_positive','resolved') DEFAULT 'new',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `threat_detections_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `users` ADD `organizationId` int;