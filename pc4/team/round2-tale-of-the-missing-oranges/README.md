# Tale of the Missing Oranges!

Perform database forensics to find the missing inventory. 

**NICE Work Roles** 
- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-forensics-analyst) 

**NICE Tasks**
- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0532) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

## Background

Some orange items are missing from the warehouse. There is no record of  sale for those items in the database. Your task is to analyze the SQLite database to determine who checked out those items from the warehouse. 

The `Sales` table shows who checked out which items. The `Inventory` table shows the remaining balance of items on a particular day.

## Getting Started

You do have access to the SQLite database **warehouse.db** file. It's attached as an ISO to the `orange-analyst` VM. The first few bytes of the database file were mistakenly overwritten with zeroes. Also, the database page size is 4096 bytes.

## Challenge Questions

1. What is the root page for "users" table?
2. What is the product ID associated with "Orange Concentrate"?
3. Some of the "Orange Concentrate" items are missing from the warehouse. We see that there is an entry in the inventory table showing some items were checked out, but no equivalent entry in the Sales table. Analyze the deleted record from Sales table and provide the userid that checked out the missing items.
