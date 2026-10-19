SELECT 'case1-none';
use db1
CREATE TABLE t1 (id INT);
SELECT 'case1-db1';
use db2
CREATE TABLE t1 (id INT);
SELECT 'case1-db2';
DROP TABLE t1;
use `db-3`
SELECT 'case1-db-3';
