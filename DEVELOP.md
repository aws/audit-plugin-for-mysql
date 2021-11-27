# Development

Before making any code changes, read the following documentation:

* [Introduction to Plugin Descriptors](https://dev.mysql.com/doc/extending-mysql/8.0/en/server-plugin-descriptors.html)
* [Plugin status and system variables’ structure](https://dev.mysql.com/doc/extending-mysql/8.0/en/plugin-status-system-variables.html)
* [MySQL engine error reference](https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html)
* MySQL documentation [about writing audit plugin](https://dev.mysql.com/doc/extending-mysql/8.0/en/writing-audit-plugins.html)
* Audit plugin [API header file](https://github.com/mysql/mysql-server/blob/mysql-8.0.25/include/mysql/plugin_audit.h)

## Notes on MariaDB and MySQL differences

The MariaDB Audit Plugin is not compatible with MySQL 8.0 mainly because:

* In MySQL 5.7, major changes in [plugin_audit.h](https://github.com/mysql/mysql-server/blob/mysql-8.0.25/include/mysql/plugin_audit.h) made the MySQL audit plugin API diverge from MariaDB. In MySQL 8.0, additional changes caused the plugin to diverge from both MySQL 5.7 and MariaDB.
* In MySQL 8.0, the [*mysql_global.h* was removed](https://mysqlserverteam.com/mysql-8-0-source-code-improvements/). See [bug report](https://bugs.mysql.com/bug.php?id=83097) for details.

**Note:** There is a known issue related to the system variable
```server_audit_loc_info```. Because this system variable is for plugin
developer only, it should be invisible to the customer. We set
```PLUGIN_VAR_NOSYSVAR | PLUGIN_VAR_NOCMDOPT | PLUGIN_VAR_MEMALLOC``` for it but
it is still visible to the MySQL customers.

## Debugging

The [MySQL example audit
plugin](https://github.com/mysql/mysql-server/tree/mysql-8.0.25/plugin/audit_null)
is useful for exploring  the details of the audit events. Modify or add an extra
print in the audit null code to get the event information.

## Tests

See the `server_audit.test` file to view tests. The expectation for all future
code changes that add a feature or fix a bug is that they also extend or update
the tests accordingly.

***Note*** MySQL does not support a thread pool, so there is only one test for
MySQL 8.0 to test audit plugin functionality with a single thread.

## Running test suite with mysql-test-run

### Register test

To register the audit plugin MTR test, add the following line to `/mysql-test/include/plugin.defs`:

    server_audit    plugin_output_directory   no SERVER_AUDIT   server_audit

### Load plugin

To test the plugin, either install the plugin when executing the MTR test
or [pre-load the
plugin](https://dev.mysql.com/doc/refman/8.0/en/plugin-loading.html#server-plugin-installing-command-line)
before the MTR starts.

Server audit plugin test requires `test_plugin_server` to test the proxy
use case. The test plugin `test_plugin_server` must be installed during the server start
up, otherwise the proxy test case will fail.

The [test case
options](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_TESTCASE_SPECIFIC_SERVER_OPTIONS.html)
file `server_audit-master.opt` exists to facilitate this.

## Updating tests

When there is a difference between the expected result and actual result, move
the expected result to a backup and [regenerate the
result](https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_GENERATE_TESTCASE_RESULT_FILE.html).

Generate test result file by running:

    ./mysql-test-run --do-test=server_audit --record server_audit --verbose

After you have both results, you can diff these two files. Note that failures are
often caused by extra spaces.
