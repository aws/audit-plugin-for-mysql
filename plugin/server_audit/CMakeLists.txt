# Copyright (C) 2013 Alexey Botchkov and SkySQL Ab
# Copyright (C) 2021 Amazon.com, Inc. or its affiliates.
# SPDX-License-Identifier: GPL-2.0
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA

SET(SOURCES server_audit.cc file_logger.cc)

MYSQL_ADD_PLUGIN(server_audit ${SOURCES} MODULE_ONLY MODULE_OUTPUT_NAME "server_audit")
