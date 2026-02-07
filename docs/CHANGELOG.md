# Changelog

## v2.0.6
- [x] **Private Network Scanning** - Local/private IP targets now allowed by default (configurable via `allow_private_networks` in `config.yaml`)
- [x] **Configurable Network Policy** - New `allow_private_networks` security setting for controlling local network access
- [x] **Improved Test Coverage** - Added dedicated tests for private network validation behavior

## v2.0.5
- [x] **Parameter Selection** - Target specific parameters with `-p id,username`
- [x] **Enhanced Reports** - Detailed HTML reports with tables, columns, and payloads
- [x] **Global SQLMap** - Uses your system's SQLMap installation
- [x] **Bug Fixes** - Improved database tracking and report generation
