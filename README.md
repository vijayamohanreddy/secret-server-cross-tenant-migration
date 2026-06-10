# Delinea Secret Server Cross-Tenant Migration Tool (Unofficial)

# **Unofficial Tool:** This project is not affiliated with, endorsed by, or supported by any vendor or product owner.

## Overview

The Delinea Secret Server Cross-Tenant Migration Tool Unofficial is a Windows PowerShell 5.1 GUI application designed to migrate secrets and related metadata between Delinea Secret Server environments. It supports cloud-to-cloud, on-premises-to-on-premises, and hybrid migration scenarios where source and target tenants must be managed independently.

The tool is built for administrators who need a controlled, repeatable way to export, validate, import, reconcile, and clean up migrated data while preserving as much operational context as possible.

## Primary Use Cases

- Tenant-to-tenant secret migration during mergers, divestitures, or environment consolidation
- Environment refresh from production to staging or from legacy to modernized Secret Server instances
- Controlled folder-based or search-based secret extraction for phased migration waves
- Template and permission alignment between source and target tenants
- Dry-run validation before production cutover

# Simple Usage

1. **Export Secrets** — Export all Secrets, Folders, and related metadata from the source tenant into a JSON file using the Export tab.

2. **Update Permissions** — If user or group names differ between source and target tenants, use the Update Permissions tool to apply your CSV‑based mapping. This updates the exported JSON with correct target‑tenant principals.

3. **Validate Templates** — If you do not want to import or create new templates in the target tenant, use the Template Check tab to compare source vs. target templates. The tool generates an “updatable CSV” showing mismatches. Apply this CSV to update the exported JSON so all secrets align with target‑tenant templates.

4. **Prepare for Import** — After permissions and templates are aligned, your JSON is fully ready for import. Use the Import tab to load the refined JSON into the target tenant.
   
## Key Capabilities

### Export

- Export secrets to JSON, XML, CSV, or ZIP bundle
- Export an entire tenant, a specific folder, or a filtered secret set using search text
- Include child folders through recursive folder traversal
- Capture password history where available
- Export file attachments with endpoint fallback handling
- Export secret settings such as checkout, comments, approvals, expiration, OTP, and password requirements
- Export folder ACLs and secret ACLs
- Embed template export XML for later template migration

### Import

- Import from JSON, XML, CSV, or ZIP with automatic format detection
- Create folder hierarchy on the target or flatten into a single target folder
- Map templates using name match, suffix match, fuzzy match, or manual mapping workflows
- Translate field IDs when source and target template schemas differ
- Remap users and groups by username or display name patterns
- Handle duplicate secrets using Skip, Update existing, or Create New behavior
- Restore password history, attachments, secret settings, folder ACLs, and secret ACLs

### Safety and Control

- Dry-run mode to simulate migration without writing changes
- Rollback tracking for created folders and created secrets
- Cleanup Last Import capability with optional rollback of updated secrets
- Pre-import permission checks against the effective target folder
- Detailed logging to file and GUI

### Operations and Performance

- Token caching with automatic refresh support
- Parallel HTTP requests for template retrieval and duplicate detection
- Cached folder, principal, template, and permission lookups
- Large JSON read/write helpers optimized for sizeable exports
- GUI-based workflow for administrators who do not want a command-line-only process

## Intended Audience

This tool is intended for:

- Delinea Secret Server administrators
- IAM and PAM engineering teams
- Migration project teams handling cross-tenant moves
- Operations teams performing controlled wave-based cutovers

## Platform and Runtime Requirements

- Windows operating system
- PowerShell 5.1 or later
- .NET Framework 4.5 or later
- Network connectivity to both Delinea Secret Server environments
- A source account with permission to read secrets, folders, templates, and relevant metadata
- A target account with permission to create folders, create or update secrets, and apply permissions where required

## Authentication and Security

The tool uses OAuth2 password grant authentication against Delinea Secret Server token endpoints. It supports separate source and target credentials and can store passwords using DPAPI encryption in the configuration file. Password entry in the GUI uses masked fields.

Security-related behaviors include:

- DPAPI-encrypted credential storage when enabled
- Token caching with expiration handling
- Administrator auto-elevation support for script and compiled executable execution
- Optional verbose HTTP logging for troubleshooting

Because the tool can export secret material, it should be run only in approved administrative environments and according to organizational security policy.

## Packaging and Execution Model

The tool can run as either:

- A PowerShell script
- A compiled executable produced with ps2exe

When launched, the application determines its own base directory and uses that location to store its default configuration, export files, log files, and rollback artifacts.

Default local artifacts:

- Configuration: `delinea-migrate.config.json`
- JSON export: `secrets-export.json`
- CSV export: `secrets-export.csv`
- Log file: `delinea-migrate.log` with optional timestamp suffix
- Rollback folder: `rollback`

## User Interface Summary

The GUI is organized into operational tabs:

- Settings: source and target tenant endpoints, credentials, token path, config path, theme, and output locations
- Actions: verify connectivity, export, import, cleanup last import, and secret count operations
- Tools: permission remapping and template mapping helpers
- Template Check: source-vs-target template comparison, CSV export, and mapping support
- Reconciliation workflow: delta-based follow-up import support using comparison outputs

## Configuration Model

The application uses a JSON configuration file and will create one automatically if it does not exist.

### Global Settings

- `TokenPath`: default `/oauth2/token`
- `ExportFile`: default JSON export path
- `ExportCsvFile`: default CSV export path
- `LogFile`: default log path
- `LogFileDateStamp`: controls timestamped log file naming
- `TemplateCsvPath`: optional template comparison or mapping CSV path
- `RemapCsvPath`: optional principal remapping CSV path
- `Theme`: default `Ocean`

### Source Settings

- `TenantBase`
- `SSApiBase`
- `Username`
- `PasswordDpapi`
- `TokenUrl`
- `SearchText`
- `FolderId`
- `MaxSecrets`
- `IncludeHistory`
- `ExportTemplates`
- `UseV1ExportService`
- `ExportChildFolders`
- `ExportJson`
- `ExportXml`
- `ExportCsv`
- `ExportZip`
- `EncryptPasswords`

### Target Settings

- `TenantBase`
- `SSApiBase`
- `Username`
- `PasswordDpapi`
- `TokenUrl`
- `TargetFolderId`
- `TargetRootFolderId`
- `FolderTreeMigration`
- `OverwriteIfExists`
- `SecretTypeMapByName`
- `ImportTemplates`
- `TemplateSuffix`
- `DuplicateSecretAction`
- `CopyFolderAcls`
- `CopySecretAcls`
- `CopySecretSettings`
- `CopyAttachments`
- `RemapPrincipals`
- `DryRun`
- `SkipPasswordValidation`
- `SyncTemplateFields`
- `StopOnError`
- `ApplyPasswordHistory`
- `CleanupRollbackUpdatedSecrets`
- `RollbackDir`
- `VerboseHttp`

## Recommended Migration Workflow

### 1. Prepare Access

- Confirm both source and target API bases are reachable
- Confirm the target account has create or edit rights in the intended target folder
- Confirm any required users or groups exist in the target environment if ACL remapping will be used

### 2. Configure the Tool

- Launch the tool as an administrator
- Populate source and target tenant information
- Save the configuration file for repeatable execution
- Use the Verify action before running any migration wave

### 3. Run an Export

- Choose full export, folder-based export, or search-based export
- Decide whether to include child folders, templates, attachments, settings, and password history
- Select the desired output format or bundle type
- Review the generated log and export artifacts

### 4. Validate Templates and Mapping

- Use Template Check to compare source and target secret templates
- Export comparison results to CSV if manual review is needed
- Prepare or import template mapping CSV data when direct matches are not available

### 5. Perform a Dry Run Import

- Enable dry-run mode first for production migrations
- Validate folder creation, duplicate detection, principal mapping, and template compatibility
- Review warnings and resolve permission or template issues before live import

### 6. Execute the Import

- Run the import using the approved settings
- Monitor duplicate handling, folder tree creation, ACL application, and attachment upload behavior
- Review the final log for skipped items, warnings, and failed operations

### 7. Reconcile and Clean Up

- Use the reconciliation flow for delta-based follow-up runs
- Use Cleanup Last Import if a rollback of created objects is required
- Retain logs, export files, rollback data, and mapping files as migration evidence

## Duplicate Handling Strategy

The import engine uses a layered duplicate detection model designed for reliability in large environments:

- Full folder-based secret indexing where possible
- Targeted name-based search as a fallback
- Case-insensitive and whitespace-tolerant matching
- Real-time cache updates as new secrets are created during import

This approach reduces the risk of duplicate creation when API visibility is inconsistent across endpoints.

## Template Migration Strategy

Template handling is one of the differentiators of this tool. It supports:

- Direct name matching
- Suffix-based match behavior for imported templates
- Detailed source-vs-target comparison at field and settings level
- CSV export for review and manual mapping
- Import of missing templates from export data
- Optional synchronization of template fields before import

This is useful when source and target tenants have drifted over time or use different naming conventions.

## Permission and Principal Handling

The tool can migrate both folder ACLs and secret ACLs with attention to operational safety:

- It never intentionally places secrets into the wrong folder as a fallback behavior
- It validates access to the effective target folder before import
- It can remap users and groups using cached target-side lookups
- It logs principals that cannot be mapped so they can be addressed separately

Permission migration should still be tested in a non-production target first because entitlement models can differ materially across tenants.

## Output and Reporting Artifacts

Depending on selected options, the tool can generate:

- JSON export files
- XML export files compatible with web-portal import scenarios
- CSV export bundles
- ZIP packages
- Template comparison CSV files
- Template mapping CSV files
- Rollback tracking data
- Timestamped log files

These artifacts support auditability, troubleshooting, staged cutovers, and reruns.

## Operational Notes

- The tool is optimized for GUI-driven administrative use rather than unattended headless execution
- Large exports are supported through custom JSON serialization helpers to reduce PowerShell JSON overhead
- Some permission or settings endpoints may legitimately return non-fatal errors depending on tenant configuration and available API features
- Password history and attachments depend on source-side API availability and access permissions
- Verbose HTTP logging should be enabled only when troubleshooting because it increases log volume

## Limitations and Assumptions

- The tool depends on API access and feature availability in both Delinea environments
- Successful secret migration does not guarantee one-to-one permission equivalence if principals do not exist in the target
- Template parity is not assumed; mapping or import may still be required
- Cleanup and rollback are strongest for objects created by the tool, not for every possible in-place update scenario
- Production use should follow a staged migration plan with dry-run validation and post-import reconciliation

## Publishing Summary

The Delinea Secret Server Cross-Tenant Migration Tool Unofficial provides a practical administrative framework for exporting and importing secrets, templates, folder structures, settings, attachments, and permissions between Delinea environments. Its value is in combining migration depth, safety controls, template intelligence, reconciliation support, and a Windows GUI into a single operator-facing utility suitable for real migration projects.

For publishing purposes, this tool can be positioned as a migration accelerator for Delinea Secret Server administrators who need more than a simple data export and require validation, repeatability, logging, rollback support, and structured target-side import behavior.
